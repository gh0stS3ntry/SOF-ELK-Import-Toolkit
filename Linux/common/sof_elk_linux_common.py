"""Shared engine for the Linux importers (journal, text syslog, ...).

What lives here, so every Linux importer behaves the same way:

  * Evidence: one interface over a UAC zip, an extracted UAC folder, or any collected root
    filesystem (CyLR/Velociraptor/Dissect output, a mounted image). It finds the collection
    base (where UAC writes uac.log, journal/, live_response/) and the evidence root
    (UAC's "[root]/", or the folder that holds etc/ and var/log/), and opens files inside a
    zip without extracting it. .gz, .bz2 and .xz are decompressed transparently.
  * HostProfile: hostname, distro (host.os.*), machine-id (host.id) and time zone, read from
    the evidence itself (uac.log, /etc/hostname, /etc/os-release, /etc/machine-id,
    /etc/timezone, /etc/localtime).
  * Index handling: loads Linux/index_templates/, installs the common component template and
    creates <prefix>-<hostname> from the merged body. For SOF-ELK index families (logstash-*)
    no index template is installed, so SOF-ELK's own logstash-YYYY.MM indexes are untouched.
    An existing index that this toolkit did not create is refused.
  * Sending: the retrying _bulk client in Windows/common/sof_elk_es_client.py, deterministic
    _id values (re-runs overwrite instead of duplicating), and a per-source summary.

Standard library only (Python 3.9+).
"""
from __future__ import annotations

import argparse
import bz2
import copy
import datetime as dt
import gzip
import hashlib
import io
import ipaddress
import json
import lzma
import os
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath
from urllib import error

try:
    import zoneinfo
except ImportError:  # Python 3.8
    zoneinfo = None

LINUX_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = LINUX_DIR / "index_templates"
COMMON_COMPONENT = "sofelk-toolkit-linux-common"
# Template sets: (folder, common component file, component name). "windows" is used by
# indexes the Windows importers already define (browsinghistory-*), so a Linux host and a
# Windows host land in the same schema.
TEMPLATE_SETS = {
    "linux": (TEMPLATE_DIR, "component-toolkit-linux-common.json", COMMON_COMPONENT),
    "windows": (LINUX_DIR.parent / "Windows" / "index_templates", "component-toolkit-common.json",
                "sofelk-toolkit-common"),
}

# The retrying bulk client is shared with the Windows and AWS importers.
sys.path.insert(0, str(LINUX_DIR.parent / "Windows" / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, resolve_index  # noqa: E402

UAC_ROOT_DIR = "[root]"


# --------------------------------------------------------------------------- small helpers

def set_field(doc, dotted, value):
    """doc["a"]["b"] = value for "a.b". None, "" and [] are not written."""
    if value is None or value == "" or value == []:
        return
    parts = dotted.split(".")
    for p in parts[:-1]:
        doc = doc.setdefault(p, {})
    doc[parts[-1]] = value


def get_field(doc, dotted):
    for p in dotted.split("."):
        if not isinstance(doc, dict) or p not in doc:
            return None
        doc = doc[p]
    return doc


def sanitize_hostname(hostname):
    """Same normalisation as the Windows importers: "RD 01" -> "rd-01"."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("hostname must contain at least one letter or digit")
    return value


def iso_utc(stamp):
    """Aware datetime -> ISO 8601 UTC with microseconds."""
    stamp = stamp.astimezone(dt.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond:06d}Z"


def epoch_us_to_iso(value):
    """Epoch microseconds (int or digit string) -> ISO 8601 UTC, or None."""
    try:
        us = int(value)
    except (TypeError, ValueError):
        return None
    try:
        stamp = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=us)
    except OverflowError:
        return None
    return iso_utc(stamp)


def doc_id(*parts):
    return hashlib.sha1(json.dumps(parts, ensure_ascii=False).encode("utf-8")).hexdigest()


ROTATED_RE = re.compile(r"^(?P<family>.+?)(?:\.(?P<num>\d+)|-(?P<date>\d{8}))?(?:\.(?:gz|bz2|xz))?$")


def rotation_family(name):
    """'access.log.2.gz' -> 'access.log', 'access_log-20261025' -> 'access_log'."""
    m = ROTATED_RE.match(name)
    return m.group("family") if m else name


def rotation_sort_key(rel):
    """Oldest first within a folder: per family, numbered copies (.3, .2, .1), dated copies, current."""
    name = PurePosixPath(rel).name
    folder = str(PurePosixPath(rel).parent)
    m = ROTATED_RE.match(name)
    if not m:
        return (folder, name, 0, 0, "")
    if m.group("num"):
        return (folder, m.group("family"), 0, -int(m.group("num")), "")
    if m.group("date"):
        return (folder, m.group("family"), 1, 0, m.group("date"))
    return (folder, m.group("family"), 2, 0, "")


def split_host_port(text):
    """'1.2.3.4:5678', '[::1]:80', '::1' -> (ip-or-host, port or None)."""
    text = text.strip()
    m = re.fullmatch(r"\[([^\]]+)\](?::(\d+))?", text)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else None
    if text.count(":") == 1:
        host, _, port = text.partition(":")
        if port.isdigit():
            return host, int(port)
    if text.count(":") > 1 and not is_ip(text):
        host, _, port = text.rpartition(":")
        if port.isdigit() and is_ip(host):
            return host, int(port)
    return text, None


def is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- evidence access

COMPRESSORS = {".gz": gzip.GzipFile, ".bz2": bz2.BZ2File, ".xz": lzma.LZMAFile}
MAGIC = ((b"\x1f\x8b", ".gz"), (b"BZh", ".bz2"), (b"\xfd7zXZ\x00", ".xz"))


def open_compressed(path):
    """Binary stream of a file on disk, decompressed when it is gzip, bzip2 or xz (by magic bytes)."""
    with open(path, "rb") as fh:
        head = fh.read(6)
    for magic, ext in MAGIC:
        if head.startswith(magic):
            return {".gz": gzip.open, ".bz2": bz2.open, ".xz": lzma.open}[ext](path, "rb")
    return open(path, "rb")


class Evidence:
    """A UAC zip, a UAC folder, or a collected root filesystem.

    Paths handed out and accepted are POSIX-style and relative to the evidence container
    (the zip, or the folder given on the command line). `base` is the collection folder
    (where uac.log sits for UAC, else ""), `root` the evidence root ("[root]/" for UAC).
    """

    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        if not self.path.exists():
            raise SystemExit(f"ERROR: evidence path not found: {self.path}")
        self.is_zip = self.path.is_file()
        self.zip = None
        self.names = None
        self.dirs = None
        if self.is_zip:
            if not zipfile.is_zipfile(self.path):
                raise SystemExit(f"ERROR: {self.path} is neither a folder nor a zip file")
            self.zip = zipfile.ZipFile(self.path)
            self.infos = {}
            for info in self.zip.infolist():
                name = info.filename.replace("\\", "/")
                if info.is_dir():
                    continue
                self.infos[name] = info
            self.names = sorted(self.infos)
            self.dirs = set()
            for name in self.names:
                parent = PurePosixPath(name).parent
                while str(parent) not in (".", ""):
                    self.dirs.add(str(parent))
                    parent = parent.parent
        self.base, self.root = self._locate()
        self.is_uac = self.exists(self._join(self.base, "uac.log"))

    # -- path helpers
    @staticmethod
    def _join(*parts):
        return "/".join(p.strip("/") for p in parts if p and p.strip("/"))

    def label(self):
        return self.path.name

    def exists(self, rel):
        if self.is_zip:
            return rel in self.infos
        return (self.path / rel).is_file()

    def is_dir(self, rel):
        rel = rel.strip("/")
        if self.is_zip:
            return rel == "" or rel in self.dirs
        return (self.path / rel).is_dir()

    def listdir(self, rel):
        """(files, dirs) directly inside rel."""
        rel = rel.strip("/")
        files, dirs = [], []
        if self.is_zip:
            prefix = rel + "/" if rel else ""
            seen = set()
            for name in self.names:
                if not name.startswith(prefix):
                    continue
                rest = name[len(prefix):]
                head, sep, _ = rest.partition("/")
                if sep:
                    if head not in seen:
                        seen.add(head)
                        dirs.append(head)
                else:
                    files.append(head)
            return sorted(files), sorted(dirs)
        folder = self.path / rel
        try:
            for entry in os.scandir(folder):
                if entry.is_dir(follow_symlinks=False):
                    dirs.append(entry.name)
                elif entry.is_file():
                    files.append(entry.name)
        except OSError:
            pass
        return sorted(files), sorted(dirs)

    def mtime(self, rel):
        """Modification time of a file as a naive datetime (zip entries carry no zone)."""
        if self.is_zip:
            info = self.infos.get(rel)
            return dt.datetime(*info.date_time) if info else None
        try:
            return dt.datetime.fromtimestamp((self.path / rel).stat().st_mtime)
        except OSError:
            return None

    def size(self, rel):
        if self.is_zip:
            info = self.infos.get(rel)
            return info.file_size if info else 0
        try:
            return (self.path / rel).stat().st_size
        except OSError:
            return 0

    def open_binary(self, rel, decompress=True):
        """Binary stream of a member; .gz/.bz2/.xz content (by magic bytes) is decompressed."""
        if not self.is_zip:
            return open_compressed(self.path / rel) if decompress else open(self.path / rel, "rb")
        raw = self.zip.open(self.infos[rel])
        if not decompress:
            return raw
        head = raw.read(6)
        raw.close()
        raw = self.zip.open(self.infos[rel])
        for magic, ext in MAGIC:
            if head.startswith(magic):
                return gzip.GzipFile(fileobj=raw) if ext == ".gz" else COMPRESSORS[ext](raw)
        return raw

    def open_text(self, rel):
        return io.TextIOWrapper(self.open_binary(rel), encoding="utf-8", errors="replace", newline="")

    def read_text(self, rel, limit=1 << 20):
        if not self.exists(rel):
            return None
        try:
            with self.open_binary(rel, decompress=False) as fh:
                return fh.read(limit).decode("utf-8", "replace")
        except OSError:
            return None

    def read_bytes(self, rel, limit=1 << 20):
        if not self.exists(rel):
            return None
        try:
            with self.open_binary(rel, decompress=False) as fh:
                return fh.read(limit)
        except OSError:
            return None

    def walk(self, rel, max_depth=8):
        """Every file path under rel (recursively, up to max_depth folders down), sorted."""
        rel = rel.strip("/")
        if self.is_zip:
            prefix = rel + "/" if rel else ""
            return [n for n in self.names if n.startswith(prefix)
                    and n[len(prefix):].count("/") <= max_depth]
        out = []
        top = self.path / rel
        if not top.is_dir():
            return out
        base_depth = len(top.parts)
        for dirpath, dirnames, filenames in os.walk(top):
            depth = len(Path(dirpath).parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for name in filenames:
                out.append((Path(dirpath) / name).relative_to(self.path).as_posix())
        return sorted(out)

    def copy_out(self, rel, dest):
        """Copy a member, as stored (no decompression), to the local file dest."""
        with self.open_binary(rel, decompress=False) as src, open(dest, "wb") as dst:
            while True:
                chunk = src.read(1 << 20)
                if not chunk:
                    break
                dst.write(chunk)

    def evidence_path(self, rel):
        """Container path -> the path it had on the evidence host ("/home/kali/x")."""
        root = self.root.strip("/")
        if root and rel.startswith(root + "/"):
            rel = rel[len(root) + 1:]
        elif root:
            return rel
        return "/" + rel

    def readlink(self, rel):
        """Target of a symlink in a folder input (zip inputs store the file content instead)."""
        if self.is_zip:
            info = self.infos.get(rel)
            if info is not None and (info.external_attr >> 16) & 0o170000 == 0o120000:
                return self.zip.read(info).decode("utf-8", "replace")
            return None
        p = self.path / rel
        try:
            return os.readlink(p) if p.is_symlink() else None
        except OSError:
            return None

    def root_path(self, rel):
        """Evidence-root path (etc/os-release) -> container path."""
        return self._join(self.root, rel)

    def base_path(self, rel):
        return self._join(self.base, rel)

    def os_path(self, rel):
        """Real filesystem path of a folder member (None inside a zip)."""
        return None if self.is_zip else str(self.path / rel)

    # -- layout detection
    def _locate(self):
        """(collection base, evidence root) inside the container."""
        # UAC: uac.log at the top or one/two folders down, evidence files under [root]/.
        candidates = [""]
        if self.is_zip:
            for name in self.names:
                if name.endswith("uac.log") and name.count("/") <= 2:
                    candidates.insert(0, name[:-len("uac.log")].rstrip("/"))
                    break
        else:
            for depth_dir in [self.path] + [p for p in self.path.iterdir() if p.is_dir()][:50]:
                if (depth_dir / "uac.log").is_file():
                    candidates.insert(0, depth_dir.relative_to(self.path).as_posix().strip("."))
                    break
        for base in candidates:
            uac_root = self._join(base, UAC_ROOT_DIR)
            if self.is_dir(uac_root):
                return base, uac_root
        # Any other collector or a mounted image: the folder holding etc/ or var/log/.
        queue = [("", 0)]
        while queue:
            rel, depth = queue.pop(0)
            if self.is_dir(self._join(rel, "var/log")) or self.exists(self._join(rel, "etc/os-release")):
                return rel, rel
            if depth < 3:
                _, dirs = self.listdir(rel)
                queue.extend((self._join(rel, d), depth + 1) for d in dirs[:200])
        return candidates[0], candidates[0]


# --------------------------------------------------------------------------- host profile

OS_FAMILIES = {
    "debian": "debian", "ubuntu": "debian", "kali": "debian", "raspbian": "debian", "linuxmint": "debian",
    "rhel": "redhat", "fedora": "redhat", "centos": "redhat", "rocky": "redhat", "almalinux": "redhat",
    "ol": "redhat", "amzn": "redhat",
    "suse": "suse", "sles": "suse", "opensuse": "suse", "opensuse-leap": "suse", "opensuse-tumbleweed": "suse",
    "alpine": "alpine", "arch": "arch", "gentoo": "gentoo",
}
RELEASE_FILES = ("etc/redhat-release", "etc/system-release", "etc/rocky-release", "etc/centos-release",
                 "etc/fedora-release", "etc/oracle-release", "etc/SUSE-brand", "etc/SuSE-release",
                 "etc/alpine-release", "etc/lsb-release")


def parse_os_release(text):
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r'^\s*([A-Z0-9_]+)=(.*)$', line)
        if m:
            value = m.group(2).strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            out[m.group(1)] = value
    return out


def parse_offset(text):
    """'+08:00', '+0800', 'UTC', 'Z' -> fixed tzinfo, else None."""
    t = text.strip()
    if t.upper() in ("UTC", "Z", "GMT", "ETC/UTC"):
        return dt.timezone.utc
    m = re.fullmatch(r"(?:UTC|GMT)?([+-])(\d{1,2}):?(\d{2})?", t, re.IGNORECASE)
    if not m:
        return None
    delta = dt.timedelta(hours=int(m.group(2)), minutes=int(m.group(3) or 0))
    return dt.timezone(delta if m.group(1) == "+" else -delta, t)


class HostProfile:
    """What the evidence says about the host. `notes` explains where each value came from."""

    def __init__(self, ev, hostname=None, local_tz=None):
        self.notes = []
        self.os = {}
        self.host_id = None
        self.tz = None
        self.tz_name = None
        self.evidence_hostname = self._evidence_hostname(ev)
        if hostname:
            self.hostname = sanitize_hostname(hostname)
            if self.evidence_hostname and sanitize_hostname(self.evidence_hostname) != self.hostname:
                self.notes.append(f"WARNING: --hostname '{hostname}' differs from the evidence"
                                  f" hostname '{self.evidence_hostname}'")
        elif self.evidence_hostname:
            self.hostname = sanitize_hostname(self.evidence_hostname)
        else:
            raise SystemExit("ERROR: no hostname found in the evidence (uac.log, /etc/hostname);"
                             " give one with --hostname")
        self._os(ev)
        machine_id = (ev.read_text(ev.root_path("etc/machine-id")) or "").strip()
        if re.fullmatch(r"[0-9a-f]{32}", machine_id):
            self.host_id = machine_id
        self._kernel(ev)
        self._timezone(ev, local_tz)

    @staticmethod
    def _evidence_hostname(ev):
        log = ev.read_text(ev.base_path("uac.log"), limit=65536)
        if log:
            m = re.search(r"\bHostname: (\S+)", log)
            if m:
                return m.group(1)
        for rel in (ev.root_path("etc/hostname"), ev.base_path("live_response/network/hostname.txt")):
            text = (ev.read_text(rel) or "").strip()
            if text and re.fullmatch(r"[A-Za-z0-9._-]+", text.splitlines()[0].strip()):
                return text.splitlines()[0].strip()
        return None

    def _os(self, ev):
        info = {}
        for rel in ("etc/os-release", "usr/lib/os-release"):
            info = parse_os_release(ev.read_text(ev.root_path(rel)))
            if info:
                break
        os_id = info.get("ID", "").lower()
        like = info.get("ID_LIKE", "").lower().split()
        family = OS_FAMILIES.get(os_id) or next((OS_FAMILIES[x] for x in like if x in OS_FAMILIES), None)
        if not info:
            for rel in RELEASE_FILES:
                text = (ev.read_text(ev.root_path(rel)) or "").strip()
                if text:
                    self.os["full"] = text.splitlines()[0][:200]
                    low = rel.lower()
                    family = ("debian" if "lsb" in low else "suse" if "suse" in low
                              else "alpine" if "alpine" in low else "redhat")
                    break
        self.os.update({k: v for k, v in {
            "type": "linux", "name": info.get("NAME"), "version": info.get("VERSION_ID") or info.get("VERSION"),
            "full": info.get("PRETTY_NAME") or self.os.get("full"), "platform": os_id or None,
            "family": family}.items() if v})

    def _kernel(self, ev):
        text = ev.read_text(ev.base_path("live_response/system/uname_-a.txt"))
        if text:
            parts = text.split()
            if len(parts) >= 3:
                self.os["kernel"] = parts[2]

    def _timezone(self, ev, local_tz):
        name = (ev.read_text(ev.root_path("etc/timezone")) or "").strip().splitlines()
        name = name[0].strip() if name else None
        link = ev.readlink(ev.root_path("etc/localtime"))
        if link and "zoneinfo/" in link:
            name = name or link.split("zoneinfo/", 1)[1]
        if local_tz:
            self.tz = parse_offset(local_tz)
            if self.tz is None and zoneinfo is not None:
                try:
                    self.tz = zoneinfo.ZoneInfo(local_tz)
                except (zoneinfo.ZoneInfoNotFoundError, ValueError):
                    self.tz = None
            if self.tz is None:
                raise SystemExit(f"ERROR: --local-tz '{local_tz}' is neither a UTC offset (+08:00) nor a"
                                 " time zone name this Python knows")
            self.tz_name = local_tz
            self.notes.append(f"time zone {local_tz} (from --local-tz)")
            return
        # The host's own rules: /etc/localtime (TZif) from the evidence, so this works on
        # Windows too, where Python has no time zone database.
        data = ev.read_bytes(ev.root_path("etc/localtime"))
        if (not data or not data.startswith(b"TZif")) and link and "zoneinfo/" in link:
            data = ev.read_bytes(ev.root_path("usr/share/zoneinfo/" + link.split("zoneinfo/", 1)[1]))
        if data and data.startswith(b"TZif") and zoneinfo is not None:
            try:
                self.tz = zoneinfo.ZoneInfo.from_file(io.BytesIO(data), key=name or "localtime")
                self.tz_name = name or "evidence /etc/localtime"
                self.notes.append(f"time zone {self.tz_name} (from the evidence's /etc/localtime)")
                return
            except ValueError:
                pass
        if name and zoneinfo is not None:
            try:
                self.tz = zoneinfo.ZoneInfo(name)
                self.tz_name = name
                self.notes.append(f"time zone {name} (from /etc/timezone)")
                return
            except (zoneinfo.ZoneInfoNotFoundError, ValueError):
                pass
        self.notes.append("WARNING: no time zone found in the evidence; local times in text logs are"
                          " read as UTC (use --local-tz to set one)")

    def fields(self):
        """Fields added to every document."""
        doc = {}
        set_field(doc, "host.name", self.hostname)
        set_field(doc, "host.id", self.host_id)
        for k, v in self.os.items():
            set_field(doc, f"host.os.{k}", v)
        return doc

    def describe(self):
        bits = [f"host '{self.hostname}'"]
        if self.os.get("full") or self.os.get("name"):
            bits.append(self.os.get("full") or self.os.get("name"))
        if self.os.get("family"):
            bits.append(f"family {self.os['family']}")
        if self.host_id:
            bits.append(f"machine-id {self.host_id}")
        return ", ".join(bits)


# --------------------------------------------------------------------------- templates

def _load_json(name, folder=TEMPLATE_DIR):
    path = folder / name
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Cannot read index template {path}: {exc}")


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in extra.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        elif isinstance(v, list) and isinstance(out.get(k), list):
            out[k] = out[k] + copy.deepcopy(v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_templates(prefix, template_set="linux"):
    """(component, index_template, merged index body) for an index prefix like 'logstash'."""
    folder, component_file, _ = TEMPLATE_SETS[template_set]
    component = _load_json(component_file, folder)
    index_tpl = _load_json(f"index-{prefix}.json", folder)
    merged = _merge(component.get("template", {}), index_tpl.get("template", {}))
    return component, index_tpl, merged


def template_fields(mappings):
    """{"dotted.leaf": type} from mapping properties."""
    exact = {}

    def walk(props, prefix):
        for name, spec in props.items():
            path = f"{prefix}{name}"
            if "properties" in spec:
                walk(spec["properties"], path + ".")
            else:
                exact[path] = spec.get("type", "object")

    walk(mappings.get("properties", {}), "")
    return exact


def unknown_fields(doc, exact):
    """Leaf fields of doc that the template does not map (Elasticsearch would drop them)."""
    out = []

    def walk(obj, prefix):
        for k, v in obj.items():
            path = f"{prefix}{k}"
            if isinstance(v, dict):
                walk(v, path + ".")
            elif path not in exact:
                out.append(path)

    walk(doc, "")
    return out


# --------------------------------------------------------------------------- Elasticsearch

class ES(EsClient):
    def call(self, method, path, body=None, ctype="application/json"):
        if body is not None and not isinstance(body, (str, bytes)):
            body = json.dumps(body)
        return self.request(method, path, body, ctype)

    def install_component(self, component, name=COMMON_COMPONENT):
        status, resp = self.call("PUT", f"/_component_template/{name}", component)
        if status >= 300:
            sys.exit(f"Could not install component template {name} ({status}):"
                     f" {json.dumps(resp)[:500]}")

    def install_index_template(self, prefix, index_tpl):
        status, resp = self.call("PUT", f"/_index_template/sofelk-toolkit-{prefix}", index_tpl)
        if status >= 300:
            sys.exit(f"Could not install index template sofelk-toolkit-{prefix} ({status}):"
                     f" {json.dumps(resp)[:500]}")

    def prepare_index(self, schema, index, body):
        """Create the index from the template body, or extend an existing toolkit index."""
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            status, resp = self.call("PUT", f"/{index}", body)
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
            return "created"
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        mapping = next(iter(resp.values()), {}).get("mappings", {})
        if mapping.get("_meta", {}).get("toolkit_schema") != schema:
            sys.exit(f"Index '{index}' exists but was not created by this importer (for example by"
                     f" SOF-ELK's Logstash pipeline or an earlier tool), so its field types may"
                     f" differ.\nDelete it and reload:  curl -X DELETE '{self.url}/{index}'")
        new = {"_meta": body["mappings"]["_meta"], "properties": body["mappings"]["properties"]}
        status, resp = self.call("PUT", f"/{index}/_mapping", new)
        if status >= 300:
            sys.exit(f"Index '{index}' mapping does not match the current template ({status}):"
                     f" {json.dumps(resp)[:500]}\nDelete the index and reload.")
        return "appending"

    def send(self, lines, stats):
        if not lines:
            return
        status, resp = self.bulk(lines)
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    err = res["error"]
                    print(f"    ! {err.get('reason', err) if isinstance(err, dict) else err}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def count(self, index, query):
        self.call("POST", f"/{index}/_refresh")
        status, resp = self.call("POST", f"/{index}/_count", {"query": query})
        return resp.get("count") if status < 300 else None


# --------------------------------------------------------------------------- source description

class LogSource:
    """One importer's description, as used by run_sources().

    name        short name used in messages and --only ("journal", "syslog")
    prefix      index prefix ("logstash")
    dataset     event.dataset of its documents, used for the index check ("syslog.journal"); a
                tuple or list when one source writes several datasets ("linux.account", ...)
    templates   template set (TEMPLATE_SETS): "linux", or "windows" for an index family the
                Windows importers already define
    collect     (ev, profile, args) -> list of work items, or None if there is nothing to do
    parse       (ev, profile, args, item, report) -> iterator of (id_parts, doc) or (None, reason)
    missing     optional (ev, profile, args) -> (exit code, message) when collect found nothing
    item_label  item -> text for progress lines
    """

    def __init__(self, name, prefix, dataset, collect, parse, item_label=str, missing=None, templates="linux"):
        self.name = name
        self.prefix = prefix
        self.dataset = dataset
        self.datasets = tuple(dataset) if isinstance(dataset, (tuple, list)) else (dataset,)
        self.templates = templates
        self.collect = collect
        self.parse = parse
        self.item_label = item_label
        self.missing = missing
        self.index_template = prefix not in SOFELK_FAMILIES


# Index families SOF-ELK itself writes as <family>-YYYY.MM: a toolkit index template for
# <family>-* would take over those indexes, so the index is created with the body instead.
SOFELK_FAMILIES = {"logstash", "httpdlog"}


class Report:
    """Per-source counters and messages."""

    def __init__(self):
        self.skipped = {}
        self.warnings = []

    def skip(self, reason, n=1):
        self.skipped[reason] = self.skipped.get(reason, 0) + n

    def warn(self, text):
        if text not in self.warnings:
            self.warnings.append(text)


def build_parser(description, sources, epilog=""):
    ap = argparse.ArgumentParser(description=description, epilog=epilog,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence", help="UAC output (.zip or extracted folder), or any collected root"
                                     " filesystem / mounted image (the folder holding etc/ and var/log/)")
    ap.add_argument("--hostname", help="Evidence host name for the index name <prefix>-<hostname>"
                                       " (default: read from uac.log or /etc/hostname)")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--local-tz", help="Time zone for local times in text logs: an offset (+08:00) or an"
                                       " IANA name (Asia/Singapore). Default: the evidence's /etc/localtime")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true", help="Parse everything and show sample documents;"
                                                           " send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents per source in --dry-run")
    if len(sources) > 1:
        ap.add_argument("--only", help="Comma-separated subset to load: " + ", ".join(s.name for s in sources))
    for s in sources:
        if getattr(s, "add_arguments", None):
            s.add_arguments(ap)
    add_client_arguments(ap)
    return ap


def run_sources(sources, description, argv=None, epilog=""):
    """Command-line entry point shared by linux2sofelk.py and the single-source importers."""
    ap = build_parser(description, sources, epilog)
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    selected = sources
    if getattr(args, "only", None):
        wanted = {x.strip().lower() for x in args.only.split(",") if x.strip()}
        unknown = wanted - {s.name for s in sources}
        if unknown:
            sys.exit(f"--only: unknown source(s) {', '.join(sorted(unknown))}")
        selected = [s for s in sources if s.name in wanted]

    ev = Evidence(args.evidence)
    profile = HostProfile(ev, args.hostname, args.local_tz)
    kind = "UAC collection" if ev.is_uac else "collected root filesystem"
    print(f"Evidence: {ev.path} ({kind}{', zip' if ev.is_zip else ''};"
          f" root '{ev.root or '.'}')")
    print(f"Host: {profile.describe()}")
    for note in profile.notes:
        print(f"  {note}")

    es = None
    if not args.dry_run:
        es = ES(args.es, args.user, args.password, args.insecure)
        try:
            status, info = es.call("GET", "/")
        except error.URLError as exc:
            sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {exc.reason}")
        if status >= 300:
            sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
        print(f"Connected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    exit_code = 0
    for source in selected:
        code = run_source(source, ev, profile, args, es)
        exit_code = max(exit_code, code)
    return exit_code


def run_source(source, ev, profile, args, es):
    print(f"\n=== {source.name} ===")
    items = source.collect(ev, profile, args)
    if not items:
        if source.missing:
            code, message = source.missing(ev, profile, args)
            print(message)
            return code
        print(f"No {source.name} input found.")
        return 0
    index = resolve_index(source.prefix, profile.hostname)
    component, index_tpl, body = load_templates(source.prefix, source.templates)
    exact = template_fields(body["mappings"])
    if es is not None:
        es.install_component(component, TEMPLATE_SETS[source.templates][2])
        if source.index_template:
            es.install_index_template(source.prefix, index_tpl)
        print(f"Index '{index}': {es.prepare_index(source.prefix, index, body)}")
    else:
        print(f"Target index: '{index}'")

    common = profile.fields()
    if args.case:
        common["case"] = args.case
    report = Report()
    total = {"records": 0, "ok": 0, "errors": 0, "updated": 0}
    unmapped, samples, lines, seen_datasets = {}, [], [], set()
    for item in items:
        n = 0
        for parts, doc in source.parse(ev, profile, args, item, report):
            if parts is None:
                report.skip(doc)
                continue
            n += 1
            for k, v in common.items():
                if k == "host":
                    doc.setdefault("host", {}).update({hk: hv for hk, hv in v.items()
                                                       if hk not in doc["host"]})
                else:
                    doc.setdefault(k, copy.deepcopy(v))
            seen_datasets.add(get_field(doc, "event.dataset"))
            for name in unknown_fields(doc, exact):
                unmapped[name] = unmapped.get(name, 0) + 1
            _id = doc_id(source.prefix, profile.hostname, *parts)
            if es is None:
                if len(samples) < args.sample_docs:
                    samples.append(doc)
                continue
            lines.append(json.dumps({"index": {"_index": index, "_id": _id}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
            if len(lines) >= args.batch_size * 2:
                es.send(lines, total)
        total["records"] += n
        print(f"  {source.item_label(item)}: {n} record(s)")
    if es is not None:
        es.send(lines, total)

    for text in report.warnings:
        print(f"WARNING: {text}")
    if report.skipped:
        print("Not loaded:")
        for reason, n in sorted(report.skipped.items()):
            print(f"  {reason}: {n}")
    if unmapped:
        print(f"WARNING: fields not in index-{source.prefix}.json (Elasticsearch will not index them):")
        for name, n in sorted(unmapped.items()):
            print(f"  {name}: {n} document(s)")

    if es is None:
        print(f"{total['records']} record(s) parsed. Sample document(s):")
        for doc in samples:
            print("  " + json.dumps(doc, ensure_ascii=False)[:2000])
        print("Dry run only - nothing sent.")
        return 0
    new = total["ok"] - total["updated"]
    print(f"Done: {total['records']} record(s) read -> {new} new documents, {total['updated']}"
          f" already in index (re-run), {total['errors']} errors.")
    query = {"bool": {"filter": [{"term": {"host.name": profile.hostname}},
                                 {"terms": {"event.dataset": sorted(source.datasets)}}]}}
    in_index = es.count(index, query)
    if in_index is not None:
        verdict = "matches" if in_index == total["records"] else "DOES NOT MATCH"
        shown = sorted(d for d in seen_datasets if d) or list(source.datasets)
        print(f"Index check: '{index}' holds {in_index} {'/'.join(shown)} documents for host"
              f" '{profile.hostname}' ({verdict} the {total['records']} records read).")
    return 1 if total["errors"] else 0

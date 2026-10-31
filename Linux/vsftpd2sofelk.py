#!/usr/bin/env python3
"""Load FTP server logs (vsftpd.log and xferlog) into SOF-ELK as logstash-<hostname>.

Files looked for under the evidence's /var/log, current and rotated (.1, .2.gz, -20261025):
  vsftpd.log         vsftpd's own log (vsftpd_log_file; written when xferlog_std_format=NO or
                     dual_log_enable=YES). Logins, failed logins, uploads, downloads, deletes,
                     mkdir/rmdir, renames, and every FTP command/response with log_ftp_protocol=YES.
  xferlog            the wu-ftpd transfer log format, written by vsftpd (RHEL default:
                     /var/log/xferlog), ProFTPD (/var/log/proftpd/xferlog) and pure-ftpd.
--ftp-log adds files kept elsewhere. vsftpd set to log through syslog (syslog_enable=YES) is
already covered by journal2sofelk.py / syslog2sofelk.py.

Time zone: vsftpd writes GMT unless use_localtime=YES (Debian and Ubuntu ship YES). The setting
is read from the evidence's /etc/vsftpd.conf or /etc/vsftpd/vsftpd.conf; --ftp-time local|utc
overrides it. ProFTPD's xferlog is always local time. The zone used is in event.timezone.

Passwords never reach Elasticsearch: the argument of a logged PASS command, vsftpd's
'anon password "..."' and xferlog's user name field for anonymous sessions (which holds the
password typed) are replaced with <redacted>, in message as well as in ftp.* and user.name.

Documents share logstash-<hostname> with the system logs, with SOF-ELK's syslog names
(log.syslog.appname vsftpd/proftpd, process.pid, message) plus user.name, source.ip, file.path,
event.action (ftp-login, ftp-download, ftp-upload, ftp-delete, ftp-mkdir, ftp-rmdir,
ftp-rename, ftp-chmod, ftp-connect, ftp-command, ftp-response), event.outcome and ftp.*.
event.dataset is ftp.vsftpd or ftp.xferlog.

Example:
  python3 Linux/vsftpd2sofelk.py /cases/uac-ftp01.zip --case IR-42 --dry-run
"""
import datetime as dt
import hashlib
import ipaddress
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import (LogSource, iso_utc, rotation_family, rotation_sort_key,  # noqa: E402
                                  run_sources, set_field)

FAMILIES = {"vsftpd.log", "xferlog", "xferlog.log"}
FTP_DIRS = {"vsftpd", "proftpd", "pure-ftpd"}
DATASETS = ("ftp.vsftpd", "ftp.xferlog")
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
TIME = r"(?P<time>[A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2} \d{4})"
VSFTPD_RE = re.compile(TIME + r" \[pid (?P<pid>\d+)\] (?:\[(?P<user>[^\]]*)\] )?(?P<what>[A-Za-z ]+?):"
                       r" Client \"(?P<client>[^\"]*)\"(?:, (?P<rest>.*))?$")
XFERLOG_RE = re.compile(TIME + r" (?P<secs>\d+) (?P<host>\S+) (?P<size>\d+) (?P<file>.+) (?P<type>[ab])"
                        r" (?P<flag>[CUT_]+) (?P<dir>[oid]) (?P<mode>[agr]) (?P<user>\S+) (?P<service>\S+)"
                        r" (?P<auth>[01]) (?P<authuser>\S+) (?P<status>[ci])$")
TRANSFER_RE = re.compile(r'^"(?P<path>.*)", (?P<bytes>\d+) bytes, (?P<rate>\S+)$')
QUOTED_RE = re.compile(r'^"(?P<value>.*)"$')
PASS_RE = re.compile(r"(?i)^(PASS)(?: .*)?$")
ANON_RE = re.compile(r'anon password ".*"$')

ACTIONS = {
    "CONNECT": ("ftp-connect", "network", "connection"),
    "LOGIN": ("ftp-login", "authentication", "start"),
    "DOWNLOAD": ("ftp-download", "file", "access"),
    "UPLOAD": ("ftp-upload", "file", "creation"),
    "DELETE": ("ftp-delete", "file", "deletion"),
    "MKDIR": ("ftp-mkdir", "file", "creation"),
    "RMDIR": ("ftp-rmdir", "file", "deletion"),
    "RENAME": ("ftp-rename", "file", "change"),
    "CHMOD": ("ftp-chmod", "file", "change"),
    "FTP COMMAND": ("ftp-command", "network", "protocol"),
    "FTP RESPONSE": ("ftp-response", "network", "protocol"),
}
XFER_DIRECTION = {"o": ("outgoing", "ftp-download", "access"), "i": ("incoming", "ftp-upload", "creation"),
                  "d": ("delete", "ftp-delete", "deletion")}
XFER_MODE = {"a": "anonymous", "g": "guest", "r": "real"}
XFER_FLAGS = {"C": "compressed", "U": "uncompressed", "T": "tar", "_": "none"}


# --------------------------------------------------------------------------- input discovery

def collect(ev, profile, args):
    items = []
    folder = ev.root_path("var/log")
    if ev.is_dir(folder):
        for path in ev.walk(folder, max_depth=2):
            name = PurePosixPath(path).name
            parent = PurePosixPath(path).parent.name.lower()
            family = rotation_family(name)
            direct = PurePosixPath(path).parent.as_posix() == folder
            if not (direct or parent in FTP_DIRS) or ev.size(path) == 0:
                continue
            # pure-ftpd's transfer.log is xferlog format when AltLog is set to xferlog.
            if family in FAMILIES or (parent == "pure-ftpd" and family == "transfer.log"):
                items.append(path)
    for extra in args.ftp_log or []:
        rel = ev.root_path(extra.lstrip("/"))
        if ev.exists(rel):
            items.append(rel)
        else:
            print(f"  --ftp-log {extra}: not found in the evidence ({rel})")
    return sorted(set(items), key=rotation_sort_key)


def add_arguments(ap):
    ap.add_argument("--ftp-log", action="append",
                    help="Extra vsftpd.log or xferlog file, as a path on the evidence host; repeatable")
    ap.add_argument("--ftp-time", choices=("auto", "local", "utc"), default="auto",
                    help="Clock of vsftpd's logs: local (use_localtime=YES) or utc. Default: read"
                         " use_localtime from the evidence's vsftpd.conf (vsftpd's default is UTC)")


def vsftpd_uses_localtime(ev):
    """True/False from use_localtime in the evidence's vsftpd.conf, None when there is no config."""
    for rel in ("etc/vsftpd.conf", "etc/vsftpd/vsftpd.conf"):
        text = ev.read_text(ev.root_path(rel))
        if text is None:
            continue
        value = False
        for line in text.splitlines():
            m = re.match(r"^\s*use_localtime\s*=\s*(\S+)", line)
            if m:
                value = m.group(1).upper() in ("YES", "TRUE", "1")
        return value
    return None


# --------------------------------------------------------------------------- parsing helpers

def parse_time(text, tz):
    parts = re.sub(r"\s+", " ", text.strip()).split(" ")
    try:
        hh, mm, ss = map(int, parts[3].split(":"))
        return dt.datetime(int(parts[4]), MONTHS[parts[1]], int(parts[2]), hh, mm, ss, tzinfo=tz)
    except (KeyError, ValueError, IndexError):
        return None


def set_client(doc, text):
    if not text:
        return
    try:
        ip = ipaddress.ip_address(text)
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        set_field(doc, "source.ip", str(ip))
    except ValueError:
        set_field(doc, "source.address", text)


def redact(line):
    """Drop passwords: PASS arguments and anonymous passwords."""
    line = ANON_RE.sub('anon password "<redacted>"', line)
    return re.sub(r'(?i)("PASS) .*"$', r'\1 <redacted>"', line)


def parse_vsftpd(m, doc):
    what = m.group("what").strip()
    words = what.split(" ", 1)
    status = None
    if words[0] in ("OK", "FAIL") and len(words) == 2:
        status, verb = words[0], words[1].upper()
    else:
        verb = what.upper()
    action = ACTIONS.get(verb)
    set_field(doc, "ftp.action", what)
    set_field(doc, "process.pid", int(m.group("pid")))
    set_field(doc, "log.syslog.procid", m.group("pid"))
    user = m.group("user")
    if user:
        set_field(doc, "user.name", user)
    set_client(doc, m.group("client"))
    if action:
        set_field(doc, "event.action", action[0])
        set_field(doc, "event.category", action[1])
        set_field(doc, "event.type", action[2])
    elif verb:
        set_field(doc, "event.action", "ftp-" + verb.lower().replace(" ", "-"))
    if status:
        set_field(doc, "event.outcome", "success" if status == "OK" else "failure")
    rest = m.group("rest") or ""
    t = TRANSFER_RE.match(rest)
    q = QUOTED_RE.match(rest)
    if t:
        set_field(doc, "file.path", t.group("path"))
        set_field(doc, "ftp.transfer.bytes", int(t.group("bytes")))
        set_field(doc, "ftp.transfer.rate", t.group("rate"))
    elif verb == "FTP COMMAND" and q:
        cmd, _, arg = q.group("value").partition(" ")
        set_field(doc, "ftp.command", cmd.upper())
        if PASS_RE.match(q.group("value")):
            arg = "<redacted>" if arg else ""
        set_field(doc, "ftp.command_arg", arg)
    elif verb == "FTP RESPONSE" and q:
        code, _, text = q.group("value").partition(" ")
        if code.isdigit():
            set_field(doc, "ftp.response.code", int(code))
            set_field(doc, "ftp.response.message", text)
        else:
            set_field(doc, "ftp.response.message", q.group("value"))
    elif verb == "RENAME" and q:
        # vsftpd writes '"<old> <new>"'; paths with spaces make the split ambiguous, so the
        # original text stays in message and ftp.rename_to holds the last word.
        old, _, new = q.group("value").rpartition(" ")
        set_field(doc, "file.path", old or q.group("value"))
        set_field(doc, "ftp.rename_to", new if old else None)
    elif q:
        set_field(doc, "file.path", q.group("value"))
    if doc.get("file", {}).get("path"):
        set_field(doc, "file.name", PurePosixPath(doc["file"]["path"]).name)


def parse_xferlog(m, doc):
    direction, action, etype = XFER_DIRECTION[m.group("dir")]
    set_field(doc, "event.action", action)
    set_field(doc, "event.category", "file")
    set_field(doc, "event.type", etype)
    set_field(doc, "event.outcome", "success" if m.group("status") == "c" else "failure")
    set_client(doc, m.group("host"))
    set_field(doc, "file.path", m.group("file"))
    set_field(doc, "file.name", PurePosixPath(m.group("file")).name)
    set_field(doc, "user.name", "anonymous" if m.group("mode") == "a" else m.group("user"))
    set_field(doc, "ftp.transfer.bytes", int(m.group("size")))
    set_field(doc, "ftp.transfer.duration", int(m.group("secs")))
    set_field(doc, "ftp.transfer.type", "ascii" if m.group("type") == "a" else "binary")
    set_field(doc, "ftp.transfer.direction", direction)
    set_field(doc, "ftp.special_action", ",".join(XFER_FLAGS.get(c, c) for c in m.group("flag")))
    set_field(doc, "ftp.access_mode", XFER_MODE[m.group("mode")])
    set_field(doc, "ftp.service", m.group("service"))
    set_field(doc, "ftp.auth_method", "rfc931" if m.group("auth") == "1" else "none")
    set_field(doc, "ftp.auth_user_id", None if m.group("authuser") == "*" else m.group("authuser"))
    set_field(doc, "ftp.completion", "complete" if m.group("status") == "c" else "incomplete")


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    rel = item
    is_proftpd = "proftpd" in rel.lower()
    local = vsftpd_uses_localtime(ev)
    if args.ftp_time != "auto":
        local = args.ftp_time == "local"
    elif is_proftpd:
        local = True
    elif local is None:
        report.warn("no vsftpd.conf in the evidence: vsftpd log times were read as UTC (vsftpd's"
                    " default); use --ftp-time local if use_localtime=YES was set")
        local = False
    tz = (profile.tz or dt.timezone.utc) if local else dt.timezone.utc
    tz_name = (profile.tz_name or "UTC") if local else "UTC"
    app = "proftpd" if is_proftpd else "vsftpd"
    family = f"{ev.evidence_path(str(PurePosixPath(rel).parent))}/{rotation_family(PurePosixPath(rel).name)}"
    seen = parse.seen
    with ev.open_text(rel) as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            clean = redact(line)
            doc = {}
            m = VSFTPD_RE.match(clean)
            if m:
                dataset = "ftp.vsftpd"
                parse_vsftpd(m, doc)
            else:
                m = XFERLOG_RE.match(clean)
                if not m:
                    yield None, "line in neither vsftpd.log nor xferlog format"
                    continue
                dataset = "ftp.xferlog"
                if m.group("mode") == "a":
                    # For anonymous sessions xferlog's user name field is the password typed.
                    clean = clean[:m.start("user")] + "<redacted>" + clean[m.end("user"):]
                parse_xferlog(m, doc)
            stamp = parse_time(m.group("time"), tz)
            if stamp is None:
                yield None, "invalid date in line"
                continue
            doc["@timestamp"] = iso_utc(stamp)
            set_field(doc, "message", clean)
            set_field(doc, "log.syslog.appname", app)
            set_field(doc, "process.name", app)
            set_field(doc, "event.kind", "event")
            set_field(doc, "event.dataset", dataset)
            set_field(doc, "event.timezone", tz_name)
            set_field(doc, "labels.type", "ftp")
            set_field(doc, "log.file.path", rel)
            set_field(doc, "log.offset", offset)
            key = hashlib.sha1(line.encode("utf-8", "replace")).digest()
            n = seen.get((family, key), 0)
            seen[(family, key)] = n + 1
            yield [dataset, family, key.hex(), n], doc


parse.seen = {}

VSFTPD = LogSource("vsftpd", "logstash", DATASETS, collect, parse, str)
VSFTPD.add_arguments = add_arguments


def main(argv=None):
    return run_sources([VSFTPD], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

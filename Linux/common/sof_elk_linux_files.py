"""File metadata and safe file walking for the snapshot importers (packages, linuxconfig).

Snapshot documents (an account, a cron entry, a systemd unit, an installed package) take
their @timestamp from the source file's modification time, and systemd persistence depends
on symlinks (multi-user.target.wants/x.service -> /usr/lib/systemd/system/x.service). Where
that information comes from depends on the collection:

  * UAC writes bodyfile/bodyfile.txt (TSK body format: MD5|name|inode|mode|uid|gid|size|
    atime|mtime|ctime|crtime, with "name -> target" for symlinks). It holds exact epoch times,
    owners, modes and symlink targets for every file on the host, including files UAC did not
    copy (e.g. /var/lib/dpkg/info/*.list). This is the preferred source.
  * A folder (mounted image, tar extract): os.lstat() and os.readlink() on the evidence copy.
    Symlinks are NOT followed on the analyst's machine: an absolute link such as
    /usr/lib/systemd/system/cron.service is resolved inside the evidence root instead.
  * A zip without a bodyfile: the zip entry's date, which zip stores in the collecting host's
    local time (2-second resolution); it is read with the evidence host's time zone. UAC
    stores symlinks as copies of their target, so links cannot be told apart from files.

FileMeta.get(path) returns a dict with the absolute evidence path and whatever is known:
mtime/atime/ctime (aware UTC datetimes), uid, gid, mode, size, link target, and "source"
("bodyfile", "filesystem" or "zip").

Standard library only (Python 3.9+).
"""
from __future__ import annotations

import datetime as dt
import os
import posixpath
import stat as statmod

EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
BODYFILE_NAMES = ("bodyfile/bodyfile.txt", "bodyfile.txt")


def epoch_to_dt(value):
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return EPOCH + dt.timedelta(seconds=seconds)
    except OverflowError:
        return None


def iso(stamp):
    if stamp is None:
        return None
    stamp = stamp.astimezone(dt.timezone.utc)
    return stamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{stamp.microsecond:06d}Z"


def host_path(ev, rel):
    """Container path ([root]/etc/passwd) -> absolute path on the evidence host (/etc/passwd)."""
    root = ev.root.strip("/")
    rel = rel.strip("/")
    if root and rel.startswith(root + "/"):
        rel = rel[len(root) + 1:]
    elif root and rel == root:
        rel = ""
    return "/" + rel


def mode_string(mode_text):
    """'-rw-r--r--' / 'lrwxrwxrwx' (bodyfile) -> (octal permission string, is_link)."""
    if not mode_text or len(mode_text) < 10:
        return None, False
    perms = mode_text[-9:]
    value = 0
    for i, ch in enumerate(perms):
        if ch not in "-":
            if ch in "sStT" and i in (2, 5, 8):
                # setuid / setgid / sticky: execute bit is set for lowercase s/t
                if ch in "st":
                    value |= 1 << (8 - i)
                value |= {2: 0o4000, 5: 0o2000, 8: 0o1000}[i]
            else:
                value |= 1 << (8 - i)
    return f"{value:04o}", mode_text[0] == "l"


class FileMeta:
    """Metadata lookups for evidence files, from the bodyfile when there is one."""

    def __init__(self, ev, profile):
        self.ev = ev
        self.profile = profile
        self.body = None          # {abs path: entry} once loaded
        self.body_rel = None
        for name in BODYFILE_NAMES:
            rel = ev.base_path(name)
            if ev.exists(rel):
                self.body_rel = rel
                break
        self._wanted_prefixes = set()
        self._loaded_prefixes = set()

    @property
    def has_bodyfile(self):
        return self.body_rel is not None

    def want(self, *prefixes):
        """Register absolute path prefixes whose bodyfile entries should be loaded."""
        for p in prefixes:
            self._wanted_prefixes.add(p)

    def _covered(self, prefix):
        return any(prefix.startswith(done) for done in self._loaded_prefixes)

    def _load(self):
        missing = {p for p in self._wanted_prefixes - self._loaded_prefixes if not self._covered(p)}
        self._wanted_prefixes -= {p for p in self._wanted_prefixes if p not in missing}
        if not self.has_bodyfile or (self.body is not None and not missing):
            return
        if self.body is None:
            self.body = {}
        prefixes = tuple(sorted(missing))
        with self.ev.open_text(self.body_rel) as fh:
            for line in fh:
                parts = line.rstrip("\r\n").split("|")
                if len(parts) < 11:
                    continue
                name = parts[1]
                target = None
                if " -> " in name and parts[3].startswith("l"):
                    name, target = name.split(" -> ", 1)
                if not name.startswith(prefixes):
                    continue
                perm, is_link = mode_string(parts[3])
                entry = {"path": name, "source": "bodyfile", "mode": perm, "link": is_link,
                         "target": target, "mode_text": parts[3]}
                for key, idx in (("uid", 4), ("gid", 5), ("size", 6)):
                    try:
                        entry[key] = int(parts[idx])
                    except ValueError:
                        pass
                for key, idx in (("atime", 7), ("mtime", 8), ("ctime", 9), ("crtime", 10)):
                    entry[key] = epoch_to_dt(parts[idx])
                self.body[name] = entry
        self._loaded_prefixes |= missing

    def bodyfile_entry(self, abs_path):
        if not self._covered(abs_path):
            self.want(abs_path)
            self._load()
        return (self.body or {}).get(abs_path)

    def bodyfile_children(self, abs_dir):
        """Bodyfile entries directly inside abs_dir (needs want(abs_dir + '/') first)."""
        if not self._covered(abs_dir.rstrip("/") + "/"):
            self.want(abs_dir.rstrip("/") + "/")
            self._load()
        prefix = abs_dir.rstrip("/") + "/"
        return [e for p, e in (self.body or {}).items() if p.startswith(prefix) and "/" not in p[len(prefix):]]

    def bodyfile_under(self, abs_dir, max_depth=2):
        """Bodyfile entries below abs_dir, at most max_depth folders down (needs a prior want())."""
        prefix = abs_dir.rstrip("/") + "/"
        if not self._covered(prefix):
            self.want(prefix)
            self._load()
        return [e for p, e in (self.body or {}).items()
                if p.startswith(prefix) and p[len(prefix):].count("/") < max_depth]

    def get(self, rel):
        """Metadata of a container path; never follows symlinks on the analyst's machine."""
        path = host_path(self.ev, rel)
        entry = self.bodyfile_entry(path) if self.has_bodyfile else None
        if entry:
            return dict(entry)
        if not self.ev.is_zip:
            try:
                st = os.lstat(self.ev.path / rel)
            except OSError:
                return {"path": path, "source": None}
            entry = {"path": path, "source": "filesystem", "uid": st.st_uid, "gid": st.st_gid,
                     "size": st.st_size, "mode": f"{statmod.S_IMODE(st.st_mode):04o}",
                     "link": statmod.S_ISLNK(st.st_mode), "target": None,
                     "mtime": epoch_to_dt(st.st_mtime), "atime": epoch_to_dt(st.st_atime),
                     "ctime": epoch_to_dt(st.st_ctime)}
            if entry["link"]:
                try:
                    entry["target"] = os.readlink(self.ev.path / rel)
                except OSError:
                    pass
            return entry
        info = self.ev.infos.get(rel)
        if info is None:
            return {"path": path, "source": None}
        naive = dt.datetime(*info.date_time)
        tz = self.profile.tz or dt.timezone.utc
        entry = {"path": path, "source": "zip", "size": info.file_size, "link": False, "target": None}
        try:
            entry["mtime"] = naive.replace(tzinfo=tz).astimezone(dt.timezone.utc)
        except (OverflowError, ValueError):
            pass
        mode = (info.external_attr >> 16) & 0o177777
        if mode:
            entry["mode"] = f"{statmod.S_IMODE(mode):04o}"
            if statmod.S_ISLNK(mode):
                entry["link"] = True
                entry["target"] = self.ev.readlink(rel)
        return entry


def file_fields(doc, meta, set_field):
    """file.* fields (ECS) from a FileMeta entry."""
    if not meta:
        return
    path = meta.get("path")
    set_field(doc, "file.path", path)
    if path:
        set_field(doc, "file.name", posixpath.basename(path))
        set_field(doc, "file.directory", posixpath.dirname(path))
    set_field(doc, "file.mtime", iso(meta.get("mtime")))
    set_field(doc, "file.ctime", iso(meta.get("ctime")))
    set_field(doc, "file.uid", str(meta["uid"]) if meta.get("uid") is not None else None)
    set_field(doc, "file.gid", str(meta["gid"]) if meta.get("gid") is not None else None)
    set_field(doc, "file.mode", meta.get("mode"))
    set_field(doc, "file.size", meta.get("size"))
    if meta.get("link"):
        set_field(doc, "file.type", "symlink")
        set_field(doc, "file.target_path", meta.get("target"))
    elif meta.get("source"):
        set_field(doc, "file.type", "file")


def resolve_in_root(ev, link_rel, target):
    """Container path that a symlink in the evidence points to, resolved inside the evidence root."""
    if target is None:
        return None
    if target.startswith("/"):
        candidate = ev.root_path(target.lstrip("/"))
    else:
        candidate = posixpath.normpath(posixpath.join(posixpath.dirname(link_rel), target))
    return candidate


def walk(ev, rel_dir, recursive=False, max_depth=6):
    """Files under a container folder, as container paths. Symlinks are listed (not followed).

    For folder inputs, symlinked files are reported even when their target is outside the
    evidence (an absolute link that would otherwise resolve on the analyst's machine).
    """
    rel_dir = rel_dir.strip("/")
    out = []
    if ev.is_zip:
        if not ev.is_dir(rel_dir):
            return out
        prefix = rel_dir + "/" if rel_dir else ""
        for name in ev.names:
            if not name.startswith(prefix):
                continue
            rest = name[len(prefix):]
            if not recursive and "/" in rest:
                continue
            if rest.count("/") > max_depth:
                continue
            out.append(name)
        return out
    base = ev.path / rel_dir
    if not base.is_dir() or base.is_symlink():
        return out
    stack = [(rel_dir, 0)]
    while stack:
        cur, depth = stack.pop()
        try:
            entries = list(os.scandir(ev.path / cur))
        except OSError:
            continue
        for entry in entries:
            rel = f"{cur}/{entry.name}" if cur else entry.name
            if entry.is_symlink():
                out.append(rel)
            elif entry.is_dir(follow_symlinks=False):
                if recursive and depth < max_depth:
                    stack.append((rel, depth + 1))
            elif entry.is_file(follow_symlinks=False):
                out.append(rel)
    return sorted(out)


def read_lines(ev, rel, limit=8 << 20):
    """Text lines of an evidence file (decompressed), or None. Symlinks in a folder input are
    read from their target inside the evidence root, never from the analyst's machine."""
    if not ev.is_zip:
        p = ev.path / rel
        if p.is_symlink():
            try:
                target = os.readlink(p)
            except OSError:
                return None
            resolved = resolve_in_root(ev, rel, target)
            if resolved is None or resolved == rel:
                return None
            if (ev.path / resolved).is_symlink():
                return read_lines(ev, resolved, limit) if resolved.count("/") < 64 else None
            rel = resolved
        if not (ev.path / rel).is_file():
            return None
    elif not ev.exists(rel):
        return None
    try:
        with ev.open_binary(rel) as fh:
            data = fh.read(limit)
    except (OSError, EOFError, ValueError):
        return None
    return data.decode("utf-8", "replace").splitlines()

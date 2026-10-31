#!/usr/bin/env python3
"""Load a Linux bodyfile (file system timeline) into SOF-ELK as bodyfile-<hostname>.

A bodyfile has one line per file system entry, in the Sleuth Kit 3.x format that UAC,
`fls -r -m /` and mac-robber all write:

    MD5|name|inode|mode_as_string|UID|GID|size|atime|mtime|ctime|crtime

Inputs:
  * UAC: bodyfile/bodyfile.txt in the collection (read straight out of the zip).
  * --bodyfile FILE (repeatable): any other bodyfile, inside the evidence or anywhere on
    disk, for example `fls -r -m / image.raw > image.body`. .gz/.bz2/.xz are fine.
  * Executable hashes from UAC's hash_executables/hash_executables.{md5,sha1,sha256}
    (md5sum/sha1sum output) are joined on the path into file.hash.*.
  * Owner and group names are resolved from the collected /etc/passwd and /etc/group
    (names at collection time). /etc/shadow is never read.

One document per entry. @timestamp is the modification time (mtime); the other times are in
file.accessed, file.ctime (inode change) and file.created (crtime, left out when 0, which is
normal on ext3 and UFS1). Epoch times need no time zone. Flags for quick hunting:
bodyfile.setuid, setgid, sticky, world_writable, executable, hidden (name starts with "."),
deleted (TSK "(deleted)" entries) and regular_file_in_dev (a regular file under /dev).

The _id is derived from the host, the path and the inode, so loading a later collection of
the same host updates the entries instead of duplicating them.

Example:
  python3 Linux/bodyfile2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
import datetime as dt
import re
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import (EvidenceOrDiskFile, LogSource, iso_utc, load_accounts,  # noqa: E402
                                  run_sources, set_field)

UAC_BODYFILE_DIR = "bodyfile"
HASH_DIR = "hash_executables"
HASH_ALGOS = {"md5": 32, "sha1": 40, "sha256": 64}
HASH_LINE_RE = re.compile(r"^(?P<hash>[0-9a-fA-F]{32,64}) [ *](?P<path>.+)$")
TYPE_NAMES = {"-": "file", "r": "file", "d": "dir", "l": "symlink", "c": "char-device",
              "b": "block-device", "p": "fifo", "s": "socket", "h": "shadow", "w": "whiteout",
              "v": "virtual"}
DELETED_RE = re.compile(r" \((?:deleted|deleted-realloc|realloc)\)$")
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------- input discovery

def collect(ev, profile, args):
    items = []
    folder = ev.base_path(UAC_BODYFILE_DIR)
    if ev.is_dir(folder):
        files, _ = ev.listdir(folder)
        for name in files:
            if name.lower().endswith((".txt", ".body", ".bodyfile")) and ev.size(f"{folder}/{name}") > 0:
                items.append(EvidenceOrDiskFile.member(ev, f"{folder}/{name}"))
    for extra in args.bodyfile or []:
        try:
            items.append(EvidenceOrDiskFile(ev, extra))
        except FileNotFoundError:
            print(f"  --bodyfile {extra}: not found in the evidence or on disk")
    return items


def missing(ev, profile, args):
    return 0, ("No bodyfile found (UAC writes bodyfile/bodyfile.txt). For an image, make one with"
               " `fls -r -m / <image>` and pass it with --bodyfile.")


def add_arguments(ap):
    ap.add_argument("--bodyfile", action="append",
                    help="Bodyfile to load (TSK 3.x format, e.g. from `fls -r -m /`), inside the evidence"
                         " or on disk; repeatable")


def load_hashes(ev):
    """{path: {"md5": ..., "sha1": ...}} from UAC's hash_executables lists."""
    hashes = {}
    folder = ev.base_path(HASH_DIR)
    if not ev.is_dir(folder):
        return hashes
    files, _ = ev.listdir(folder)
    for name in files:
        algo = name.rsplit(".", 1)[-1].lower()
        if algo not in HASH_ALGOS:
            continue
        with ev.open_text(f"{folder}/{name}") as fh:
            for line in fh:
                m = HASH_LINE_RE.match(line.rstrip("\r\n"))
                if m and len(m.group("hash")) == HASH_ALGOS[algo]:
                    hashes.setdefault(m.group("path"), {})[algo] = m.group("hash").lower()
    return hashes


# --------------------------------------------------------------------------- parsing helpers

def parse_mode(text):
    """'drwxr-xr-x' or TSK 'd/drwxr-xr-x' -> (type name, octal string, perms string) or None."""
    if "/" in text:
        text = text.split("/", 1)[1]
    if len(text) != 10:
        return None
    kind, perms = text[0], text[1:]
    if kind not in TYPE_NAMES or not re.fullmatch(r"[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]", perms):
        return None
    value = 0
    for i, ch in enumerate(perms):
        if ch != "-" and ch not in "ST":
            value |= 1 << (8 - i)
    if perms[2] in "sS":
        value |= 0o4000
    if perms[5] in "sS":
        value |= 0o2000
    if perms[8] in "tT":
        value |= 0o1000
    return TYPE_NAMES[kind], f"{value:04o}", perms


def epoch_to_iso(text):
    """Epoch seconds (int or decimal) -> ISO 8601 UTC; None for 0, empty or bad values."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return None
    if value <= 0:
        return None
    try:
        return iso_utc(EPOCH + dt.timedelta(seconds=value))
    except OverflowError:
        return None


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    if not hasattr(parse, "context") or parse.context[0] is not ev:
        users, groups = load_accounts(ev)
        parse.context = (ev, users, groups, load_hashes(ev))
    _, users, groups, hashes = parse.context
    no_time = 0
    with item.open_text() as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            # The name may itself contain "|": take 1 field from the left, 9 from the right.
            head, sep, rest = line.partition("|")
            cols = rest.rsplit("|", 9) if sep else []
            if len(cols) != 10:
                yield None, "line is not in bodyfile format (11 fields)"
                continue
            md5 = head
            name, inode, mode_text, uid, gid, size, atime, mtime, ctime, crtime = cols
            mode = parse_mode(mode_text)
            if mode is None and not re.fullmatch(r"\d+", size or "x"):
                yield None, "line is not in bodyfile format (bad mode and size)"
                continue
            ftype, octal, perms = mode or (None, None, None)

            doc = {}
            path, deleted = name, False
            m = DELETED_RE.search(path)
            if m:
                path, deleted = path[:m.start()], True
            target = None
            if ftype == "symlink" and " -> " in path:
                path, target = path.split(" -> ", 1)
            pp = PurePosixPath(path)
            set_field(doc, "file.path", path)
            set_field(doc, "file.name", pp.name or path)
            set_field(doc, "file.directory", str(pp.parent) if pp.name else None)
            if ftype in ("file", None) and "." in pp.name.lstrip("."):
                set_field(doc, "file.extension", pp.name.rsplit(".", 1)[1].lower()[:64])
            set_field(doc, "file.target_path", target)
            set_field(doc, "file.inode", inode)
            set_field(doc, "file.uid", uid)
            set_field(doc, "file.gid", gid)
            set_field(doc, "file.owner", users.get(uid))
            set_field(doc, "file.group", groups.get(gid))
            try:
                set_field(doc, "file.size", int(size))
            except ValueError:
                pass
            set_field(doc, "file.type", ftype)
            set_field(doc, "file.mode", octal)
            set_field(doc, "bodyfile.mode_string", mode_text)
            times = {}
            for field, value in (("accessed", atime), ("mtime", mtime), ("ctime", ctime), ("created", crtime)):
                times[field] = epoch_to_iso(value)
                set_field(doc, f"file.{field}", times[field])
            stamp = times["mtime"] or times["ctime"] or times["created"] or times["accessed"]
            if stamp is None:
                no_time += 1
            set_field(doc, "@timestamp", stamp)
            hash_set = dict(hashes.get(path, {}))
            if md5 and md5 != "0" and re.fullmatch(r"[0-9a-fA-F]{32}", md5):
                hash_set.setdefault("md5", md5.lower())
            for algo, value in hash_set.items():
                set_field(doc, f"file.hash.{algo}", value)

            if perms:
                doc.setdefault("bodyfile", {}).update({
                    "setuid": perms[2] in "sS",
                    "setgid": perms[5] in "sS",
                    "sticky": perms[8] in "tT",
                    "world_writable": perms[7] == "w" and ftype != "symlink",
                    "executable": ftype == "file" and any(perms[i] in "xst" for i in (2, 5, 8)),
                })
            bf = doc.setdefault("bodyfile", {})
            bf["deleted"] = deleted
            bf["hidden"] = pp.name.startswith(".") and pp.name not in (".", "..")
            bf["regular_file_in_dev"] = ftype == "file" and (path.startswith("/dev/") or path == "/dev")

            set_field(doc, "event.kind", "event")
            set_field(doc, "event.category", "file")
            set_field(doc, "event.type", "info")
            set_field(doc, "event.dataset", "bodyfile")
            set_field(doc, "log.file.path", str(item))
            set_field(doc, "log.offset", offset)
            yield ["bodyfile", path, inode, deleted], doc
    if no_time:
        report.warn(f"{item}: {no_time} entries have no time at all; they are loaded without @timestamp")


BODYFILE = LogSource("bodyfile", "bodyfile", "bodyfile", collect, parse, str, missing)
BODYFILE.add_arguments = add_arguments


def main(argv=None):
    return run_sources([BODYFILE], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

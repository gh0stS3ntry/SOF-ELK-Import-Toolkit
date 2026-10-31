#!/usr/bin/env python3
"""Load Linux login records (wtmp, btmp, wtmpdb) into SOF-ELK as wtmp-<hostname>.

Inputs, found under the evidence root:
  /var/log/wtmp, wtmp.1, wtmp-20261025.gz ...   logins, logouts, boots, shutdowns, runlevels
  /var/log/btmp, btmp.1 ...                      failed logins (lastb)
  /var/lib/wtmpdb/wtmp*.db                       wtmpdb, the SQLite replacement for wtmp
                                                 (Debian 13+, openSUSE Tumbleweed, SLE 16)
  --wtmp-file PATH                               any other file in utmp format (repeatable)

wtmp and btmp hold glibc utmp records (384 bytes each) and are read with struct; wtmpdb is
read with the standard sqlite3 module. utmp (/var/run/utmp) is not loaded: it only holds the
sessions open at collection time, which wtmp has too. lastlog and faillog are left out
because they are unreliable.

Every record becomes one document with event.action:
  login, logout, failed-login (every btmp record), boot, shutdown, runlevel-change,
  clock-changed, login-prompt (getty waiting on a terminal), init-process, accounting,
  process-ended (a DEAD_PROCESS record that ends no login: a getty exiting, or a logout whose
  login is in a wtmp file that was not collected)
A login is paired with its logout like `last` does: the next logout on the same terminal, or
else the next boot or shutdown (wtmp.logout_type logout / shutdown / crash). Both documents
then carry event.start, event.end and event.duration (nanoseconds), and the logout document
gets the user name and source address of its login. Rotated copies are read oldest first,
so sessions that span a rotation are still paired.

Times are epoch-based (UTC); no time zone is needed. The _id is derived from the record
bytes, so the same record in a later collection (after rotation renamed the file)
overwrites instead of duplicating.

Example:
  python3 Linux/wtmp2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
import datetime as dt
import hashlib
import ipaddress
import os
import re
import shutil
import sqlite3
import struct
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import LogSource, iso_utc, run_sources, set_field  # noqa: E402

RECORD_SIZE = 384
# struct utmp (glibc, 64-bit and 32-bit x86/ARM alike): type, pid, line, id, user, host,
# exit status, session, tv_sec, tv_usec, addr_v6, unused
UTMP_FMT = "h2xi32s4s32s256shhii i16s20s".replace(" ", "")
TYPE_NAMES = {0: "EMPTY", 1: "RUN_LVL", 2: "BOOT_TIME", 3: "NEW_TIME", 4: "OLD_TIME", 5: "INIT_PROCESS",
              6: "LOGIN_PROCESS", 7: "USER_PROCESS", 8: "DEAD_PROCESS", 9: "ACCOUNTING"}
FILE_RE = re.compile(r"^(?P<family>wtmp|btmp)(?:\.(?P<num>\d+)|-(?P<date>\d{8}))?(?:\.(?:gz|bz2|xz))?$")
WTMPDB_RE = re.compile(r"^wtmp.*\.db$")
WTMPDB_TYPES = {1: "BOOT_TIME", 2: "RUN_LVL", 3: "USER_PROCESS"}
EPOCH = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)


# --------------------------------------------------------------------------- input discovery

def rotation_key(rel):
    m = FILE_RE.match(Path(rel).name)
    if not m:
        return (0, "")
    if m.group("num"):
        return (-int(m.group("num")), "")
    if m.group("date"):
        return (-10**6, m.group("date"))
    return (1, "")


def collect(ev, profile, args):
    """Work items: ("utmp", family, [files oldest first]) or ("wtmpdb", file)."""
    families = {"wtmp": [], "btmp": []}
    folder = ev.root_path("var/log")
    if ev.is_dir(folder):
        files, _ = ev.listdir(folder)
        for name in files:
            m = FILE_RE.match(name)
            if m and ev.size(f"{folder}/{name}") > 0:
                families[m.group("family")].append(f"{folder}/{name}")
    for extra in args.wtmp_file or []:
        rel = ev.root_path(extra.lstrip("/"))
        if ev.exists(rel):
            family = "btmp" if "btmp" in Path(rel).name else "wtmp"
            families[family].append(rel)
        else:
            print(f"  --wtmp-file {extra}: not found in the evidence ({rel})")
    items = [("utmp", fam, sorted(set(files), key=rotation_key)) for fam, files in families.items() if files]
    db_folder = ev.root_path("var/lib/wtmpdb")
    if ev.is_dir(db_folder):
        files, _ = ev.listdir(db_folder)
        # Rotated databases (wtmp_YYYYMM.db) first, the live wtmp.db last.
        for name in sorted((n for n in files if WTMPDB_RE.match(n)), key=lambda n: (n == "wtmp.db", n)):
            items.append(("wtmpdb", "wtmpdb", [f"{db_folder}/{name}"]))
    return items


def item_label(item):
    return f"{item[1]}: {', '.join(item[2])}"


def add_arguments(ap):
    ap.add_argument("--wtmp-file", action="append",
                    help="Extra file in utmp format, as a path on the evidence host (e.g."
                         " /var/log/wtmp.bak); a name containing 'btmp' is read as failed logins;"
                         " repeatable")


# --------------------------------------------------------------------------- helpers

def text(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


def to_iso(sec, usec=0):
    try:
        return iso_utc(EPOCH + dt.timedelta(seconds=sec, microseconds=usec))
    except OverflowError:
        return None


def addr_ip(raw):
    """ut_addr_v6 -> IP string, or None when empty."""
    words = struct.unpack("<4I", raw)
    if not any(words):
        return None
    if not any(words[1:]):
        return str(ipaddress.IPv4Address(raw[:4]))
    return str(ipaddress.IPv6Address(raw))


def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def remote_fields(doc, host, ip=None):
    """source.* from a remote host string; X displays (':0') stay in wtmp.host only."""
    set_field(doc, "wtmp.host", host)
    if host and not host.startswith(":"):
        set_field(doc, "source.address", host)
        if not ip and is_ip(host.split("%", 1)[0]):
            ip = host.split("%", 1)[0]
    set_field(doc, "source.ip", ip)


def detect_endian(data):
    """'<' or '>' from the first records' type and microsecond fields."""
    for endian in ("<", ">"):
        ok = True
        for off in range(0, min(len(data), RECORD_SIZE * 8) - RECORD_SIZE + 1, RECORD_SIZE):
            rec = struct.unpack_from(endian + UTMP_FMT, data, off)
            if not (0 <= rec[0] <= 9 and 0 <= rec[10] < 1_000_000):
                ok = False
                break
        if ok:
            return endian
    return "<"


ACTIONS = {
    "BOOT_TIME": ("boot", ["host"], ["start"]),
    "RUN_LVL": ("runlevel-change", ["host"], ["change"]),
    "NEW_TIME": ("clock-changed", ["host"], ["change"]),
    "OLD_TIME": ("clock-changed", ["host"], ["change"]),
    "INIT_PROCESS": ("init-process", ["process"], ["start"]),
    "LOGIN_PROCESS": ("login-prompt", ["process"], ["start"]),
    "USER_PROCESS": ("login", ["authentication", "session"], ["start"]),
    "DEAD_PROCESS": ("logout", ["session"], ["end"]),
    "ACCOUNTING": ("accounting", ["host"], ["info"]),
}


def base_doc(family, type_name, stamp, rel, offset):
    doc = {}
    set_field(doc, "@timestamp", stamp)
    action, category, etype = ACTIONS.get(type_name, ("unknown", ["host"], ["info"]))
    if family == "btmp":
        action, category, etype = "failed-login", ["authentication"], ["start"]
        set_field(doc, "event.outcome", "failure")
    elif action == "login":
        set_field(doc, "event.outcome", "success")
    set_field(doc, "event.kind", "event")
    set_field(doc, "event.category", category)
    set_field(doc, "event.type", etype)
    set_field(doc, "event.action", action)
    set_field(doc, "event.dataset", "wtmp")
    set_field(doc, "wtmp.source", family)
    set_field(doc, "wtmp.type_name", type_name)
    set_field(doc, "log.file.path", rel)
    set_field(doc, "log.offset", offset)
    return doc


def duration_ns(start, end):
    a = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = dt.datetime.fromisoformat(end.replace("Z", "+00:00"))
    delta = b - a
    return (delta.days * 86400 + delta.seconds) * 10**9 + delta.microseconds * 1000


def close_session(login, end_doc, logout_type):
    """Pair a login document with what ended it."""
    start, end = login["@timestamp"], end_doc["@timestamp"]
    if not start or not end:
        return
    set_field(login, "event.start", start)
    set_field(login, "event.end", end)
    set_field(login, "event.duration", max(duration_ns(start, end), 0))
    set_field(login, "wtmp.logout_type", logout_type)
    if logout_type == "logout":
        set_field(end_doc, "event.start", start)
        set_field(end_doc, "event.end", end)
        set_field(end_doc, "event.duration", max(duration_ns(start, end), 0))
        set_field(end_doc, "wtmp.logout_type", "logout")
        for field in ("user", "source"):
            if field in login and field not in end_doc:
                end_doc[field] = dict(login[field])


# --------------------------------------------------------------------------- utmp files

def parse_utmp(ev, family, files, report):
    docs = []
    seen = {}
    open_sessions = {}  # line -> login doc
    last_shutdown = False
    for rel in files:
        with ev.open_binary(rel) as fh:
            data = fh.read()
        if len(data) % RECORD_SIZE:
            report.warn(f"{rel}: size {len(data)} is not a multiple of {RECORD_SIZE} bytes (not glibc utmp,"
                        f" or truncated); the trailing {len(data) % RECORD_SIZE} bytes are ignored")
        endian = detect_endian(data)
        for index, off in enumerate(range(0, len(data) - RECORD_SIZE + 1, RECORD_SIZE)):
            raw = data[off:off + RECORD_SIZE]
            (utype, pid, line, ut_id, user, host, e_term, e_exit, session, sec, usec, addr,
             _unused) = struct.unpack(endian + UTMP_FMT, raw)
            if utype == 0 and not any(raw[4:]):
                continue
            type_name = TYPE_NAMES.get(utype)
            if type_name is None or type_name == "EMPTY":
                docs.append((None, "record with an unknown type"))
                continue
            stamp = to_iso(sec, usec) if sec > 0 else None
            if stamp is None:
                docs.append((None, "record without a valid time"))
                continue
            doc = base_doc(family, type_name, stamp, rel, index)
            line_s, user_s, host_s = text(line), text(user), text(host)
            set_field(doc, "wtmp.type", utype)
            set_field(doc, "wtmp.line", line_s)
            set_field(doc, "wtmp.id", text(ut_id))
            set_field(doc, "wtmp.user", user_s)
            set_field(doc, "wtmp.session", session or None)
            if e_term or e_exit:
                set_field(doc, "wtmp.exit.termination", e_term)
                set_field(doc, "wtmp.exit.status", e_exit)
            if type_name == "RUN_LVL":
                if user_s == "shutdown":
                    doc["event"]["action"] = "shutdown"
                    doc["event"]["type"] = ["end"]
                level, prev = pid & 0xFF, (pid >> 8) & 0xFF
                set_field(doc, "wtmp.runlevel", chr(level) if 32 < level < 127 else None)
                set_field(doc, "wtmp.previous_runlevel", chr(prev) if 32 < prev < 127 else None)
                set_field(doc, "wtmp.host", host_s)
            elif type_name == "BOOT_TIME":
                set_field(doc, "wtmp.host", host_s)  # kernel release
            else:
                set_field(doc, "process.pid", pid or None)
                if type_name in ("USER_PROCESS", "DEAD_PROCESS") or family == "btmp":
                    set_field(doc, "user.name", user_s or None)
                remote_fields(doc, host_s, addr_ip(addr))

            if family == "wtmp":
                action = doc["event"]["action"]
                if action == "login" and line_s:
                    open_sessions[line_s] = doc
                    last_shutdown = False
                elif action == "logout" and line_s in open_sessions:
                    close_session(open_sessions.pop(line_s), doc, "logout")
                elif action == "shutdown":
                    for login in open_sessions.values():
                        close_session(login, doc, "shutdown")
                    open_sessions.clear()
                    last_shutdown = True
                elif action == "boot":
                    for login in open_sessions.values():
                        close_session(login, doc, "shutdown" if last_shutdown else "crash")
                    open_sessions.clear()
                    last_shutdown = False
            key = hashlib.sha1(raw).hexdigest()
            n = seen.get(key, 0)
            seen[key] = n + 1
            docs.append((["wtmp", family, key, n], doc))
    # A DEAD_PROCESS that ends no login is a getty or other process on that terminal ending
    # (or a logout whose login was rotated away): not counted as a logout.
    for parts, doc in docs:
        if parts and doc["event"]["action"] == "logout" and "start" not in doc["event"]:
            doc["event"]["action"] = "process-ended"
            doc["event"]["category"] = ["process"]
    if open_sessions:
        report.warn(f"{len(open_sessions)} {family} login(s) have no logout: still logged in at collection"
                    " time, or the logout record is missing (no event.end)")
    return docs


# --------------------------------------------------------------------------- wtmpdb

def copy_database(ev, rel, folder):
    """Copy a wtmpdb database (and its -wal/-journal) to folder; sqlite3 needs a real file."""
    target = os.path.join(folder, Path(rel).name)
    for suffix in ("", "-wal", "-journal"):
        member = rel + suffix
        if ev.exists(member):
            with ev.open_binary(member, decompress=False) as src, open(target + suffix, "wb") as dst:
                shutil.copyfileobj(src, dst)
    return target


def parse_wtmpdb(ev, rel, report):
    docs = []
    with tempfile.TemporaryDirectory(prefix="wtmpdb-") as tmp:
        path = copy_database(ev, rel, tmp)
        try:
            con = sqlite3.connect(path)
            rows = con.execute("SELECT ID, Type, User, Login, Logout, TTY, RemoteHost, Service FROM wtmp"
                               " ORDER BY Login").fetchall()
            con.close()
        except sqlite3.DatabaseError as exc:
            report.warn(f"{rel}: not a readable wtmpdb database ({exc})")
            return docs
    for row_id, rtype, user, login, logout, tty, rhost, service in rows:
        type_name = WTMPDB_TYPES.get(rtype)
        if type_name is None or not isinstance(login, int) or login <= 0:
            docs.append((None, "wtmpdb row with an unknown type or no login time"))
            continue
        start = to_iso(login // 10**6, login % 10**6)
        doc = base_doc("wtmpdb", type_name, start, rel, row_id)
        set_field(doc, "wtmp.type", rtype)
        set_field(doc, "wtmp.record_id", row_id)
        set_field(doc, "wtmp.user", user)
        set_field(doc, "wtmp.line", tty)
        set_field(doc, "wtmp.service", service)
        if type_name == "USER_PROCESS":
            set_field(doc, "user.name", user)
            remote_fields(doc, rhost)
        else:
            set_field(doc, "wtmp.host", rhost)  # kernel release on boot rows
        docs.append((["wtmpdb", row_id, login, "start"], doc))
        if isinstance(logout, int) and logout > 0:
            end = to_iso(logout // 10**6, logout % 10**6)
            end_type = "BOOT_TIME" if type_name == "BOOT_TIME" else "DEAD_PROCESS"
            end_doc = base_doc("wtmpdb", end_type, end, rel, row_id)
            if type_name == "BOOT_TIME":
                end_doc["event"]["action"] = "shutdown"
                end_doc["event"]["type"] = ["end"]
            set_field(end_doc, "wtmp.type", rtype)
            set_field(end_doc, "wtmp.record_id", row_id)
            set_field(end_doc, "wtmp.user", user)
            set_field(end_doc, "wtmp.line", tty)
            set_field(end_doc, "wtmp.service", service)
            for d in (doc, end_doc):
                set_field(d, "event.start", start)
                set_field(d, "event.end", end)
                set_field(d, "event.duration", max(duration_ns(start, end), 0))
            if type_name == "USER_PROCESS":
                set_field(doc, "wtmp.logout_type", "logout")
                set_field(end_doc, "wtmp.logout_type", "logout")
                for field in ("user", "source"):
                    if field in doc:
                        end_doc[field] = dict(doc[field])
            else:
                set_field(end_doc, "wtmp.host", rhost)
            docs.append((["wtmpdb", row_id, login, "end"], end_doc))
    return docs


# --------------------------------------------------------------------------- entry point

def parse(ev, profile, args, item, report):
    kind, family, files = item
    docs = parse_wtmpdb(ev, files[0], report) if kind == "wtmpdb" else parse_utmp(ev, family, files, report)
    yield from docs


WTMP = LogSource("wtmp", "wtmp", "wtmp", collect, parse, item_label)
WTMP.add_arguments = add_arguments


def main(argv=None):
    return run_sources([WTMP], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

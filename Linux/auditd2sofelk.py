#!/usr/bin/env python3
"""Load Linux audit logs (auditd) into SOF-ELK as auditd-<hostname>.

Inputs: /var/log/audit/audit.log and its rotations (audit.log.1 ... audit.log.N, and
logrotate's .gz/.xz/dated copies) under the evidence root, plus --audit-log FILE
(repeatable; inside the evidence or anywhere on disk). auditd is on by default on the RHEL
family and common on SUSE; Debian, Ubuntu and Kali only have it when the auditd package was
installed.

One document per audit EVENT. The kernel writes an event as several records (SYSCALL, EXECVE,
CWD, PATH, PROCTITLE, ... then EOE) that share one id, msg=audit(<epoch>:<serial>); they are
grouped by that id, as Auditbeat does, so a single document holds who ran what, where and on
which file. message keeps the raw records, one per line.

Field names follow Auditbeat's auditd module and ECS:
  auditd.sequence (serial), auditd.log.record_type (first record), auditd.record_types (all),
  auditd.result (success/fail), auditd.key (audit rule key), auditd.session (ses),
  auditd.node, auditd.data.* (syscall name, arch, exit, tty, op, terminal ...),
  auditd.paths.* (one entry per PATH record)
  process.pid / parent.pid / name (comm) / executable (exe) / working_directory (CWD),
  process.command_line and process.args (EXECVE arguments, hex-decoded; else PROCTITLE, or
  the sudo command of a USER_CMD record), process.title (PROCTITLE)
  user.id (uid), user.audit.id (auid), user.effective.id (euid), user.group.id (gid),
  user.effective.group.id (egid), with .name from the log's ENRICHED part (log_format =
  ENRICHED) or else from the collected /etc/passwd and /etc/group
  file.path / inode / mode / uid / gid (the PATH record of the object acted on)
  source.ip / source.address (addr= / hostname= of user-space login records),
  destination.ip / port (connect() socket address)
Authentication and session records (USER_LOGIN, USER_AUTH, USER_START, CRED_ACQ, ...) put the
account logging in (acct=) in user.name and the uid of the process that wrote the record
(sshd, login, sudo: usually root) in process.user.id, as the syslog importers do for sshd.
Account management records (ADD_USER, DEL_USER, ADD_GROUP, USER_CHAUTHTOK, ...) put the account
changed in user.target.name / user.target.id and the actor in user.*.

Audit times are epoch seconds (UTC): no time zone is needed. The _id is derived from the host,
the node and the event id, so rotated logs collected again do not duplicate.

Example:
  python3 Linux/auditd2sofelk.py /mnt/rocky9-image --hostname db01 --case IR-42 --dry-run
"""
import binascii
import datetime as dt
import ipaddress
import re
import struct
import sys
from collections import OrderedDict
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import (EvidenceOrDiskFile, LogSource, iso_utc, load_accounts,  # noqa: E402
                                  run_sources, set_field)

FILE_RE = re.compile(r"^audit\.log(?:\.(?P<num>\d+)|-(?P<date>\d{8}))?(?:\.(?:gz|bz2|xz))?$")
RECORD_RE = re.compile(r"^(?:node=(?P<node>\S+) )?type=(?P<type>\S+) msg=audit\((?P<sec>\d+)\.(?P<ms>\d+):"
                       r"(?P<serial>\d+)\):\s?(?P<body>.*)$")
KV_RE = re.compile(r"([A-Za-z_][\w\-\[\]]*)=(\"[^\"]*\"|'[^']*'|\{[^}]*\}|\S*)")
HEX_RE = re.compile(r"^(?:[0-9A-F]{2})+$")
# Fields whose unquoted value is hex-encoded by the kernel / libaudit when it holds spaces or
# special characters.
ENCODED = {"name", "cwd", "comm", "exe", "proctitle", "key", "acct", "cmd", "data", "path", "old-chardev",
           "new-chardev", "watch", "dir", "vm", "old_vm", "new_vm", "cgroup", "root_dir", "new-disk",
           "old-disk", "grp", "new_group"}
ARCHES = {"c000003e": "x86_64", "40000003": "i386", "c00000b7": "aarch64", "40000028": "arm",
          "c0000015": "ppc64le", "80000016": "s390x", "c00000f3": "riscv64"}
# x86_64 syscalls that matter in an investigation; other numbers stay numeric.
SYSCALLS_X86_64 = {
    0: "read", 1: "write", 2: "open", 4: "stat", 9: "mmap", 10: "mprotect", 21: "access", 41: "socket",
    42: "connect", 43: "accept", 44: "sendto", 49: "bind", 50: "listen", 56: "clone", 57: "fork",
    58: "vfork", 59: "execve", 62: "kill", 76: "truncate", 77: "ftruncate", 82: "rename", 83: "mkdir",
    84: "rmdir", 85: "creat", 86: "link", 87: "unlink", 88: "symlink", 90: "chmod", 91: "fchmod",
    92: "chown", 93: "fchown", 94: "lchown", 101: "ptrace", 105: "setuid", 106: "setgid",
    113: "setreuid", 114: "setregid", 117: "setresuid", 119: "setresgid", 157: "prctl", 161: "chroot",
    165: "mount", 166: "umount2", 169: "reboot", 170: "sethostname", 175: "init_module",
    176: "delete_module", 188: "setxattr", 189: "lsetxattr", 190: "fsetxattr", 197: "removexattr",
    257: "openat", 258: "mkdirat", 260: "fchownat", 263: "unlinkat", 264: "renameat", 265: "linkat",
    266: "symlinkat", 268: "fchmodat", 288: "accept4", 313: "finit_module", 316: "renameat2",
    319: "memfd_create", 322: "execveat", 437: "openat2"}
SYSCALLS_BY_ARCH = {"x86_64": SYSCALLS_X86_64, "i386": {11: "execve", 5: "open", 102: "socketcall"},
                    "aarch64": {221: "execve", 281: "execveat", 56: "openat", 203: "connect", 200: "bind",
                                273: "finit_module", 105: "init_module", 35: "unlinkat", 38: "renameat"}}
UNSET_IDS = {"4294967295", "-1", "unset"}
AUTH_TYPES = {"USER_AUTH", "USER_ACCT", "USER_LOGIN", "USER_LOGOUT", "USER_START", "USER_END", "USER_ERR",
              "CRED_ACQ", "CRED_DISP", "CRED_REFR", "LOGIN", "USER_ROLE_CHANGE", "ANOM_LOGIN_FAILURES",
              "ANOM_LOGIN_LOCATION", "ANOM_LOGIN_SESSIONS", "ANOM_LOGIN_TIME", "ANOM_LOGIN_ACCT"}
ACCOUNT_TYPES = {"ADD_USER", "DEL_USER", "ADD_GROUP", "DEL_GROUP", "USER_CHAUTHTOK", "USER_MGMT",
                 "GRP_MGMT", "GRP_CHAUTHTOK", "ACCT_LOCK", "ACCT_UNLOCK", "ROLE_ASSIGN", "ROLE_REMOVE"}
# record type -> (event.action, event.category, event.type)
ACTIONS = {
    "USER_LOGIN": ("logged-in", ["authentication", "session"], ["start"]),
    "USER_LOGOUT": ("logged-out", ["authentication", "session"], ["end"]),
    "LOGIN": ("changed-login-id-to", ["authentication"], ["info"]),
    "USER_AUTH": ("authenticated", ["authentication"], ["info"]),
    "USER_ACCT": ("was-authorized", ["authentication"], ["info"]),
    "USER_START": ("started-session", ["session"], ["start"]),
    "USER_END": ("ended-session", ["session"], ["end"]),
    "USER_ERR": ("error", ["authentication"], ["info"]),
    "CRED_ACQ": ("acquired-credentials", ["authentication"], ["info"]),
    "CRED_DISP": ("disposed-credentials", ["authentication"], ["info"]),
    "CRED_REFR": ("refreshed-credentials", ["authentication"], ["info"]),
    "USER_CMD": ("ran-command", ["process"], ["start"]),
    "ADD_USER": ("added-user-account", ["iam"], ["user", "creation"]),
    "DEL_USER": ("deleted-user-account", ["iam"], ["user", "deletion"]),
    "ADD_GROUP": ("added-group-account-to", ["iam"], ["group", "creation"]),
    "DEL_GROUP": ("deleted-group-account-from", ["iam"], ["group", "deletion"]),
    "USER_MGMT": ("modified-user-account", ["iam"], ["user", "change"]),
    "GRP_MGMT": ("modified-group-account", ["iam"], ["group", "change"]),
    "USER_CHAUTHTOK": ("changed-password", ["iam"], ["user", "change"]),
    "GRP_CHAUTHTOK": ("changed-group-password", ["iam"], ["group", "change"]),
    "ACCT_LOCK": ("locked-account", ["iam"], ["user", "change"]),
    "ACCT_UNLOCK": ("unlocked-account", ["iam"], ["user", "change"]),
    "SERVICE_START": ("started-service", ["process"], ["start"]),
    "SERVICE_STOP": ("stopped-service", ["process"], ["end"]),
    "DAEMON_START": ("started-audit", ["process"], ["start"]),
    "DAEMON_END": ("stopped-audit", ["process"], ["end"]),
    "DAEMON_ABORT": ("aborted-audit", ["process"], ["end"]),
    "CONFIG_CHANGE": ("changed-audit-configuration", ["configuration"], ["change"]),
    "SYSTEM_BOOT": ("booted-system", ["host"], ["start"]),
    "SYSTEM_SHUTDOWN": ("shutdown-system", ["host"], ["end"]),
    "SYSTEM_RUNLEVEL": ("changed-to-runlevel", ["host"], ["change"]),
    "KERN_MODULE": ("loaded-kernel-module", ["driver"], ["start"]),
    "AVC": ("violated-selinux-policy", ["configuration"], ["denied"]),
    "ANOM_ABEND": ("crashed-program", ["process"], ["end"]),
    "ANOM_PROMISCUOUS": ("changed-promiscuous-mode-on-device", ["network"], ["change"]),
    "TTY": ("typed", ["process"], ["info"]),
    "USER_TTY": ("typed", ["process"], ["info"]),
}
EXEC_SYSCALLS = {"execve", "execveat"}
FLUSH_AFTER = 1000  # lines: an event not finished by EOE is written after this many more lines


# --------------------------------------------------------------------------- input discovery

def rotation_key(item):
    m = FILE_RE.match(Path(str(item)).name)
    if not m:
        return (2, str(item))
    if m.group("num"):
        return (0, -int(m.group("num")))
    if m.group("date"):
        return (0, -10**9 + int(m.group("date")))
    return (1, 0)


def collect(ev, profile, args):
    items = []
    folder = ev.root_path("var/log/audit")
    if ev.is_dir(folder):
        files, _ = ev.listdir(folder)
        for name in files:
            if FILE_RE.match(name) and ev.size(f"{folder}/{name}") > 0:
                items.append(EvidenceOrDiskFile.member(ev, f"{folder}/{name}"))
    for extra in args.audit_log or []:
        try:
            items.append(EvidenceOrDiskFile(ev, extra))
        except FileNotFoundError:
            print(f"  --audit-log {extra}: not found in the evidence or on disk")
    return sorted(items, key=rotation_key)


def missing(ev, profile, args):
    return 0, "No audit log found (/var/log/audit/audit.log*): auditd was not installed or not collected."


def add_arguments(ap):
    ap.add_argument("--audit-log", action="append",
                    help="Extra audit log, inside the evidence (/var/log/audit/old.log) or on disk;"
                         " repeatable")


# --------------------------------------------------------------------------- record parsing

def decode_value(key, value, execve=False):
    """Strip quotes; decode the kernel's hex encoding of unquoted values. a0, a1 ... are
    encoded strings only in EXECVE records (in SYSCALL they are hex numbers)."""
    if not value:
        return None
    if value[0] in "\"'" and value[-1:] == value[0]:
        return value[1:-1]
    if value == "(null)" or value == "?":
        return None
    base = re.sub(r"\[\d+\]$", "", key)
    if (base in ENCODED or (execve and re.fullmatch(r"a\d+(\[\d+\])?", key))) and HEX_RE.match(value):
        try:
            return binascii.unhexlify(value).decode("utf-8", "replace")
        except (binascii.Error, ValueError):
            return value
    return value


def parse_body(body, rtype=""):
    """(raw fields, enriched fields, nested msg fields) of one record body."""
    raw_part, _, enriched_part = body.partition("\x1d")
    fields, nested = {}, {}
    for key, value in KV_RE.findall(raw_part):
        if key == "msg" and value.startswith("'"):
            for k2, v2 in KV_RE.findall(value[1:-1]):
                nested[k2] = decode_value(k2, v2)
            continue
        fields.setdefault(key, decode_value(key, value, rtype == "EXECVE"))
    enriched = {k: decode_value("", v) for k, v in KV_RE.findall(enriched_part)}
    return fields, enriched, nested


def decode_sockaddr(hexstr):
    """saddr= hex -> {"family", "addr", "port", "path"}."""
    try:
        raw = binascii.unhexlify(hexstr)
    except (binascii.Error, ValueError):
        return {}
    if len(raw) < 2:
        return {}
    family = struct.unpack("<H", raw[:2])[0]
    if family == 2 and len(raw) >= 8:
        return {"family": "ipv4", "port": struct.unpack(">H", raw[2:4])[0],
                "addr": str(ipaddress.IPv4Address(raw[4:8]))}
    if family == 10 and len(raw) >= 24:
        return {"family": "ipv6", "port": struct.unpack(">H", raw[2:4])[0],
                "addr": str(ipaddress.IPv6Address(raw[8:24]))}
    if family == 1:
        path = raw[2:].split(b"\0", 1)[0] if raw[2:3] != b"\0" else b"@" + raw[3:].split(b"\0", 1)[0]
        return {"family": "unix", "path": path.decode("utf-8", "replace")}
    if family == 16:
        return {"family": "netlink"}
    return {"family": str(family)}


def valid_ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        return None


def id_value(value):
    return None if value is None or value in UNSET_IDS else value


# --------------------------------------------------------------------------- event -> document

def build_doc(event, item, accounts):
    users, groups = accounts
    records = event["records"]
    types = [r["type"] for r in records if r["type"] != "EOE"]
    if not types:
        types = ["EOE"]
    primary = types[0]
    by_type = {}
    for r in records:
        by_type.setdefault(r["type"], []).append(r)
    main = by_type.get(primary, records)[0]
    f, enr, nested = main["fields"], main["enriched"], main["nested"]
    doc = {}
    doc["@timestamp"] = iso_utc(dt.datetime.fromtimestamp(event["sec"], dt.timezone.utc)
                                + dt.timedelta(milliseconds=event["ms"]))
    set_field(doc, "message", "\n".join(r["line"] for r in records))
    set_field(doc, "auditd.sequence", event["serial"])
    set_field(doc, "auditd.node", event["node"])
    set_field(doc, "auditd.log.record_type", primary)
    set_field(doc, "auditd.record_types", sorted(set(types)))
    set_field(doc, "auditd.session", id_value(f.get("ses")))

    # Keys: comma- or \x01-separated, sometimes hex encoded as one value.
    key = f.get("key")
    if key:
        set_field(doc, "auditd.key", [k for k in re.split(r"[\x01,]", key) if k])

    arch = ARCHES.get((f.get("arch") or "").lower(), f.get("arch"))
    syscall = enr.get("SYSCALL")
    if f.get("syscall") is not None and not syscall:
        try:
            syscall = SYSCALLS_BY_ARCH.get(arch, {}).get(int(f["syscall"]), f["syscall"])
        except ValueError:
            syscall = f["syscall"]
    set_field(doc, "auditd.data.syscall", syscall)
    set_field(doc, "auditd.data.arch", enr.get("ARCH") or arch)
    set_field(doc, "auditd.data.exit", f.get("exit"))
    set_field(doc, "auditd.data.tty", f.get("tty") if f.get("tty") not in (None, "(none)") else None)
    for k in ("op", "terminal", "res", "a0", "a1", "a2", "a3", "items", "ppid_comm"):
        source = nested if k in ("op", "terminal", "res") else f
        set_field(doc, f"auditd.data.{k}", source.get(k))
    set_field(doc, "auditd.data.unit", nested.get("unit"))

    # Result
    result = None
    if f.get("success") in ("yes", "no"):
        result = "success" if f["success"] == "yes" else "fail"
    elif nested.get("res") is not None:
        result = "success" if nested["res"] in ("success", "1", "yes") else "fail"
    elif f.get("res") is not None:
        result = "success" if f["res"] in ("success", "1", "yes") else "fail"
    set_field(doc, "auditd.result", result)

    # Process
    set_field(doc, "process.pid", _int(f.get("pid")))
    set_field(doc, "process.parent.pid", _int(f.get("ppid")))
    set_field(doc, "process.name", f.get("comm") or nested.get("comm"))
    set_field(doc, "process.executable", f.get("exe") or nested.get("exe"))
    cwd = by_type.get("CWD", [{}])[0].get("fields", {}).get("cwd") or nested.get("cwd")
    set_field(doc, "process.working_directory", cwd)
    args = []
    for rec in by_type.get("EXECVE", []):
        args.extend(execve_args(rec["fields"]))
    title = None
    for rec in by_type.get("PROCTITLE", []):
        title = (rec["fields"].get("proctitle") or "").replace("\x00", " ").strip() or None
    set_field(doc, "process.title", title)
    if args:
        set_field(doc, "process.args", args)
        set_field(doc, "process.command_line", " ".join(args))
    elif nested.get("cmd"):
        set_field(doc, "process.command_line", nested["cmd"])
    elif title and syscall in EXEC_SYSCALLS:
        set_field(doc, "process.command_line", title)

    # Users
    actor = "process.user" if primary in AUTH_TYPES else "user"
    for field, raw_key, enr_key, table in (
            (f"{actor}.id", "uid", "UID", users), ("user.audit.id", "auid", "AUID", users),
            ("user.effective.id", "euid", "EUID", users), ("user.group.id", "gid", "GID", groups),
            ("user.effective.group.id", "egid", "EGID", groups)):
        value = id_value(f.get(raw_key))
        if value is None:
            continue
        set_field(doc, field, value)
        name = enr.get(enr_key) or table.get(value)
        if name and name not in ("unset", "?"):
            set_field(doc, field[:-3] + ".name", name)
    acct = nested.get("acct")
    nested_id = id_value(nested.get("id"))
    if primary in AUTH_TYPES:
        set_field(doc, "user.name", acct)
        if acct is None and nested_id is not None:
            set_field(doc, "user.id", nested_id)
            set_field(doc, "user.name", users.get(nested_id))
    elif primary in ACCOUNT_TYPES:
        target = "group" if "GROUP" in primary or primary.startswith("GRP_") else "user.target"
        table = groups if target == "group" else users
        set_field(doc, f"{target}.name", acct or nested.get("grp") or table.get(nested_id))
        set_field(doc, f"{target}.id", nested_id)
    elif acct:
        set_field(doc, "user.target.name", acct)

    # Remote side of user-space records: hostname= is only the remote name when addr= is set
    # (for local commands such as useradd it is the host itself).
    addr = valid_ip(nested.get("addr"))
    hostname = nested.get("hostname")
    set_field(doc, "auditd.data.hostname", hostname)
    set_field(doc, "auditd.data.addr", nested.get("addr"))
    if addr:
        set_field(doc, "source.ip", addr)
        set_field(doc, "source.address", hostname if hostname and hostname != addr else addr)
    for rec in by_type.get("KERN_MODULE", []):
        set_field(doc, "auditd.data.name", rec["fields"].get("name"))

    # Files: PATH records, the object acted on first (not the PARENT directory entry).
    paths = []
    for rec in by_type.get("PATH", []):
        pf = rec["fields"]
        name = pf.get("name")
        if name and not name.startswith("/") and cwd:
            name = str(PurePosixPath(cwd) / name)
        entry = {k: v for k, v in {"name": name, "nametype": pf.get("nametype"), "inode": pf.get("inode"),
                                   "mode": pf.get("mode"), "ouid": pf.get("ouid"), "ogid": pf.get("ogid"),
                                   "item": pf.get("item")}.items() if v is not None}
        if entry:
            paths.append(entry)
    if paths:
        doc.setdefault("auditd", {})["paths"] = paths
        target = next((p for p in paths if p.get("nametype") not in ("PARENT",) and p.get("name")), None)
        target = target or next((p for p in paths if p.get("name")), None)
        if target:
            set_field(doc, "file.path", target.get("name"))
            set_field(doc, "file.inode", target.get("inode"))
            mode = target.get("mode")
            set_field(doc, "file.mode", mode[-4:] if mode and mode.isdigit() else None)
            set_field(doc, "file.uid", target.get("ouid"))
            set_field(doc, "file.gid", target.get("ogid"))
            set_field(doc, "file.owner", users.get(target.get("ouid")))
            set_field(doc, "file.group", groups.get(target.get("ogid")))
    elif nested.get("path"):
        set_field(doc, "file.path", nested.get("path"))

    # Sockets
    for rec in by_type.get("SOCKADDR", []):
        sock = decode_sockaddr(rec["fields"].get("saddr") or "")
        for k, v in sock.items():
            set_field(doc, f"auditd.data.socket.{k}", v)
        if sock.get("addr") and syscall in ("connect", "sendto"):
            set_field(doc, "destination.ip", sock["addr"])
            set_field(doc, "destination.port", sock.get("port"))
        elif sock.get("addr") and syscall in ("bind", "accept", "accept4", "listen"):
            set_field(doc, "source.ip", doc.get("source", {}).get("ip") or sock["addr"])
            set_field(doc, "source.port", sock.get("port"))
        break

    # Classification
    if syscall in EXEC_SYSCALLS or "EXECVE" in by_type:
        action, category, etype = "executed", ["process"], ["start"]
    elif primary == "SYSCALL":
        action, category, etype = (syscall or "syscall").lower(), ["process"], ["info"]
        if syscall in ("init_module", "finit_module"):
            action, category, etype = "loaded-kernel-module", ["driver"], ["start"]
        elif syscall == "delete_module":
            action, category, etype = "unloaded-kernel-module", ["driver"], ["end"]
        elif syscall in ("connect",):
            category, etype = ["network"], ["connection", "start"]
        elif paths:
            category = ["file"]
    else:
        action, category, etype = ACTIONS.get(primary, (primary.lower().replace("_", "-"), None, ["info"]))
    set_field(doc, "event.kind", "event")
    set_field(doc, "event.action", action)
    set_field(doc, "event.category", category)
    set_field(doc, "event.type", etype)
    if result:
        set_field(doc, "event.outcome", "success" if result == "success" else "failure")
    set_field(doc, "event.dataset", "auditd.log")
    set_field(doc, "log.file.path", str(item))
    set_field(doc, "log.offset", event["offset"])
    return doc


def execve_args(fields):
    """a0, a1 ... aN (and long arguments split as aN[0], aN[1] ...), in order."""
    try:
        argc = int(fields.get("argc", "0"))
    except ValueError:
        argc = 0
    out = []
    for i in range(argc):
        if f"a{i}" in fields:
            out.append(fields[f"a{i}"] or "")
            continue
        parts, j = [], 0
        while f"a{i}[{j}]" in fields:
            parts.append(fields[f"a{i}[{j}]"] or "")
            j += 1
        if not parts:
            break
        out.append("".join(parts))
    return out


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    if getattr(parse, "accounts_for", None) is not ev:
        parse.accounts = load_accounts(ev)
        parse.accounts_for = ev
    accounts = parse.accounts
    open_events = OrderedDict()

    def finish(key):
        event = open_events.pop(key)
        return ["auditd", event["node"] or "", f"{event['sec']}.{event['ms']:03d}:{event['serial']}"], \
            build_doc(event, item, accounts)

    with item.open_text() as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            m = RECORD_RE.match(line)
            if not m:
                yield None, "line that is not an audit record"
                continue
            key = (m.group("node"), m.group("sec"), m.group("ms"), m.group("serial"))
            event = open_events.get(key)
            if event is None:
                event = {"node": m.group("node"), "sec": int(m.group("sec")), "ms": int(m.group("ms")[:3]),
                         "serial": int(m.group("serial")), "offset": offset, "records": []}
                open_events[key] = event
            event["last"] = offset
            if m.group("type") != "EOE" or not event["records"]:
                fields, enriched, nested = parse_body(m.group("body"), m.group("type"))
                event["records"].append({"type": m.group("type"), "fields": fields, "enriched": enriched,
                                         "nested": nested, "line": line})
            if m.group("type") == "EOE":
                yield finish(key)
            # Events without EOE (single-record user-space events) are written once they are old.
            while open_events:
                first_key = next(iter(open_events))
                if offset - open_events[first_key]["last"] < FLUSH_AFTER:
                    break
                yield finish(first_key)
    while open_events:
        yield finish(next(iter(open_events)))


AUDITD = LogSource("auditd", "auditd", "auditd.log", collect, parse, str, missing)
AUDITD.add_arguments = add_arguments


def main(argv=None):
    return run_sources([AUDITD], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

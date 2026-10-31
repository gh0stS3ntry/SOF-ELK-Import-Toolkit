#!/usr/bin/env python3
"""Load the systemd journal of a Linux host into SOF-ELK as logstash-<hostname>.

Input is the JSON export of the journal, one entry per line, as written by
`journalctl -o json`. A UAC collection made with the custom artifact
journalctl-gh0stS3ntry.yaml already holds it at journal/journalctl_full_journal_logs.json;
it is read straight out of the UAC zip, without extracting anything. The binary journal
files themselves are never parsed.

If the collection has no export, nothing is loaded for the journal. The importer prints the
folder(s) holding the collected binary journal files and the journalctl command to export
them (on any Linux machine or in WSL), then exits with status 3 so the run is visibly
incomplete. Run it again once the export exists, or point --journal-json at it.

Documents go to logstash-<hostname>, next to text syslog files (Linux/syslog2sofelk.py),
with event.dataset "syslog.journal". Field names follow SOF-ELK's syslog parsing:
  __REALTIME_TIMESTAMP -> @timestamp          MESSAGE            -> message
  SYSLOG_IDENTIFIER    -> log.syslog.appname   (falls back to _COMM)
  SYSLOG_PID / _PID    -> log.syslog.procid    _HOSTNAME          -> log.syslog.hostname
  PRIORITY             -> log.syslog.severity.code/.name
  SYSLOG_FACILITY      -> log.syslog.facility.code/.name, log.syslog.priority
  _COMM -> process.name, _PID -> process.pid, _EXE -> process.executable,
  _CMDLINE -> process.command_line, _UID/_GID -> process.user.id/process.group.id
  _TRANSPORT, _SYSTEMD_UNIT, _BOOT_ID, __CURSOR, ... -> journald.*
  any other field -> journald.extra as "FIELD=value"
sshd, PAM, sudo, su, pkexec, account management, logind, cron and kernel/iptables messages are
parsed further (see Linux/common/sof_elk_linux_messages.py). The _id is derived from the
journal cursor, so loading the same export twice, or an overlapping later export, does not
create duplicates.

Example:
  python3 Linux/journal2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
import io
import json
import sys
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import LogSource, epoch_us_to_iso, open_compressed, run_sources, set_field  # noqa: E402
from sof_elk_linux_messages import enrich  # noqa: E402

EXPORT_NAME = "journalctl_full_journal_logs.json"
SEVERITY = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
FACILITY = ["kernel", "user-level", "mail", "daemon", "security/authorization", "syslogd", "line printer",
            "network news", "uucp", "clock", "security/authorization", "ftp", "ntp", "log audit",
            "log alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
            "local7"]

# journal field -> (document field, conversion)
FIELD_MAP = {
    "_HOSTNAME": ("log.syslog.hostname", "str"),
    "_COMM": ("process.name", "str"),
    "_PID": ("process.pid", "int"),
    "_EXE": ("process.executable", "str"),
    "_CMDLINE": ("process.command_line", "str"),
    "_UID": ("process.user.id", "str"),
    "_GID": ("process.group.id", "str"),
    "_TRANSPORT": ("journald.transport", "str"),
    "_SYSTEMD_UNIT": ("journald.unit", "str"),
    "_SYSTEMD_USER_UNIT": ("journald.user_unit", "str"),
    "_SYSTEMD_SLICE": ("journald.slice", "str"),
    "_SYSTEMD_CGROUP": ("journald.cgroup", "str"),
    "_SYSTEMD_INVOCATION_ID": ("journald.invocation_id", "str"),
    "_BOOT_ID": ("journald.boot_id", "str"),
    "_MACHINE_ID": ("journald.machine_id", "str"),
    "__CURSOR": ("journald.cursor", "str"),
    "__SEQNUM": ("journald.seqnum", "int"),
    "__SEQNUM_ID": ("journald.seqnum_id", "str"),
    "__MONOTONIC_TIMESTAMP": ("journald.monotonic_timestamp", "int"),
    "__REALTIME_TIMESTAMP": ("journald.realtime_timestamp", "int"),
    "_SOURCE_REALTIME_TIMESTAMP": ("journald.source_realtime", "time"),
    "_AUDIT_SESSION": ("journald.audit_session", "str"),
    "_AUDIT_LOGINUID": ("journald.audit_loginuid", "str"),
    "_RUNTIME_SCOPE": ("journald.runtime_scope", "str"),
    "MESSAGE_ID": ("journald.message_id", "str"),
    "INVOCATION_ID": ("journald.invocation_id", "str"),
    "_CAP_EFFECTIVE": ("journald.cap_effective", "str"),
    "_SELINUX_CONTEXT": ("journald.selinux_context", "str"),
    "_KERNEL_SUBSYSTEM": ("journald.kernel.subsystem", "str"),
    "_KERNEL_DEVICE": ("journald.kernel.device", "str"),
    "_UDEV_SYSNAME": ("journald.udev.sysname", "str"),
    "_UDEV_DEVNODE": ("journald.udev.devnode", "str"),
    "CODE_FILE": ("journald.code.file", "str"),
    "CODE_FUNC": ("journald.code.func", "str"),
    "CODE_LINE": ("journald.code.line", "int"),
    "ERRNO": ("journald.errno", "int"),
}
# Used for other fields, or of no value in the index.
CONSUMED = set(FIELD_MAP) | {"MESSAGE", "SYSLOG_IDENTIFIER", "SYSLOG_PID", "PRIORITY", "SYSLOG_FACILITY"}
DROPPED = {"_SOURCE_MONOTONIC_TIMESTAMP", "SYSLOG_TIMESTAMP", "_STREAM_ID", "SYSLOG_RAW"}
EXTRA_LIMIT = 1024


def value_text(value):
    """A journal JSON value as text. journalctl writes binary or non-UTF-8 values as an array of
    byte values, and a field that occurs more than once as an array of values."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if value and all(isinstance(x, int) for x in value):
            try:
                return bytes(value).decode("utf-8", "replace")
            except ValueError:
                return None
        parts = [value_text(x) for x in value]
        return "\n".join(p for p in parts if p is not None)
    return str(value)


def first_text(value):
    """First value of a repeated field (as text)."""
    if isinstance(value, list) and value and not all(isinstance(x, int) for x in value):
        return value_text(value[0])
    return value_text(value)


def to_int(text):
    try:
        return int(text)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- input discovery

def collect(ev, profile, args):
    """Export files: --journal-json, else journal/*.json(.gz) in the collection."""
    if args.journal_json:
        items = []
        for name in args.journal_json:
            path = Path(name).expanduser().resolve()
            if not path.is_file():
                sys.exit(f"ERROR: --journal-json file not found: {path}")
            items.append(("file", str(path)))
        return items
    found = []
    for folder in {ev.base_path("journal"), "journal"}:
        if not ev.is_dir(folder):
            continue
        files, _ = ev.listdir(folder)
        for name in files:
            if name.lower().endswith((".json", ".json.gz", ".json.xz", ".json.bz2", ".jsonl")):
                rel = f"{folder}/{name}".lstrip("/")
                if ev.size(rel) > 0:
                    found.append(("ev", rel))
    # The custom UAC artifact's file first, then any other export.
    found.sort(key=lambda item: (not item[1].endswith(EXPORT_NAME), item[1]))
    return found


def journal_dirs(ev):
    """Folders inside the evidence that hold binary journal files: [(rel, file count)]."""
    out = []
    for parent in ("var/log/journal", "run/log/journal"):
        rel_parent = ev.root_path(parent)
        if not ev.is_dir(rel_parent):
            continue
        files, dirs = ev.listdir(rel_parent)
        groups = [(rel_parent, files)] + [(f"{rel_parent}/{d}", ev.listdir(f"{rel_parent}/{d}")[0]) for d in dirs]
        for rel, names in groups:
            n = sum(1 for x in names if x.endswith((".journal", ".journal~")))
            if n:
                out.append((rel, n))
    return out


def missing(ev, profile, args):
    """No export: tell the user how to make one (exit 3), or that there is no journal (exit 0)."""
    dirs = journal_dirs(ev)
    if not dirs:
        return 0, ("No systemd journal in this collection: no journalctl JSON export (journal/*.json) and"
                   " no binary journal files under var/log/journal or run/log/journal. Hosts without"
                   " systemd (e.g. Alpine/OpenRC) log to text files only; see syslog2sofelk.py.")
    lines = ["ACTION NEEDED: the journal was NOT loaded. This collection has no journalctl JSON export",
             f"(journal/{EXPORT_NAME}), only the binary journal files:"]
    for rel, n in dirs:
        lines.append(f"  {rel}/  ({n} file(s))")
    lines.append("Export them on a Linux machine or in WSL (journalctl ships with systemd; Windows has no"
                 " journalctl), then run the journal import again:")

    def out_name(rel):
        return EXPORT_NAME if len(dirs) == 1 else f"journalctl_{PurePosixPath(rel).name}.json"

    if ev.is_zip:
        lines.append(f"  1. Extract {ev.path.name}, e.g. to /cases/{profile.hostname}, and"
                     f" mkdir -p /cases/{profile.hostname}/{ev.base_path('journal')}")
        step = 2
        for rel, _ in dirs:
            lines.append(f"  {step}. journalctl --directory='/cases/{profile.hostname}/{rel}' -o json"
                         f" > /cases/{profile.hostname}/{ev.base_path('journal/' + out_name(rel))}")
            step += 1
        lines.append(f"  {step}. python3 Linux/journal2sofelk.py /cases/{profile.hostname} --hostname {profile.hostname}"
                     f"   (or: python3 Linux/journal2sofelk.py {ev.path} --hostname {profile.hostname}"
                     f" --journal-json <exported .json>)")
    else:
        folder = ev.path / ev.base_path("journal")
        lines.append(f"  mkdir -p '{folder}'")
        for rel, _ in dirs:
            lines.append(f"  journalctl --directory='{ev.path / rel}' -o json > '{folder / out_name(rel)}'")
        lines.append(f"  python3 Linux/journal2sofelk.py '{ev.path}' --hostname {profile.hostname}")
    if len(dirs) > 1:
        lines.append("  (Several journal folders, one per machine-id or for /run: each goes to its own .json"
                     " file in journal/, and every .json there is loaded.)")
    return 3, "\n".join(lines)


def item_label(item):
    return item[1]


def add_arguments(ap):
    ap.add_argument("--journal-json", action="append",
                    help="journalctl -o json export to load instead of the collection's journal/*.json"
                         " (repeatable; .gz/.xz/.bz2 accepted)")


# --------------------------------------------------------------------------- parsing

def open_item(ev, item):
    kind, ref = item
    if kind == "ev":
        return ev.open_text(ref), ref
    return io.TextIOWrapper(open_compressed(ref), encoding="utf-8", errors="replace", newline=""), Path(ref).name


def build_doc(entry, rel, offset):
    doc = {}
    stamp = epoch_us_to_iso(first_text(entry.get("__REALTIME_TIMESTAMP")))
    if stamp is None:
        return None
    doc["@timestamp"] = stamp
    set_field(doc, "message", value_text(entry.get("MESSAGE")))
    for key, (field, conv) in FIELD_MAP.items():
        if key not in entry:
            continue
        text = first_text(entry[key])
        if conv == "int":
            set_field(doc, field, to_int(text))
        elif conv == "time":
            set_field(doc, field, epoch_us_to_iso(text))
        else:
            set_field(doc, field, text)
    appname = first_text(entry.get("SYSLOG_IDENTIFIER")) or first_text(entry.get("_COMM"))
    set_field(doc, "log.syslog.appname", appname)
    set_field(doc, "log.syslog.procid", first_text(entry.get("SYSLOG_PID")) or first_text(entry.get("_PID")))
    if not doc.get("process", {}).get("name"):
        set_field(doc, "process.name", appname)
    severity = to_int(first_text(entry.get("PRIORITY")))
    if severity is not None and 0 <= severity <= 7:
        set_field(doc, "log.syslog.severity.code", severity)
        set_field(doc, "log.syslog.severity.name", SEVERITY[severity])
    facility = to_int(first_text(entry.get("SYSLOG_FACILITY")))
    if facility is not None and 0 <= facility < len(FACILITY):
        set_field(doc, "log.syslog.facility.code", facility)
        set_field(doc, "log.syslog.facility.name", FACILITY[facility])
        if severity is not None:
            set_field(doc, "log.syslog.priority", facility * 8 + severity)
    extra = []
    for key in sorted(entry):
        if key in CONSUMED or key in DROPPED or key.startswith("__"):
            continue
        text = value_text(entry[key])
        if text is None:
            continue
        extra.append(f"{key}={text[:EXTRA_LIMIT]}")
    set_field(doc, "journald.extra", extra)
    set_field(doc, "event.kind", "event")
    set_field(doc, "event.dataset", "syslog.journal")
    set_field(doc, "labels.type", "syslog")
    set_field(doc, "log.file.path", rel)
    set_field(doc, "log.offset", offset)
    enrich(doc, appname, doc.get("message"))
    return doc


def parse(ev, profile, args, item, report):
    fh, rel = open_item(ev, item)
    mismatched = 0
    with fh:
        for offset, line in enumerate(fh):
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                yield None, "line is not JSON (is this a journalctl -o json export?)"
                continue
            if not isinstance(entry, dict):
                yield None, "line is not a JSON object"
                continue
            doc = build_doc(entry, rel, offset)
            if doc is None:
                yield None, "entry without a valid __REALTIME_TIMESTAMP"
                continue
            machine = doc.get("journald", {}).get("machine_id")
            if profile.host_id and machine and machine != profile.host_id:
                mismatched += 1
            cursor = doc.get("journald", {}).get("cursor")
            yield (["journal", cursor] if cursor else ["journal", rel, offset]), doc
    if mismatched:
        report.warn(f"{mismatched} entr(y/ies) in {rel} carry a _MACHINE_ID other than the evidence's"
                    f" /etc/machine-id ({profile.host_id}). Was the export taken on another machine, e.g."
                    " by a plain 'journalctl -o json' during an offline (--mount-point) collection?")


JOURNAL = LogSource("journal", "logstash", "syslog.journal", collect, parse, item_label, missing)
JOURNAL.add_arguments = add_arguments


def main(argv=None):
    return run_sources([JOURNAL], __doc__.split("\n\n")[0], argv,
                       epilog="Exit status: 0 ok, 1 bulk errors, 3 no journal export (journal not loaded).")


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Load Linux text syslog files into SOF-ELK as logstash-<hostname>.

Reads the classic rsyslog/syslog-ng/busybox files under the evidence's /var/log, for every
major distro family, including rotated copies (.1, .2.gz, -20261025, -20261025.xz):

  Debian/Ubuntu/Kali   syslog, auth.log, daemon.log, kern.log, user.log, mail.log, debug, ufw.log
  RHEL/Fedora/Amazon   messages, secure, cron, maillog
  SUSE                 messages (dated, xz-compressed rotation)
  Alpine (busybox)     messages
  firewalld            firewalld  ("YYYY-MM-DD HH:MM:SS LEVEL: message", local time)

Line formats:
  * RFC 3164  "Oct 31 13:35:20 host prog[pid]: msg" (optionally with a leading <PRI>). There is
    no year: it is taken from the file's modification time and counted back over each
    December -> January rollover in the file (--year sets it instead).
  * ISO 8601 / RFC 3339 as written by rsyslog on Debian 12+, Ubuntu 24.04+ and RHEL 9
    ("2026-10-31T13:35:20.123456+08:00 host prog[pid]: msg").
  * RFC 5424 ("<PRI>1 2026-10-31T05:35:20Z host app procid msgid [sd] msg").
Times without a zone are local time on the evidence host: the zone comes from the
evidence's /etc/localtime (or --local-tz) and is recorded in event.timezone.

Field names follow SOF-ELK's syslog parsing (1100-preprocess-syslog.conf): log.syslog.hostname,
log.syslog.appname, log.syslog.procid, process.name, process.pid, message, and
log.syslog.priority/facility/severity when the line carries a <PRI>. sshd, PAM, sudo, su,
pkexec, account management, logind, cron and kernel/iptables (ufw) messages are parsed further
(Linux/common/sof_elk_linux_messages.py). Documents carry event.dataset "syslog.file"; the
systemd journal (journal2sofelk.py) shares the index as "syslog.journal". Hosts running rsyslog
on top of journald have the same events in both: filter on event.dataset to pick one.

A line that does not start with a timestamp is appended to the previous message (multi-line
messages). The _id is derived from the host, the log family (auth.log, secure, ...) and the
line itself, so a line that appears again in a later collection (after rotation renamed the
file) overwrites instead of duplicating.

Example:
  python3 Linux/syslog2sofelk.py /cases/uac-web01.zip --case IR-42 --dry-run
"""
import datetime as dt
import hashlib
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import LogSource, iso_utc, run_sources, set_field  # noqa: E402
from sof_elk_linux_messages import enrich  # noqa: E402

FAMILIES = ("syslog", "messages", "auth.log", "secure", "daemon.log", "kern.log", "user.log", "cron",
            "cron.log", "maillog", "mail.log", "ufw.log", "debug", "firewalld")
FILE_RE = re.compile(r"^(?P<family>" + "|".join(re.escape(f) for f in FAMILIES) + r")"
                     r"(?:\.(?P<num>\d+)|-(?P<date>\d{8}))?(?:\.(?:gz|bz2|xz))?$")
SEVERITY = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug"]
FACILITY = ["kernel", "user-level", "mail", "daemon", "security/authorization", "syslogd", "line printer",
            "network news", "uucp", "clock", "security/authorization", "ftp", "ntp", "log audit",
            "log alert", "clock", "local0", "local1", "local2", "local3", "local4", "local5", "local6",
            "local7"]
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(?P<day>\d{1,2})"
    r" (?P<time>\d{2}:\d{2}:\d{2})(?:\.(?P<frac>\d{1,6}))?(?: (?P<year>\d{4}))? (?P<host>\S+) (?P<rest>.*)$")
ISO_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<date>\d{4}-\d{2}-\d{2})[T ](?P<time>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d{1,9}))?"
    r"(?P<tz>Z|[+-]\d{2}:?\d{2})? (?P<host>\S+) (?P<rest>.*)$")
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+)"
    r" (?P<sd>-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (?P<msg>.*))?$")
FIREWALLD_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2})(?:[.,](?P<frac>\d{1,6}))? (?P<level>[A-Z]+): (?P<msg>.*)$")
PROG_RE = re.compile(r"^(?P<app>[^\s\[\]:]+)(?:\[(?P<pid>\d+)\])?:(?: (?P<msg>.*)|$)")
ROLLOVER_GAP = 6  # a month step back of more than this many months is a new year


# --------------------------------------------------------------------------- input discovery

def rotation_key(item):
    """Oldest first: family, then numbered (.3 before .1 before current) / dated copies."""
    m = FILE_RE.match(Path(item).name)
    if not m:
        return (item, 0, "")
    if m.group("num"):
        return (m.group("family"), -int(m.group("num")), "")
    if m.group("date"):
        return (m.group("family"), -10**6, m.group("date"))
    return (m.group("family"), 1, "")


def collect(ev, profile, args):
    folder = ev.root_path("var/log")
    items = []
    if ev.is_dir(folder):
        files, _ = ev.listdir(folder)
        for name in files:
            if FILE_RE.match(name) and ev.size(f"{folder}/{name}") > 0:
                items.append(f"{folder}/{name}")
    for extra in args.syslog_file or []:
        rel = ev.root_path(extra.lstrip("/"))
        if ev.exists(rel):
            items.append(rel)
        else:
            print(f"  --syslog-file {extra}: not found in the evidence ({rel})")
    return sorted(set(items), key=rotation_key)


def add_arguments(ap):
    ap.add_argument("--syslog-file", action="append",
                    help="Extra syslog-format file to load, as a path on the evidence host"
                         " (e.g. /var/log/remote/web01.log); repeatable")
    ap.add_argument("--year", type=int,
                    help="Year of the LAST line of each RFC 3164 file (default: from the file's"
                         " modification time)")


# --------------------------------------------------------------------------- parsing helpers

def family_of(rel):
    m = FILE_RE.match(Path(rel).name)
    return m.group("family") if m else Path(rel).name


def pri_fields(doc, pri):
    if pri is None:
        return
    pri = int(pri)
    facility, severity = divmod(pri, 8)
    set_field(doc, "log.syslog.priority", pri)
    set_field(doc, "log.syslog.severity.code", severity)
    set_field(doc, "log.syslog.severity.name", SEVERITY[severity])
    if facility < len(FACILITY):
        set_field(doc, "log.syslog.facility.code", facility)
        set_field(doc, "log.syslog.facility.name", FACILITY[facility])


def local_to_utc(naive, profile):
    tz = profile.tz or dt.timezone.utc
    return naive.replace(tzinfo=tz)


def frac_us(frac):
    return int((frac or "0")[:6].ljust(6, "0"))


def year_plan(ev, rel, args):
    """(first-line year) for an RFC 3164 file, from its mtime and the month rollovers in it."""
    months = []
    prev = None
    rollovers = 0
    with ev.open_text(rel) as fh:
        for line in fh:
            m = RFC3164_RE.match(line)
            if not m or m.group("year"):
                continue
            month = MONTHS[m.group("mon")]
            if prev is not None and prev - month > ROLLOVER_GAP:
                rollovers += 1
            prev = month
            months.append(month)
    if not months:
        return None, 0
    if args.year:
        end_year = args.year
    else:
        mtime = ev.mtime(rel) or dt.datetime.now()
        end_year = mtime.year if prev <= mtime.month else mtime.year - 1
    return end_year - rollovers, rollovers


def split_program(rest):
    m = PROG_RE.match(rest)
    if not m:
        return None, None, rest
    return m.group("app"), m.group("pid"), m.group("msg") or ""


# --------------------------------------------------------------------------- parsing

def parse(ev, profile, args, item, report):
    rel = item
    family = family_of(rel)
    start_year, _ = year_plan(ev, rel, args)
    year, prev_month = start_year, None
    seen = parse.seen
    pending = None

    def finish(doc):
        message = doc.get("message")
        enrich(doc, doc.get("log", {}).get("syslog", {}).get("appname"), message)
        raw = doc.pop("_raw")
        key = hashlib.sha1(raw.encode("utf-8", "replace")).digest()
        n = seen.get((family, key), 0)
        seen[(family, key)] = n + 1
        return ["syslog.file", family, key.hex(), n], doc

    with ev.open_text(rel) as fh:
        for offset, line in enumerate(fh):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            doc = {}
            stamp = None
            local = False
            m = RFC5424_RE.match(line)
            fw = FIREWALLD_RE.match(line) if family == "firewalld" else None
            if fw:
                try:
                    naive = dt.datetime.fromisoformat(f"{fw.group('date')}T{fw.group('time')}")
                    stamp = local_to_utc(naive.replace(microsecond=frac_us(fw.group("frac"))), profile)
                    local = True
                except ValueError:
                    stamp = None
                app, pid, message = "firewalld", None, f"{fw.group('level')}: {fw.group('msg')}"
            elif m:
                ts = m.group("ts")
                tsm = ISO_RE.match(f"{ts} - x") if ts != "-" else None
                if tsm:
                    stamp, local = _iso_stamp(tsm, profile)
                set_field(doc, "log.syslog.hostname", None if m.group("host") == "-" else m.group("host"))
                app = None if m.group("app") == "-" else m.group("app")
                pid = None if m.group("procid") == "-" else m.group("procid")
                set_field(doc, "log.syslog.msgid", None if m.group("msgid") == "-" else m.group("msgid"))
                message = (m.group("msg") or "").lstrip("﻿")
                pri_fields(doc, m.group("pri"))
            else:
                m = RFC3164_RE.match(line)
                if m:
                    month = MONTHS[m.group("mon")]
                    if m.group("year"):
                        y = int(m.group("year"))
                    else:
                        if prev_month is not None and prev_month - month > ROLLOVER_GAP:
                            year += 1
                        prev_month = month
                        y = year
                    try:
                        hh, mm, ss = map(int, m.group("time").split(":"))
                        naive = dt.datetime(y, month, int(m.group("day")), hh, mm, ss, frac_us(m.group("frac")))
                        stamp, local = local_to_utc(naive, profile), True
                    except ValueError:
                        stamp = None
                    set_field(doc, "log.syslog.hostname", m.group("host"))
                    app, pid, message = split_program(m.group("rest"))
                    pri_fields(doc, m.group("pri"))
                else:
                    m = ISO_RE.match(line)
                    if m:
                        stamp, local = _iso_stamp(m, profile)
                        set_field(doc, "log.syslog.hostname", m.group("host"))
                        app, pid, message = split_program(m.group("rest"))
                        pri_fields(doc, m.group("pri"))
                    elif pending is not None:
                        # Continuation of a multi-line message.
                        pending["message"] = (pending.get("message") or "") + "\n" + line
                        pending["_raw"] += "\n" + line
                        continue
                    else:
                        yield None, "line without a recognised timestamp"
                        continue
            if stamp is None:
                yield None, "invalid date in line"
                continue
            if pending is not None:
                yield finish(pending)
            doc["@timestamp"] = iso_utc(stamp)
            set_field(doc, "message", message)
            set_field(doc, "log.syslog.appname", app)
            set_field(doc, "log.syslog.procid", pid)
            set_field(doc, "process.name", app)
            try:
                set_field(doc, "process.pid", int(pid) if pid else None)
            except ValueError:
                pass
            set_field(doc, "event.kind", "event")
            set_field(doc, "event.dataset", "syslog.file")
            if local:
                set_field(doc, "event.timezone", profile.tz_name or "UTC")
            set_field(doc, "labels.type", "syslog")
            set_field(doc, "log.file.path", rel)
            set_field(doc, "log.offset", offset)
            doc["_raw"] = line
            pending = doc
    if pending is not None:
        yield finish(pending)
    if start_year is not None and not args.year:
        report.warn("RFC 3164 lines carry no year: it was taken from each file's modification time"
                    " (check the first lines of each file; --year overrides it)")


parse.seen = {}


def _iso_stamp(m, profile):
    """(aware datetime, was_local) from an ISO_RE match."""
    try:
        naive = dt.datetime.fromisoformat(f"{m.group('date')}T{m.group('time')}").replace(
            microsecond=frac_us(m.group("frac")))
    except ValueError:
        return None, False
    tz = m.group("tz")
    if not tz:
        return local_to_utc(naive, profile), True
    if tz == "Z":
        return naive.replace(tzinfo=dt.timezone.utc), False
    sign = 1 if tz[0] == "+" else -1
    digits = tz[1:].replace(":", "")
    offset = dt.timedelta(hours=int(digits[:2]), minutes=int(digits[2:]))
    return naive.replace(tzinfo=dt.timezone(sign * offset)), False


SYSLOG = LogSource("syslog", "logstash", "syslog.file", collect, parse, str)
SYSLOG.add_arguments = add_arguments


def main(argv=None):
    return run_sources([SYSLOG], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

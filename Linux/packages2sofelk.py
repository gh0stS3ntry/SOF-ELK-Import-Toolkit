#!/usr/bin/env python3
"""Load Linux package history and installed-package inventories into SOF-ELK as packages-<hostname>.

One document per package action (install, upgrade, remove, ...) from each package manager's
own log, plus one document per installed package from the package database. Every major
distro family is searched, whatever the detected distro, so a host with an unusual setup is
still covered:

  event.dataset            source (current and rotated copies, .gz/.bz2/.xz)
  packages.dpkg            /var/log/dpkg.log*              Debian, Ubuntu, Kali  (local time)
  packages.apt             /var/log/apt/history.log*       Debian family: one transaction per
                                                           block, with the apt command line
                                                           and the user who ran it
  packages.dnf             /var/log/dnf.rpm.log*           RHEL/Rocky/Alma 8+, Fedora (UTC offset)
  packages.dnf_history     /var/lib/dnf/history.sqlite     RHEL 8+, Fedora: every transaction
                                                           with command line, user, repository
  packages.yum             /var/log/yum.log*               RHEL/CentOS 7 (local time, no year)
  packages.zypper          /var/log/zypp/history*          SUSE: actions, zypper command lines,
                                                           repositories added and removed
  packages.inventory       /var/lib/dpkg/status            installed packages (Debian family)
                           /var/lib/rpm/rpmdb.sqlite,      installed packages with install time
                           /usr/lib/sysimage/rpm/rpmdb.sqlite  (RHEL 9+, Fedora 33+, SUSE)
                           /lib/apk/db/installed           installed packages (Alpine)

Times without a zone are local time on the evidence host (the evidence's /etc/localtime, or
--local-tz) and the zone is stored in event.timezone. yum.log carries no year: it is taken
from the file's modification time and counted back over each December -> January rollover.

Inventory timestamps: rpm records each package's install time (package.installed). dpkg and
apk do not; when the collection has a UAC bodyfile, the modification time of dpkg's
/var/lib/dpkg/info/<package>.list (written at the last install or upgrade of the package) is
used for package.installed instead. Otherwise @timestamp is the database file's mtime.

Not read: apt/term.log (terminal output only), dnf.log/dnf5.log (debug text; the history
database has the same transactions), the Berkeley DB rpm database of RHEL 8 and older (not
readable with the standard library; dnf history and dnf.rpm.log cover those hosts).

Example:
  python3 Linux/packages2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
from __future__ import annotations

import datetime as dt
import hashlib
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
from sof_elk_linux_files import FileMeta, epoch_to_dt, host_path, iso, read_lines, walk  # noqa: E402

DATASETS = ["packages.dpkg", "packages.apt", "packages.dnf", "packages.dnf_history", "packages.yum",
            "packages.zypper", "packages.inventory"]

ROTATED = r"(?:\.(?P<num>\d+)|-(?P<date>\d{8}))?(?:\.(?:gz|bz2|xz))?$"
LOGS = (
    # (kind, folder, file name regex)
    ("dpkg", "var/log", re.compile(r"^dpkg\.log" + ROTATED)),
    ("apt", "var/log/apt", re.compile(r"^history\.log" + ROTATED)),
    ("dnf", "var/log", re.compile(r"^dnf\.rpm\.log" + ROTATED)),
    ("yum", "var/log", re.compile(r"^yum\.log" + ROTATED)),
    ("zypper", "var/log/zypp", re.compile(r"^history" + ROTATED)),
)
DATABASES = (
    ("dnf_history", "var/lib/dnf/history.sqlite"),
    ("dpkg_status", "var/lib/dpkg/status"),
    ("rpmdb", "var/lib/rpm/rpmdb.sqlite"),
    ("rpmdb", "usr/lib/sysimage/rpm/rpmdb.sqlite"),
    ("apk_installed", "lib/apk/db/installed"),
    ("apk_installed", "usr/lib/apk/db/installed"),
)
BERKELEY_RPMDB = ("var/lib/rpm/Packages", "usr/lib/sysimage/rpm/Packages")

ACTION_TYPES = {
    "install": "installation", "reinstall": "installation", "upgrade": "change", "downgrade": "change",
    "remove": "deletion", "purge": "deletion", "obsoleted": "deletion", "installed": "info",
    "reason-change": "change", "command": "info", "patch": "installation",
    "repository-added": "creation", "repository-removed": "deletion",
}
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


# --------------------------------------------------------------------------- discovery

def rotation_key(rel):
    name = rel.rsplit("/", 1)[-1]
    for _, _, regex in LOGS:
        m = regex.match(name)
        if m:
            if m.group("num"):
                return (rel.rsplit("/", 1)[0], name.split(".")[0], 0, -int(m.group("num")), "")
            if m.group("date"):
                return (rel.rsplit("/", 1)[0], name.split(".")[0], 0, -10**6, m.group("date"))
            return (rel.rsplit("/", 1)[0], name.split(".")[0], 1, 0, "")
    return (rel, "", 0, 0, "")


def collect(ev, profile, args):
    items = []
    for kind, folder, regex in LOGS:
        rel_dir = ev.root_path(folder)
        if not ev.is_dir(rel_dir):
            continue
        files, _ = ev.listdir(rel_dir)
        found = [f"{rel_dir}/{n}" for n in files if regex.match(n) and ev.size(f"{rel_dir}/{n}") > 0]
        items.extend((kind, rel) for rel in sorted(found, key=rotation_key))
    for kind, path in DATABASES:
        rel = ev.root_path(path)
        if ev.exists(rel) and ev.size(rel) > 0:
            items.append((kind, rel))
    if not any(k == "rpmdb" for k, _ in items):
        for path in BERKELEY_RPMDB:
            if ev.exists(ev.root_path(path)):
                print(f"  /{path}: Berkeley DB rpm database (RHEL 8 or older) - not readable with the"
                      " Python standard library; package history comes from dnf/yum logs instead")
    meta = FileMeta(ev, profile)
    if meta.has_bodyfile and any(k == "dpkg_status" for k, _ in items):
        meta.want("/var/lib/dpkg/info/")
    for _, rel in items:
        meta.want(host_path(ev, rel))
    collect.meta = meta
    collect.users = load_users(ev)
    return items


collect.meta = None
collect.users = {}


def item_label(item):
    return f"{item[0]}: {item[1]}"


def load_users(ev):
    """uid -> user name from the evidence's /etc/passwd (for dnf history user ids)."""
    out = {}
    for line in read_lines(ev, ev.root_path("etc/passwd")) or []:
        parts = line.split(":")
        if len(parts) >= 3 and parts[2].isdigit():
            out.setdefault(int(parts[2]), parts[0])
    return out


# --------------------------------------------------------------------------- helpers

def local_time(naive, profile):
    return naive.replace(tzinfo=profile.tz or dt.timezone.utc)


def split_arch(name):
    """'dpkg:amd64' -> ('dpkg', 'amd64')."""
    if ":" in name:
        n, a = name.split(":", 1)
        return n, a
    return name, None


NEVRA_RE = re.compile(r"^(?:(?P<e0>\d+):)?(?P<name>.+)-(?:(?P<epoch>\d+):)?(?P<ver>[^-]+)-(?P<rel>[^-]+?)"
                      r"\.(?P<arch>[^.]+)$")


def parse_nevra(text):
    """'nginx-1:1.20.1-14.el9.x86_64' or '1:nginx-1.20.1-10.el7.x86_64' -> (name, version, arch)."""
    text = text.strip()
    m = NEVRA_RE.match(text)
    if not m:
        return text, None, None
    epoch = m.group("epoch") or m.group("e0")
    version = f"{m.group('ver')}-{m.group('rel')}"
    if epoch and epoch != "0":
        version = f"{epoch}:{version}"
    return m.group("name"), version, m.group("arch")


def base_doc(dataset, manager, action, stamp, rel, ev, local, profile):
    doc = {"@timestamp": iso_utc(stamp) if isinstance(stamp, dt.datetime) else stamp}
    set_field(doc, "event.kind", "event" if dataset != "packages.inventory" else "state")
    set_field(doc, "event.category", ["package"] if not action.startswith("repository") else ["configuration"])
    set_field(doc, "event.type", [ACTION_TYPES.get(action, "change")])
    set_field(doc, "event.action", action)
    set_field(doc, "event.dataset", dataset)
    set_field(doc, "package.manager", manager)
    set_field(doc, "labels.type", "packages")
    set_field(doc, "log.file.path", rel)
    if local:
        set_field(doc, "event.timezone", profile.tz_name or "UTC")
    return doc


def set_package(doc, name, version=None, arch=None, previous=None, ptype=None):
    set_field(doc, "package.name", name)
    set_field(doc, "package.version", version)
    set_field(doc, "package.architecture", arch)
    set_field(doc, "package.type", ptype)
    set_field(doc, "packages.previous_version", previous)


class Occurrences:
    """Identical lines stay separate documents: (key, n) per repeat."""

    def __init__(self):
        self.seen = {}

    def key(self, *parts):
        digest = hashlib.sha1(repr(parts).encode("utf-8", "replace")).hexdigest()
        n = self.seen.get(digest, 0)
        self.seen[digest] = n + 1
        return [digest, n]


# --------------------------------------------------------------------------- dpkg.log

DPKG_RE = re.compile(r"^(?P<date>\d{4}-\d{2}-\d{2}) (?P<time>\d{2}:\d{2}:\d{2}) (?P<action>install|upgrade|remove|purge)"
                     r" (?P<pkg>\S+) (?P<old>\S+) (?P<new>\S+)\s*$")
DPKG_OTHER_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (?P<what>\S+)")


def parse_dpkg(ev, profile, args, rel, report, occ):
    for offset, line in enumerate(read_lines(ev, rel) or []):
        if not line.strip():
            continue
        m = DPKG_RE.match(line)
        if not m:
            o = DPKG_OTHER_RE.match(line)
            yield None, f"dpkg.log {o.group('what')} line (not a package action)" if o else "dpkg.log unrecognised line"
            continue
        try:
            naive = dt.datetime.fromisoformat(f"{m.group('date')}T{m.group('time')}")
        except ValueError:
            yield None, "dpkg.log invalid date"
            continue
        action = m.group("action")
        old = None if m.group("old") == "<none>" else m.group("old")
        new = None if m.group("new") == "<none>" else m.group("new")
        if action == "upgrade" and old and old == new:
            action = "reinstall"
        name, arch = split_arch(m.group("pkg"))
        doc = base_doc("packages.dpkg", "dpkg", action, local_time(naive, profile), rel, ev, True, profile)
        set_package(doc, name, new if action in ("install", "upgrade", "reinstall") else old, arch,
                    old if action == "upgrade" else None, "deb")
        set_field(doc, "log.offset", offset)
        set_field(doc, "event.original", line)
        yield ["dpkg"] + occ.key("dpkg", line), doc


# --------------------------------------------------------------------------- apt history.log

APT_PKG_RE = re.compile(r"(?P<pkg>[^\s,()]+) \((?P<info>[^)]*)\)")
APT_ACTIONS = {"Install": "install", "Upgrade": "upgrade", "Remove": "remove", "Purge": "purge",
               "Downgrade": "downgrade", "Reinstall": "reinstall"}


def parse_apt(ev, profile, args, rel, report, occ):
    block, start_offset = {}, 0
    lines = (read_lines(ev, rel) or []) + [""]
    for offset, line in enumerate(lines):
        if line.strip():
            if not block:
                start_offset = offset
            key, sep, value = line.partition(": ")
            if sep:
                block[key.strip()] = value.strip()
            continue
        if not block:
            continue
        current, block = block, {}
        start = current.get("Start-Date")
        try:
            naive = dt.datetime.strptime(re.sub(r"\s+", " ", start or ""), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            yield None, "apt history block without a valid Start-Date"
            continue
        stamp = local_time(naive, profile)
        end = None
        try:
            end = local_time(dt.datetime.strptime(re.sub(r"\s+", " ", current.get("End-Date", "")),
                                                  "%Y-%m-%d %H:%M:%S"), profile)
        except ValueError:
            pass
        user, uid = None, None
        req = current.get("Requested-By")
        if req:
            m = re.match(r"^(?P<user>\S+)(?: \((?P<uid>\d+)\))?", req)
            if m:
                user, uid = m.group("user"), m.group("uid")
        found = False
        for key, action in APT_ACTIONS.items():
            if key not in current:
                continue
            for pm in APT_PKG_RE.finditer(current[key]):
                found = True
                info = [x.strip() for x in pm.group("info").split(",")]
                automatic = "automatic" in info
                info = [x for x in info if x != "automatic"]
                name, arch = split_arch(pm.group("pkg"))
                previous = version = None
                if action in ("upgrade", "downgrade") and len(info) >= 2:
                    previous, version = info[0], info[1]
                elif info:
                    version = info[0]
                doc = base_doc("packages.apt", "apt", action, stamp, rel, ev, True, profile)
                set_package(doc, name, version, arch, previous, "deb")
                set_field(doc, "packages.automatic", automatic)
                set_field(doc, "process.command_line", current.get("Commandline"))
                set_field(doc, "user.name", user)
                set_field(doc, "user.id", uid)
                set_field(doc, "event.start", iso_utc(stamp))
                set_field(doc, "event.end", iso_utc(end) if end else None)
                set_field(doc, "packages.transaction_id", re.sub(r"\s+", " ", start))
                if current.get("Error"):
                    set_field(doc, "event.outcome", "failure")
                    set_field(doc, "error.message", current["Error"][:8000])
                else:
                    set_field(doc, "event.outcome", "success" if end else "unknown")
                set_field(doc, "log.offset", start_offset)
                yield ["apt"] + occ.key("apt", start, current.get("Commandline"), key, pm.group(0)), doc
        if not found:
            yield None, "apt history block without package actions"


# --------------------------------------------------------------------------- dnf.rpm.log

DNF_RE = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+\S+\s+"
                    r"(?P<action>Installed|Installing|Upgrade|Upgrading|Upgraded|Erase|Erasing|Downgrade|"
                    r"Downgrading|Downgraded|Reinstall|Reinstalling|Reinstalled|Obsolete|Obsoleting|Obsoleted|"
                    r"Cleanup|Removed|Reason change):\s+(?P<pkg>\S+)\s*$")
DNF_ACTIONS = {"Installed": "install", "Installing": "install", "Upgrade": "upgrade", "Upgrading": "upgrade",
               "Erase": "remove", "Erasing": "remove", "Removed": "remove", "Downgrade": "downgrade",
               "Downgrading": "downgrade", "Reinstall": "reinstall", "Reinstalling": "reinstall",
               "Obsoleted": "obsoleted", "Reason change": "reason-change"}
DNF_OLD = {"Upgraded", "Downgraded"}


def parse_iso_offset(text):
    t = text.replace("Z", "+00:00")
    m = re.search(r"([+-])(\d{2})(\d{2})$", t)
    if m:
        t = t[:m.start()] + f"{m.group(1)}{m.group(2)}:{m.group(3)}"
    try:
        stamp = dt.datetime.fromisoformat(t)
    except ValueError:
        return None
    return stamp if stamp.tzinfo else None


def parse_dnf(ev, profile, args, rel, report, occ):
    pending = []      # documents of this file, so "Upgraded: old" can be paired with "Upgrade: new"
    open_changes = {}  # (name, arch) -> doc waiting for its previous version
    for offset, line in enumerate(read_lines(ev, rel) or []):
        m = DNF_RE.match(line)
        if not m:
            if line.strip():
                pending.append((None, "dnf.rpm.log line that is not a package action"))
            continue
        stamp = parse_iso_offset(m.group("ts"))
        local = False
        if stamp is None:
            try:
                stamp = local_time(dt.datetime.fromisoformat(m.group("ts")[:19]), profile)
                local = True
            except ValueError:
                pending.append((None, "dnf.rpm.log invalid date"))
                continue
        name, version, arch = parse_nevra(m.group("pkg"))
        word = m.group("action")
        if word in DNF_OLD:
            doc = open_changes.pop((name, arch), None)
            if doc is not None:
                set_field(doc, "packages.previous_version", version)
            pending.append((None, f"dnf.rpm.log {word} (old version, merged into the {word[:-2].lower()} document)"))
            continue
        if word in ("Cleanup", "Reinstalled", "Obsolete", "Obsoleting"):
            pending.append((None, f"dnf.rpm.log {word} (follows the main action)"))
            continue
        action = DNF_ACTIONS[word]
        doc = base_doc("packages.dnf", "dnf", action, stamp, rel, ev, local, profile)
        set_package(doc, name, version, arch, None, "rpm")
        set_field(doc, "log.offset", offset)
        set_field(doc, "event.original", line)
        if action in ("upgrade", "downgrade"):
            open_changes[(name, arch)] = doc
        pending.append((["dnf"] + occ.key("dnf", line), doc))
    yield from pending


# --------------------------------------------------------------------------- dnf history.sqlite

DNF_HISTORY_ACTIONS = {1: "install", 2: "downgrade", 3: None, 4: "install", 5: "obsoleted", 6: "upgrade",
                       7: None, 8: "remove", 9: "reinstall", 10: None, 11: "reason-change"}
DNF_REASONS = {0: "unknown", 1: "dependency", 2: "user", 3: "clean", 4: "weak-dependency", 5: "group"}
DNF_STATES = {1: "success", 2: "failure"}


def sqlite_copy(ev, rel):
    """Copy an evidence SQLite file (and its -wal/-shm) to a temp folder; returns (dir, path)."""
    tmp = tempfile.mkdtemp(prefix="sofelk-sqlite-")
    name = rel.rsplit("/", 1)[-1]
    for suffix in ("", "-wal", "-shm"):
        src = rel + suffix
        if not ev.exists(src):
            continue
        with ev.open_binary(src, decompress=False) as fh, open(os.path.join(tmp, name + suffix), "wb") as out:
            shutil.copyfileobj(fh, out)
    return tmp, os.path.join(tmp, name)


def parse_dnf_history(ev, profile, args, rel, report, occ):
    tmp, path = sqlite_copy(ev, rel)
    try:
        con = sqlite3.connect(path)
        con.row_factory = sqlite3.Row
        try:
            rows = con.execute(
                "SELECT t.id AS tid, t.dt_begin, t.dt_end, t.user_id, t.cmdline, t.state AS tstate,"
                " ti.action, ti.reason, ti.state AS istate, r.name, r.epoch, r.version, r.release, r.arch,"
                " repo.repoid AS repoid"
                " FROM trans t JOIN trans_item ti ON ti.trans_id = t.id"
                " JOIN rpm r ON r.item_id = ti.item_id"
                " LEFT JOIN repo ON repo.id = ti.repo_id ORDER BY t.id, ti.id").fetchall()
        except sqlite3.DatabaseError as exc:
            report.warn(f"{rel}: not a dnf history database this importer knows ({exc})")
            return
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    old_versions = {}
    for row in rows:
        version = f"{row['version']}-{row['release']}"
        if row["epoch"] and str(row["epoch"]) != "0":
            version = f"{row['epoch']}:{version}"
        if row["action"] in (3, 7):  # Downgraded / Upgraded: the version that was replaced
            old_versions[(row["tid"], row["name"], row["arch"])] = version
    for row in rows:
        action = DNF_HISTORY_ACTIONS.get(row["action"])
        if action is None:
            yield None, "dnf history replaced-version item (merged into the upgrade document)"
            continue
        stamp = epoch_to_dt(row["dt_begin"])
        if stamp is None:
            yield None, "dnf history transaction without a begin time"
            continue
        version = f"{row['version']}-{row['release']}"
        if row["epoch"] and str(row["epoch"]) != "0":
            version = f"{row['epoch']}:{version}"
        doc = base_doc("packages.dnf_history", "dnf", action, stamp, rel, ev, False, profile)
        set_package(doc, row["name"], version, row["arch"],
                    old_versions.get((row["tid"], row["name"], row["arch"])), "rpm")
        set_field(doc, "packages.transaction_id", str(row["tid"]))
        set_field(doc, "packages.reason", DNF_REASONS.get(row["reason"]))
        set_field(doc, "packages.automatic", row["reason"] in (1, 4) if row["reason"] in DNF_REASONS else None)
        set_field(doc, "packages.repository", row["repoid"])
        set_field(doc, "process.command_line", row["cmdline"])
        if row["user_id"] is not None:
            set_field(doc, "user.id", str(row["user_id"]))
            set_field(doc, "user.name", collect.users.get(row["user_id"]))
        set_field(doc, "event.start", iso(stamp))
        set_field(doc, "event.end", iso(epoch_to_dt(row["dt_end"])))
        set_field(doc, "event.outcome", DNF_STATES.get(row["istate"], "unknown"))
        yield ["dnf_history", row["tid"], row["name"], row["arch"], version, row["action"]], doc


# --------------------------------------------------------------------------- yum.log (RHEL 7)

YUM_RE = re.compile(r"^(?P<mon>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) {1,2}(?P<day>\d{1,2})"
                    r" (?P<time>\d{2}:\d{2}:\d{2}) (?P<action>Installed|Updated|Erased|Dep-Installed|Obsoleted|"
                    r"Reinstalled|Downgraded):\s+(?P<pkg>\S+)\s*$")
YUM_ACTIONS = {"Installed": "install", "Dep-Installed": "install", "Updated": "upgrade", "Erased": "remove",
               "Obsoleted": "obsoleted", "Reinstalled": "reinstall", "Downgraded": "downgrade"}


def parse_yum(ev, profile, args, rel, report, occ):
    lines = read_lines(ev, rel) or []
    months = [MONTHS[m.group("mon")] for m in map(YUM_RE.match, lines) if m]
    if not months:
        for line in lines:
            if line.strip():
                yield None, "yum.log unrecognised line"
        return
    rollovers = sum(1 for a, b in zip(months, months[1:]) if a - b > 6)
    mtime = (collect.meta.get(rel).get("mtime") if collect.meta else None)
    if mtime is not None:
        mtime = mtime.astimezone(profile.tz or dt.timezone.utc)
    end_year = getattr(args, "year", None)
    if not end_year:
        end_year = (mtime or dt.datetime.now()).year
        if mtime and months[-1] > mtime.month:
            end_year -= 1
        report.warn("yum.log lines carry no year: it was taken from each file's modification time"
                    " (--year overrides it)")
    year, prev = end_year - rollovers, None
    for offset, line in enumerate(lines):
        m = YUM_RE.match(line)
        if not m:
            if line.strip():
                yield None, "yum.log unrecognised line"
            continue
        month = MONTHS[m.group("mon")]
        if prev is not None and prev - month > 6:
            year += 1
        prev = month
        try:
            hh, mm, ss = map(int, m.group("time").split(":"))
            naive = dt.datetime(year, month, int(m.group("day")), hh, mm, ss)
        except ValueError:
            yield None, "yum.log invalid date"
            continue
        name, version, arch = parse_nevra(m.group("pkg"))
        action = YUM_ACTIONS[m.group("action")]
        doc = base_doc("packages.yum", "yum", action, local_time(naive, profile), rel, ev, True, profile)
        set_package(doc, name, version, arch, None, "rpm")
        set_field(doc, "packages.automatic", True if m.group("action") == "Dep-Installed" else None)
        set_field(doc, "log.offset", offset)
        set_field(doc, "event.original", line)
        yield ["yum"] + occ.key("yum", line, year), doc


# --------------------------------------------------------------------------- zypp/history (SUSE)

def parse_zypper(ev, profile, args, rel, report, occ):
    last_command = None  # (time, user, command line)
    for offset, line in enumerate(read_lines(ev, rel) or []):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split("|")
        if len(f) < 3:
            yield None, "zypp history unrecognised line"
            continue
        try:
            naive = dt.datetime.strptime(f[0].strip(), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            yield None, "zypp history invalid date"
            continue
        stamp = local_time(naive, profile)
        word = f[1].strip()
        doc = None
        if word == "command":
            user = f[2].split("@", 1)[0] if len(f) > 2 else None
            cmd = f[3].strip() if len(f) > 3 else None
            if cmd:
                cmd = " ".join(re.findall(r"'((?:[^']|'\\'')*)'", cmd)) or cmd
            last_command = (stamp, user, cmd)
            doc = base_doc("packages.zypper", "zypper", "command", stamp, rel, ev, True, profile)
            set_field(doc, "user.name", user)
            set_field(doc, "process.command_line", cmd)
        elif word in ("install", "remove", "patch") and len(f) >= 5:
            action = word
            doc = base_doc("packages.zypper", "zypper", action, stamp, rel, ev, True, profile)
            set_package(doc, f[2].strip(), f[3].strip(), f[4].strip(), None, "rpm")
            reqby = f[5].strip() if len(f) > 5 else ""
            user = reqby.split("@", 1)[0] if reqby else None
            set_field(doc, "user.name", user if user and not user.isdigit() else None)
            set_field(doc, "user.id", user if user and user.isdigit() else None)
            if action in ("install", "patch") and len(f) > 6:
                set_field(doc, "packages.repository", f[6].strip())
            if last_command and (stamp - last_command[0]) <= dt.timedelta(minutes=30) \
                    and (not user or user == last_command[1]):
                set_field(doc, "process.command_line", last_command[2])
            set_field(doc, "packages.automatic", reqby == "" if action == "install" else None)
        elif word in ("radd", "rremove") and len(f) >= 3:
            doc = base_doc("packages.zypper", "zypper",
                           "repository-added" if word == "radd" else "repository-removed",
                           stamp, rel, ev, True, profile)
            set_field(doc, "packages.repository", f[2].strip())
            if word == "radd" and len(f) > 3:
                set_field(doc, "url.original", f[3].strip())
        else:
            yield None, f"zypp history '{word}' line"
            continue
        set_field(doc, "log.offset", offset)
        set_field(doc, "event.original", line)
        yield ["zypper"] + occ.key("zypper", line), doc


# --------------------------------------------------------------------------- inventories

def inventory_doc(ev, profile, rel, manager, action, stamp, fallback_meta):
    if stamp is None:
        stamp = fallback_meta.get("mtime")
    doc = base_doc("packages.inventory", manager, action, iso(stamp) if stamp else None, rel, ev, False, profile)
    if not doc.get("@timestamp"):
        doc.pop("@timestamp", None)
    doc["event"]["type"] = ["info"]
    set_field(doc, "packages.mtime_source", fallback_meta.get("source"))
    return doc


def parse_dpkg_status(ev, profile, args, rel, report, occ):
    meta = collect.meta.get(rel)
    lists = {}
    if collect.meta.has_bodyfile:
        for e in collect.meta.bodyfile_children("/var/lib/dpkg/info"):
            name = e["path"].rsplit("/", 1)[-1]
            if name.endswith(".list"):
                lists[name[:-5]] = e.get("mtime")
        if lists:
            report.warn("dpkg inventory: package.installed is the mtime of /var/lib/dpkg/info/<package>.list"
                        " from the bodyfile (the last install or upgrade of that package)")
    lines = (read_lines(ev, rel, limit=256 << 20) or []) + [""]
    block = {}
    last_key = None
    for line in lines:
        if line.strip():
            if line[0] in " \t":
                if last_key == "Description" and "_desc_more" not in block:
                    block["_desc_more"] = True
                continue
            key, sep, value = line.partition(":")
            if sep:
                last_key = key
                block[key] = value.strip()
            continue
        if not block:
            continue
        cur, block = block, {}
        name = cur.get("Package")
        if not name:
            continue
        status = cur.get("Status", "")
        state = status.split()[-1] if status else None
        arch = cur.get("Architecture")
        installed = lists.get(f"{name}:{arch}") or lists.get(name)
        meta_src = dict(meta)
        if installed is not None:
            meta_src["source"] = "bodyfile dpkg info list"
        doc = inventory_doc(ev, profile, rel, "dpkg", "installed" if state == "installed" else (state or "unknown"),
                            installed, meta_src)
        set_package(doc, name, cur.get("Version"), arch, None, "deb")
        set_field(doc, "package.description", cur.get("Description"))
        set_field(doc, "package.installed", iso(installed))
        try:
            set_field(doc, "package.size", int(cur.get("Installed-Size", "")) * 1024)
        except ValueError:
            pass
        set_field(doc, "packages.status", status)
        set_field(doc, "packages.source_package", (cur.get("Source") or "").split(" ")[0] or None)
        set_field(doc, "packages.maintainer", cur.get("Maintainer"))
        yield ["inventory", "dpkg", name, arch, cur.get("Version")], doc


RPM_TAGS = {1000: "name", 1001: "version", 1002: "release", 1003: "epoch", 1004: "summary", 1006: "buildtime",
            1008: "installtime", 1009: "size", 1011: "vendor", 1015: "packager", 1022: "arch", 1044: "sourcerpm"}
RPM_HEADER_MAGIC = b"\x8e\xad\xe8\x01"


def parse_rpm_header(blob):
    """Selected tags of an rpm header blob (as stored in rpmdb.sqlite) -> dict, or None."""
    if blob is None:
        return None
    blob = bytes(blob)
    if blob[:4] == RPM_HEADER_MAGIC:
        blob = blob[8:]
    if len(blob) < 8:
        return None
    count, size = struct.unpack(">II", blob[:8])
    start = 8 + 16 * count
    if count > 100000 or start + size > len(blob):
        return None
    data = blob[start:start + size]
    out = {}
    for i in range(count):
        tag, typ, off, cnt = struct.unpack(">IIII", blob[8 + 16 * i:24 + 16 * i])
        name = RPM_TAGS.get(tag)
        if not name or off >= len(data):
            continue
        if typ == 4:  # INT32
            if off + 4 <= len(data):
                out[name] = struct.unpack(">I", data[off:off + 4])[0]
        elif typ in (6, 8, 9):  # STRING, STRING_ARRAY, I18NSTRING: first string
            end = data.find(b"\x00", off)
            out[name] = data[off:end if end >= 0 else len(data)].decode("utf-8", "replace")
    return out if out.get("name") else None


def parse_rpmdb(ev, profile, args, rel, report, occ):
    meta = collect.meta.get(rel)
    tmp, path = sqlite_copy(ev, rel)
    try:
        con = sqlite3.connect(path)
        try:
            rows = con.execute("SELECT hnum, blob FROM Packages").fetchall()
        except sqlite3.DatabaseError as exc:
            report.warn(f"{rel}: not an rpm sqlite database ({exc})")
            return
        finally:
            con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for hnum, blob in rows:
        h = parse_rpm_header(blob)
        if not h:
            yield None, "rpm header that could not be parsed"
            continue
        if h["name"] == "gpg-pubkey":
            yield None, "rpm gpg-pubkey pseudo-package"
            continue
        version = f"{h.get('version')}-{h.get('release')}"
        if h.get("epoch"):
            version = f"{h['epoch']}:{version}"
        installed = epoch_to_dt(h.get("installtime"))
        doc = inventory_doc(ev, profile, rel, "rpm", "installed", installed, meta)
        if installed is not None:
            set_field(doc, "packages.mtime_source", "rpm installtime")
        set_package(doc, h["name"], version, h.get("arch"), None, "rpm")
        set_field(doc, "package.description", h.get("summary"))
        set_field(doc, "package.installed", iso(installed))
        set_field(doc, "package.size", h.get("size"))
        set_field(doc, "package.build_version", iso(epoch_to_dt(h.get("buildtime"))))
        set_field(doc, "packages.vendor", h.get("vendor"))
        set_field(doc, "packages.maintainer", h.get("packager"))
        set_field(doc, "packages.source_package", h.get("sourcerpm"))
        set_field(doc, "packages.status", "installed")
        yield ["inventory", "rpm", h["name"], h.get("arch"), version], doc


def parse_apk_installed(ev, profile, args, rel, report, occ):
    meta = collect.meta.get(rel)
    world = set()
    for line in read_lines(ev, ev.root_path("etc/apk/world")) or []:
        token = re.split(r"[<>=~@ ]", line.strip(), 1)[0]
        if token:
            world.add(token)
    block = {}
    for line in (read_lines(ev, rel, limit=256 << 20) or []) + [""]:
        if len(line) > 1 and line[1] == ":":
            block.setdefault(line[0], line[2:])
            continue
        if line.strip() or not block:
            continue
        cur, block = block, {}
        name = cur.get("P")
        if not name:
            continue
        doc = inventory_doc(ev, profile, rel, "apk", "installed", None, meta)
        set_package(doc, name, cur.get("V"), cur.get("A"), None, "apk")
        set_field(doc, "package.description", cur.get("T"))
        set_field(doc, "package.reference", cur.get("U"))
        try:
            set_field(doc, "package.size", int(cur.get("I", "")))
        except ValueError:
            pass
        set_field(doc, "package.build_version", iso(epoch_to_dt(cur.get("t"))))
        set_field(doc, "packages.source_package", cur.get("o"))
        set_field(doc, "packages.maintainer", cur.get("m"))
        set_field(doc, "packages.status", "installed")
        if world:
            set_field(doc, "packages.automatic", name not in world)
        yield ["inventory", "apk", name, cur.get("A"), cur.get("V")], doc


# --------------------------------------------------------------------------- dispatcher

PARSERS = {"dpkg": parse_dpkg, "apt": parse_apt, "dnf": parse_dnf, "dnf_history": parse_dnf_history,
           "yum": parse_yum, "zypper": parse_zypper, "dpkg_status": parse_dpkg_status, "rpmdb": parse_rpmdb,
           "apk_installed": parse_apk_installed}


def parse(ev, profile, args, item, report):
    kind, rel = item
    if collect.meta is None:
        collect.meta = FileMeta(ev, profile)
    occ = parse.occ
    for parts, doc in PARSERS[kind](ev, profile, args, rel, report, occ):
        if parts is None:
            yield None, doc
            continue
        if "@timestamp" not in doc:
            yield None, "no timestamp (file modification time unknown)"
            continue
        yield parts, doc


parse.occ = Occurrences()


def add_arguments(ap):
    if not any(a.dest == "year" for a in ap._actions):
        ap.add_argument("--year", type=int,
                        help="Year of the LAST line of each RFC 3164 / yum.log file (default: from the"
                             " file's modification time)")


PACKAGES = LogSource("packages", "packages", DATASETS, collect, parse, item_label)
PACKAGES.add_arguments = add_arguments


def main(argv=None):
    return run_sources([PACKAGES], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

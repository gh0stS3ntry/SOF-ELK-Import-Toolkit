#!/usr/bin/env python3
"""Load a snapshot of Linux accounts and persistence locations into SOF-ELK as linuxconfig-<hostname>.

One document per account, group, sudoers rule, cron entry, systemd unit, script line, SSH key,
hosts entry, resolver setting, loader setting and package repository, read from the evidence's
own files. Stacking these across hosts (STATS ... BY) gives least-frequency-of-occurrence
persistence hunting. Every distro family's locations are searched, whatever the detected
distro.

  event.dataset          read from
  linux.account          /etc/passwd + /etc/shadow METADATA ONLY (hash algorithm, locked/empty,
                         last change, expiry). The password hash itself is never stored, logged
                         or sent. /etc/passwd- (the copy before the last change) marks accounts
                         added or removed by that change.
  linux.group            /etc/group (+ /etc/group-), members incl. primary-group members, a
                         privileged flag (root, sudo, wheel, adm, admin, docker, lxd, libvirt,
                         disk, shadow, or any group granted rights in sudoers)
  linux.sudoers          /etc/sudoers, /etc/sudoers.d/*, included files: rules (NOPASSWD and
                         ALL flags), Defaults, aliases
  linux.cron             /etc/crontab, /etc/cron.d/*, /etc/anacrontab, user crontabs
                         (/var/spool/cron/crontabs/*, /var/spool/cron/*, /var/spool/cron/tabs/*,
                         /etc/crontabs/*), and one document per command line of the scripts in
                         /etc/cron.{hourly,daily,weekly,monthly,yearly}, /etc/periodic/* and at jobs
  linux.systemd_unit     unit files (.service .timer .socket .path .mount .automount) from every
                         system and user unit folder incl. ~/.config/systemd/user, drop-ins
                         (<unit>.d/*.conf), and the links that enable (*.wants/, *.requires/),
                         alias or mask them; ExecStart, User, timers, sockets, enabled/masked
  linux.init_script      non-comment lines of rc.local, init.d, /etc/local.d (Alpine), /etc/profile,
                         /etc/profile.d/*, bash.bashrc/bashrc, /etc/environment, zsh startup files,
                         and each user's .bashrc .bash_profile .bash_login .profile .bash_aliases
                         .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout
  linux.autostart        XDG autostart entries (/etc/xdg/autostart, ~/.config/autostart)
  linux.ssh_key          authorized_keys(2) and known_hosts per user, /etc/ssh/ssh_known_hosts:
                         key type, SHA256 fingerprint, comment, options (command=, from=)
  linux.hosts            /etc/hosts entries, including commented-out ones (old targets)
  linux.resolver         /etc/resolv.conf, /etc/systemd/resolved.conf(.d)
  linux.ld_preload       /etc/ld.so.preload, /etc/ld.so.conf(.d)
  linux.repository       apt sources (.list and deb822 .sources), yum/dnf .repo, zypper .repo,
                         /etc/apk/repositories

@timestamp is the source file's modification time: from the UAC bodyfile when the collection
has one (exact, and it also gives symlink targets and owners), else the file system, else the
zip entry date (read in the evidence host's time zone). file.* holds the source file's path,
times, owner and mode.

Never read: shadow hashes (only metadata is derived in memory), gshadow, private keys
(id_*, ssh_host_*_key), shell history, credential stores, live_response.

Example:
  python3 Linux/linuxconfig2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import ipaddress
import posixpath
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent / "common"))

from sof_elk_linux_common import LogSource, run_sources, set_field  # noqa: E402
from sof_elk_linux_files import FileMeta, file_fields, host_path, iso, read_lines, walk  # noqa: E402

DATASETS = ["linux.account", "linux.group", "linux.sudoers", "linux.cron", "linux.systemd_unit",
            "linux.init_script", "linux.autostart", "linux.ssh_key", "linux.hosts", "linux.resolver",
            "linux.ld_preload", "linux.repository"]

PRIVILEGED_GROUPS = {"root", "sudo", "wheel", "adm", "admin", "docker", "lxd", "libvirt", "disk", "shadow"}
NOLOGIN_SHELLS = ("nologin", "false", "sync", "shutdown", "halt")
SKIP_NAMES = {".placeholder", "README", ".keep", ".gitkeep"}
EPOCH_DATE = dt.date(1970, 1, 1)

USER_PROFILE_FILES = (".bashrc", ".bash_profile", ".bash_login", ".profile", ".bash_aliases", ".bash_logout",
                      ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout")
SYSTEM_PROFILE_FILES = ("etc/profile", "etc/bash.bashrc", "etc/bashrc", "etc/environment", "etc/zshenv",
                        "etc/zprofile", "etc/zshrc", "etc/zlogin", "etc/zlogout", "etc/zsh/zshenv",
                        "etc/zsh/zprofile", "etc/zsh/zshrc", "etc/zsh/zlogin", "etc/zsh/zlogout",
                        "etc/bash.bashrc.local")
UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path", ".mount", ".automount")
SYSTEMD_DIRS = (
    # (container-relative folder, scope, origin)
    ("etc/systemd/system", "system", "admin"),
    ("run/systemd/system", "system", "runtime"),
    ("usr/local/lib/systemd/system", "system", "admin"),
    ("usr/lib/systemd/system", "system", "vendor"),
    ("lib/systemd/system", "system", "vendor"),
    ("etc/systemd/user", "user", "admin"),
    ("usr/lib/systemd/user", "user", "vendor"),
    ("lib/systemd/user", "user", "vendor"),
)
LINK_DIR_RE = re.compile(r"\.(wants|requires|upholds)$")
CRON_PERIODIC = ("etc/cron.hourly", "etc/cron.daily", "etc/cron.weekly", "etc/cron.monthly", "etc/cron.yearly")
AT_DIRS = ("var/spool/cron/atjobs", "var/spool/at", "var/spool/atjobs")

LINE_FLAGS = (
    ("ld_preload", re.compile(r"LD_PRELOAD|LD_LIBRARY_PATH|LD_AUDIT")),
    ("dev_tcp", re.compile(r"/dev/(?:tcp|udp)/")),
    ("download_exec", re.compile(r"\b(?:curl|wget|fetch)\b[^|;&]*\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b")),
    ("base64_decode", re.compile(r"base64\s+(?:-d|--decode)\b|\bb64decode\b")),
    ("reverse_shell", re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-(?:e|c)\s|\bsocat\b[^\n]*exec:|bash\s+-i\b")),
)


# --------------------------------------------------------------------------- helpers

def line_flags(text):
    return [name for name, regex in LINE_FLAGS if regex.search(text)]


def days_to_date(value):
    try:
        days = int(value)
    except (TypeError, ValueError):
        return None
    if days < 0 or days > 2_000_000:
        return None
    return (EPOCH_DATE + dt.timedelta(days=days)).isoformat()


def int_or_none(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def strip_comment(line):
    """Shell-style comment removal for config lines (keeps # inside quotes)."""
    out, quote = [], None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            break
        out.append(ch)
    return "".join(out).strip()


class Context:
    """Per-run state shared by the parsers."""

    def __init__(self, ev, profile):
        self.ev = ev
        self.profile = profile
        self.meta = FileMeta(ev, profile)
        self.passwd = parse_passwd_lines(read_lines(ev, ev.root_path("etc/passwd")) or [])
        self.homes = {}
        for u in self.passwd.values():
            if u["home"] and u["home"] not in ("/", "/nonexistent"):
                self.homes.setdefault(u["home"].rstrip("/"), u["name"])
        self.sudo_groups = set()
        self.sudo_users = set()

    def user_for(self, abs_path):
        """Owner of a per-user file from its home folder (/home/kali/.bashrc -> kali)."""
        best = None
        for home, name in self.homes.items():
            if abs_path.startswith(home + "/") and (best is None or len(home) > len(best[0])):
                best = (home, name)
        if best:
            return best[1]
        m = re.match(r"^/home/([^/]+)/", abs_path)
        if m:
            return m.group(1)
        return "root" if abs_path.startswith("/root/") else None


def new_doc(ctx, dataset, kind, rel, meta=None):
    meta = meta if meta is not None else ctx.meta.get(rel)
    doc = {}
    if meta.get("mtime") is not None:
        doc["@timestamp"] = iso(meta["mtime"])
    set_field(doc, "event.kind", "state")
    set_field(doc, "event.category", ["configuration"])
    set_field(doc, "event.type", ["info"])
    set_field(doc, "event.dataset", dataset)
    set_field(doc, "event.action", kind)
    set_field(doc, "labels.type", "linuxconfig")
    set_field(doc, "linuxconfig.kind", kind)
    set_field(doc, "linuxconfig.mtime_source", meta.get("source"))
    set_field(doc, "log.file.path", rel)
    file_fields(doc, meta, set_field)
    return doc


def add_line(doc, text, number):
    set_field(doc, "linuxconfig.line", text[:8000])
    set_field(doc, "linuxconfig.line_number", number)
    set_field(doc, "linuxconfig.flags", line_flags(text))


def logical_lines(lines, continuation=True):
    """(1-based line number, text) with backslash continuations joined."""
    buf, start = "", None
    for i, raw in enumerate(lines, 1):
        line = raw.rstrip()
        if continuation and line.endswith("\\") and not line.lstrip().startswith("#"):
            if start is None:
                start = i
            buf += line[:-1] + " "
            continue
        if buf:
            yield start, (buf + line).strip()
            buf, start = "", None
        else:
            yield i, line
    if buf:
        yield start, buf.strip()


# --------------------------------------------------------------------------- accounts and groups

def parse_passwd_lines(lines):
    users = {}
    for i, line in enumerate(lines, 1):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.split(":")
        if len(f) < 7:
            continue
        users.setdefault(f[0], {"name": f[0], "pw": f[1], "uid": int_or_none(f[2]), "gid": int_or_none(f[3]),
                                "gecos": f[4], "home": f[5], "shell": f[6], "line_number": i})
    return users


def shadow_metadata(field):
    """(state, algorithm) of a shadow/passwd password field. The field itself is discarded."""
    if field == "":
        return "empty", None
    locked = field.startswith("!")
    rest = field.lstrip("!")
    if rest in ("", "*", "x", "*LK*", "NP", "LK") or rest.startswith("*"):
        return ("locked_no_password" if locked else "no_password"), None
    algo = None
    m = re.match(r"^\$([^$]+)\$", rest)
    if m:
        algo = {"1": "md5", "2a": "bcrypt", "2b": "bcrypt", "2x": "bcrypt", "2y": "bcrypt", "5": "sha256",
                "6": "sha512", "y": "yescrypt", "gy": "gost-yescrypt", "7": "scrypt", "sha1": "sha1",
                "md5": "sun-md5"}.get(m.group(1), "unknown")
    elif re.fullmatch(r"[./0-9A-Za-z]{13}", rest):
        algo = "des"
    elif rest.startswith("_"):
        algo = "bsdi"
    return ("locked" if locked else "set"), algo


def read_shadow(ev):
    """{user: metadata} from /etc/shadow; the hash field is reduced to state/algorithm at once."""
    out = {}
    for line in read_lines(ev, ev.root_path("etc/shadow")) or []:
        f = line.split(":")
        if len(f) < 2 or not f[0] or line.startswith("#"):
            continue
        state, algo = shadow_metadata(f[1])
        f[1] = None  # never keep the hash
        out[f[0]] = {"state": state, "algorithm": algo,
                     "last_change": f[2] if len(f) > 2 else "", "min": f[3] if len(f) > 3 else "",
                     "max": f[4] if len(f) > 4 else "", "warn": f[5] if len(f) > 5 else "",
                     "inactive": f[6] if len(f) > 6 else "", "expire": f[7] if len(f) > 7 else ""}
    return out


def login_defs_uid_min(ev):
    for line in read_lines(ev, ev.root_path("etc/login.defs")) or []:
        m = re.match(r"^\s*UID_MIN\s+(\d+)", line)
        if m:
            return int(m.group(1))
    return 1000


def parse_accounts(ctx, rel, report):
    ev = ctx.ev
    current = ctx.passwd
    backup_rel = ev.root_path("etc/passwd-")
    backup = parse_passwd_lines(read_lines(ev, backup_rel) or []) if ev.exists(backup_rel) else None
    shadow = read_shadow(ev)
    uid_min = login_defs_uid_min(ev)
    uids = {}
    for u in current.values():
        uids.setdefault(u["uid"], []).append(u["name"])
    rows = [(u, "present", rel) for u in current.values()]
    if backup is not None:
        rows = [(u, "new_since_backup" if u["name"] not in backup else "present", rel) for u in current.values()]
        rows += [(u, "only_in_backup", backup_rel) for n, u in backup.items() if n not in current]
    for u, state, src in rows:
        doc = new_doc(ctx, "linux.account", "account", src)
        set_field(doc, "user.name", u["name"])
        set_field(doc, "user.id", str(u["uid"]) if u["uid"] is not None else None)
        set_field(doc, "user.group.id", str(u["gid"]) if u["gid"] is not None else None)
        set_field(doc, "user.full_name", u["gecos"].split(",")[0] or None)
        a = "linuxconfig.account."
        set_field(doc, a + "gecos", u["gecos"])
        set_field(doc, a + "home", u["home"])
        set_field(doc, a + "shell", u["shell"])
        set_field(doc, a + "login_shell", not u["shell"].rstrip("/").endswith(NOLOGIN_SHELLS) if u["shell"] else False)
        set_field(doc, a + "system_account", u["uid"] is not None and u["uid"] < uid_min)
        set_field(doc, a + "state", state)
        set_field(doc, "linuxconfig.line_number", u["line_number"])
        flags = []
        sh = shadow.get(u["name"]) if state != "only_in_backup" else None
        if u["pw"] not in ("x", "*", "!", ""):
            # A hash in /etc/passwd itself (legacy): reduce it to metadata as well.
            pstate, palgo = shadow_metadata(u["pw"])
            sh = sh or {"state": pstate, "algorithm": palgo}
            flags.append("password_in_passwd")
        elif u["pw"] == "":
            sh = {"state": "empty", "algorithm": None}
        if sh:
            set_field(doc, a + "password_state", sh["state"])
            set_field(doc, a + "password_algorithm", sh.get("algorithm"))
            last = sh.get("last_change", "")
            set_field(doc, a + "password_last_changed", days_to_date(last) if last not in ("", "0") else None)
            if last == "0":
                flags.append("password_change_required")
            set_field(doc, a + "password_min_days", int_or_none(sh.get("min")))
            mx = int_or_none(sh.get("max"))
            set_field(doc, a + "password_max_days", mx if mx is not None and mx < 99999 else None)
            set_field(doc, a + "password_warn_days", int_or_none(sh.get("warn")))
            set_field(doc, a + "password_inactive_days", int_or_none(sh.get("inactive")))
            set_field(doc, a + "account_expires", days_to_date(sh.get("expire")))
            if sh["state"] == "empty":
                flags.append("empty_password")
        if u["uid"] == 0 and u["name"] != "root":
            flags.append("uid0")
        if len(uids.get(u["uid"], [])) > 1:
            flags.append("duplicate_uid")
        if u["name"] in ctx.sudo_users:
            flags.append("sudoers_rule")
        set_field(doc, "linuxconfig.flags", flags)
        yield ["account", state, u["name"]], doc
    if not shadow:
        report.warn("no /etc/shadow in the evidence: password state and ageing are not available")


def parse_group_lines(lines):
    groups = {}
    for i, line in enumerate(lines, 1):
        f = line.split(":")
        if len(f) < 4 or not f[0] or line.startswith("#"):
            continue
        groups.setdefault(f[0], {"name": f[0], "gid": int_or_none(f[2]),
                                 "members": sorted(m for m in f[3].split(",") if m), "line_number": i})
    return groups


def parse_groups(ctx, rel, report):
    ev = ctx.ev
    current = parse_group_lines(read_lines(ev, rel) or [])
    backup_rel = ev.root_path("etc/group-")
    backup = parse_group_lines(read_lines(ev, backup_rel) or []) if ev.exists(backup_rel) else None
    primary = {}
    for u in ctx.passwd.values():
        primary.setdefault(u["gid"], []).append(u["name"])
    rows = []
    for g in current.values():
        state = "present"
        prev = None
        if backup is not None:
            if g["name"] not in backup:
                state = "new_since_backup"
            elif backup[g["name"]]["members"] != g["members"]:
                state, prev = "changed_since_backup", backup[g["name"]]["members"]
        rows.append((g, state, rel, prev))
    if backup is not None:
        rows += [(g, "only_in_backup", backup_rel, None) for n, g in backup.items() if n not in current]
    for g, state, src, prev in rows:
        doc = new_doc(ctx, "linux.group", "group", src)
        set_field(doc, "group.name", g["name"])
        set_field(doc, "group.id", str(g["gid"]) if g["gid"] is not None else None)
        p = "linuxconfig.group."
        set_field(doc, p + "members", g["members"])
        set_field(doc, p + "primary_members", sorted(primary.get(g["gid"], [])))
        set_field(doc, p + "previous_members", prev)
        if prev is not None:
            set_field(doc, p + "members_added", sorted(set(g["members"]) - set(prev)))
            set_field(doc, p + "members_removed", sorted(set(prev) - set(g["members"])))
        in_sudoers = g["name"] in ctx.sudo_groups
        set_field(doc, p + "privileged", g["name"] in PRIVILEGED_GROUPS or in_sudoers)
        set_field(doc, p + "state", state)
        set_field(doc, "linuxconfig.line_number", g["line_number"])
        set_field(doc, "linuxconfig.flags", ["sudoers_rule"] if in_sudoers else [])
        yield ["group", state, g["name"]], doc


# --------------------------------------------------------------------------- sudoers

SUDO_TAG_RE = re.compile(r"^(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|"
                         r"NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|NOFOLLOW|INTERCEPT|NOINTERCEPT):\s*")


def sudoers_files(ev):
    """sudoers and the files it includes (sudoers.d and any #include / @include)."""
    seen, queue, out = set(), [ev.root_path("etc/sudoers")], []
    queue_dirs = [ev.root_path("etc/sudoers.d")]
    while queue or queue_dirs:
        if queue:
            rel = queue.pop(0)
            if rel in seen or not ev.exists(rel):
                continue
            seen.add(rel)
            out.append(rel)
            for line in read_lines(ev, rel) or []:
                m = re.match(r"^\s*[#@](include|includedir)\s+(\S+)", line)
                if m:
                    target = m.group(2).replace("%h", "")
                    path = ev.root_path(target.lstrip("/")) if target.startswith("/") else \
                        posixpath.join(posixpath.dirname(rel), target)
                    (queue_dirs if m.group(1) == "includedir" else queue).append(path)
        else:
            d = queue_dirs.pop(0)
            if d in seen:
                continue
            seen.add(d)
            for rel in walk(ev, d):
                name = rel.rsplit("/", 1)[-1]
                # sudo skips names ending in ~ or containing a dot in includedir folders
                if name.endswith("~") or "." in name:
                    continue
                queue.append(rel)
    return out


def split_top(text, sep=","):
    """Split on sep outside parentheses and backslash escapes."""
    out, buf, depth, esc = [], "", 0, False
    for ch in text:
        if esc:
            buf += ch
            esc = False
            continue
        if ch == "\\":
            esc = True
            buf += ch
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == sep and depth == 0:
            out.append(buf.strip())
            buf = ""
        else:
            buf += ch
    if buf.strip():
        out.append(buf.strip())
    return out


def parse_sudo_rule(text):
    """'%wheel ALL=(ALL:ALL) NOPASSWD: ALL' -> dict, or None."""
    m = re.match(r"^(?P<who>.+?)\s+(?P<rest>[^\s=]+\s*=.*)$", text)
    if not m:
        return None
    who = [w.strip() for w in split_top(m.group("who"))]
    hosts, _, cmdpart = m.group("rest").partition("=")
    cmdpart = cmdpart.strip()
    runas = None
    rm = re.match(r"^\(([^)]*)\)\s*", cmdpart)
    if rm:
        runas = rm.group(1).strip()
        cmdpart = cmdpart[rm.end():]
    tags = []
    while True:
        tm = SUDO_TAG_RE.match(cmdpart)
        if not tm:
            break
        tags.append(tm.group(1))
        cmdpart = cmdpart[tm.end():]
    commands = []
    for c in split_top(cmdpart):
        c = c.strip()
        rm = re.match(r"^\(([^)]*)\)\s*", c)
        if rm:
            runas = runas or rm.group(1).strip()
            c = c[rm.end():]
        while True:
            tm = SUDO_TAG_RE.match(c)
            if not tm:
                break
            tags.append(tm.group(1))
            c = c[tm.end():]
        if c:
            commands.append(c)
    return {"who": who, "hosts": [h.strip() for h in hosts.split(",") if h.strip()], "runas": runas,
            "tags": sorted(set(tags)), "commands": commands}


def sudo_principals(ev):
    users, groups = set(), set()
    for rel in sudoers_files(ev):
        for _, text in logical_lines(read_lines(ev, rel) or []):
            text = text.strip()
            if not text or text.startswith(("#", "@", "Defaults")) or re.match(r"^\w+_Alias\b", text):
                continue
            rule = parse_sudo_rule(text)
            if not rule:
                continue
            for w in rule["who"]:
                w = w.lstrip("!")
                if w.startswith("%:"):
                    groups.add(w[2:])
                elif w.startswith("%"):
                    groups.add(w[1:])
                elif not w.startswith(("+", "#")) and not w.isupper():
                    users.add(w)
    return users, groups


def parse_sudoers(ctx, rel, report):
    for number, text in logical_lines(read_lines(ctx.ev, rel) or []):
        text = text.strip()
        if not text:
            continue
        m = re.match(r"^[#@](include|includedir)\s+(\S+)", text)
        if text.startswith("#") and not m:
            continue
        doc = new_doc(ctx, "linux.sudoers", "include" if m else "rule", rel)
        add_line(doc, text, number)
        s = "linuxconfig.sudoers."
        if m:
            set_field(doc, s + "include", m.group(2))
        elif text.startswith("Defaults"):
            doc["linuxconfig"]["kind"] = doc["event"]["action"] = "defaults"
            dm = re.match(r"^Defaults([@:!>]\S+)?\s+(.*)$", text)
            if dm:
                set_field(doc, s + "defaults_scope", dm.group(1))
                set_field(doc, s + "defaults", [x.strip() for x in split_top(dm.group(2))])
                flags = []
                if re.search(r"env_keep\s*\+?=.*LD_|!env_reset|env_delete\s*-=", dm.group(2)):
                    flags.append("env_preserved")
                if "!authenticate" in dm.group(2):
                    flags.append("nopasswd")
                set_field(doc, "linuxconfig.flags", sorted(set(doc["linuxconfig"].get("flags", []) + flags)))
        elif re.match(r"^(User|Runas|Host|Cmnd|Cmd)_Alias\b", text):
            doc["linuxconfig"]["kind"] = doc["event"]["action"] = "alias"
            am = re.match(r"^(\w+)_Alias\s+([A-Z0-9_]+)\s*=\s*(.*)$", text)
            if am:
                set_field(doc, s + "alias_type", am.group(1).lower())
                set_field(doc, s + "alias_name", am.group(2))
                set_field(doc, s + "commands", split_top(am.group(3)))
        else:
            rule = parse_sudo_rule(text)
            if not rule:
                yield None, "sudoers line that is not a rule"
                continue
            set_field(doc, s + "principals", rule["who"])
            first = rule["who"][0] if rule["who"] else ""
            ptype = ("group" if first.startswith("%") else "netgroup" if first.startswith("+")
                     else "alias" if first.isupper() and first != "ALL" else "all" if first == "ALL" else "user")
            set_field(doc, s + "principal_type", ptype)
            if ptype == "user":
                set_field(doc, "user.name", first)
            elif ptype == "group":
                set_field(doc, "group.name", first.lstrip("%:"))
            set_field(doc, s + "hosts", rule["hosts"])
            set_field(doc, s + "runas", rule["runas"])
            set_field(doc, s + "tags", rule["tags"])
            set_field(doc, s + "commands", rule["commands"])
            nopasswd = "NOPASSWD" in rule["tags"]
            all_cmds = any(c.strip() == "ALL" for c in rule["commands"])
            set_field(doc, s + "nopasswd", nopasswd)
            set_field(doc, s + "all_commands", all_cmds)
            flags = list(doc["linuxconfig"].get("flags", []))
            if nopasswd:
                flags.append("nopasswd")
            if all_cmds:
                flags.append("all_commands")
            set_field(doc, "linuxconfig.flags", flags)
        yield ["sudoers", rel, number, text], doc


# --------------------------------------------------------------------------- cron

CRON_SPECIAL = ("@reboot", "@yearly", "@annually", "@monthly", "@weekly", "@daily", "@midnight", "@hourly")
CRON_VAR_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")


def cron_tables(ev):
    """(container path, flavour) of every crontab-format file. flavour: system (user column),
    user (owner = file name), anacron."""
    out = []
    if ev.exists(ev.root_path("etc/crontab")):
        out.append((ev.root_path("etc/crontab"), "system"))
    for rel in walk(ev, ev.root_path("etc/cron.d")):
        out.append((rel, "system"))
    if ev.exists(ev.root_path("etc/anacrontab")):
        out.append((ev.root_path("etc/anacrontab"), "anacron"))
    for folder in ("var/spool/cron/crontabs", "var/spool/cron/tabs", "etc/crontabs", "var/spool/cron"):
        for rel in walk(ev, ev.root_path(folder)):
            out.append((rel, "user"))
    return [(r, f) for r, f in out if r.rsplit("/", 1)[-1] not in SKIP_NAMES
            and not r.rsplit("/", 1)[-1].startswith(".")]


def parse_cron_table(ctx, rel, flavour, report):
    owner = rel.rsplit("/", 1)[-1] if flavour == "user" else None
    for number, text in logical_lines(read_lines(ctx.ev, rel) or [], continuation=False):
        line = text.strip()
        if not line or line.startswith("#"):
            continue
        c = "linuxconfig.cron."
        vm = CRON_VAR_RE.match(line)
        doc = new_doc(ctx, "linux.cron", "variable" if vm else "entry", rel)
        add_line(doc, line, number)
        set_field(doc, c + "source", {"system": "system", "user": "user", "anacron": "anacron"}[flavour])
        if vm and not line.startswith(("@",)) and not re.match(r"^[\d*]", line):
            set_field(doc, c + "variable_name", vm.group(1))
            set_field(doc, c + "variable_value", vm.group(2).strip().strip("'\""))
            set_field(doc, "user.name", owner)
            yield ["cron", rel, number, line], doc
            continue
        doc["linuxconfig"]["kind"] = doc["event"]["action"] = "entry"
        parts = line.split()
        user = owner
        if flavour == "anacron":
            if len(parts) < 4:
                yield None, "anacrontab line that is not a job"
                continue
            schedule, command = parts[0], " ".join(parts[3:])
            set_field(doc, c + "job_id", parts[2])
            set_field(doc, c + "delay_minutes", int_or_none(parts[1]))
            user = "root"
        elif parts[0].lower() in CRON_SPECIAL:
            schedule = parts[0]
            rest = parts[1:]
            if flavour == "system" and rest:
                user, rest = rest[0], rest[1:]
            command = " ".join(rest)
        else:
            if len(parts) < 6:
                yield None, "cron line that is not a job"
                continue
            schedule = " ".join(parts[:5])
            rest = parts[5:]
            if flavour == "system":
                user, rest = rest[0], rest[1:]
            command = " ".join(rest)
        if not command:
            yield None, "cron line without a command"
            continue
        set_field(doc, c + "schedule", schedule)
        set_field(doc, "user.name", user)
        set_field(doc, "process.command_line", command)
        yield ["cron", rel, number, line], doc


def cron_scripts(ev):
    out = []
    for folder in CRON_PERIODIC:
        for rel in walk(ev, ev.root_path(folder)):
            out.append((rel, folder.rsplit(".", 1)[-1]))
    for rel in walk(ev, ev.root_path("etc/periodic"), recursive=True, max_depth=1):
        out.append((rel, rel.rsplit("/", 2)[-2]))
    for folder in AT_DIRS:
        for rel in walk(ev, ev.root_path(folder)):
            out.append((rel, "at"))
    return [(r, p) for r, p in out if r.rsplit("/", 1)[-1] not in SKIP_NAMES
            and not r.rsplit("/", 1)[-1].startswith(".")]


def script_lines(ctx, rel, dataset, kind, extra, id_tag):
    """One document per non-comment line of a shell script / profile file."""
    lines = read_lines(ctx.ev, rel)
    if lines is None:
        return
    meta = ctx.meta.get(rel)
    abs_path = meta.get("path") or host_path(ctx.ev, rel)
    user = ctx.user_for(abs_path)
    for number, text in logical_lines(lines):
        line = text.strip()
        if not line or line.startswith("#"):
            continue
        doc = new_doc(ctx, dataset, kind, rel, meta)
        add_line(doc, line, number)
        set_field(doc, "user.name", user)
        for k, v in extra.items():
            set_field(doc, k, v)
        yield [id_tag, rel, number, line], doc


# --------------------------------------------------------------------------- systemd

def parse_unit_text(lines):
    """{section: [(key, value)]} with continuation lines joined."""
    out, section = {}, None
    for _, text in logical_lines(lines):
        line = text.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            out.setdefault(section, [])
            continue
        if "=" in line and section:
            k, v = line.split("=", 1)
            out[section].append((k.strip(), v.strip()))
    return out


def unit_values(sections, section, key):
    vals = []
    for k, v in sections.get(section, []):
        if k == key:
            if v == "":
                vals = []  # an empty assignment resets the list
            else:
                vals.append(v)
    return vals


def exec_command(value):
    """Strip systemd's ExecStart prefixes (-, @, :, +, !, !!)."""
    return re.sub(r"^[-@:+!]+", "", value).strip()


def systemd_entries(ev, meta, home_dirs):
    """[(rel, scope, origin, folder)] for every file under the unit folders."""
    dirs = list(SYSTEMD_DIRS)
    for home in home_dirs:
        for sub in (".config/systemd/user", ".local/share/systemd/user"):
            dirs.append((posixpath.join(home.lstrip("/"), sub), "user", "user_home"))
    lib_is_link = False
    e = meta.bodyfile_entry("/lib") if meta.has_bodyfile else None
    if e and e.get("link"):
        lib_is_link = True
    elif not ev.is_zip and (ev.path / ev.root_path("lib")).is_symlink():
        lib_is_link = True
    out = []
    usr_names = set()
    for folder, scope, origin in dirs:
        base = ev.root_path(folder)
        if folder.startswith("lib/") and lib_is_link:
            continue
        files = walk(ev, base, recursive=True, max_depth=2)
        for rel in files:
            sub = rel[len(base) + 1:]
            if folder.startswith("usr/lib/"):
                usr_names.add((scope, sub))
            elif folder.startswith("lib/") and (scope, sub) in usr_names:
                continue  # same file reachable as /lib and /usr/lib (merged /usr)
            out.append((rel, scope, origin, base))
        if meta.has_bodyfile:
            # Symlinks UAC did not copy (masks -> /dev/null, links to files outside the collection)
            walked = set(files)
            for e in meta.bodyfile_under("/" + folder, max_depth=2):
                rel = ev.root_path(e["path"].lstrip("/"))
                if e.get("link") and rel not in walked:
                    out.append((rel, scope, origin, base))
    return out


def parse_systemd(ctx, report):
    ev = ctx.ev
    entries = systemd_entries(ev, ctx.meta, sorted(set(list(ctx.homes) + ["/root"])))
    vendor_content = {}
    for rel, scope, origin, base in entries:
        sub = rel[len(base) + 1:]
        if origin == "vendor" and "/" not in sub and sub.endswith(UNIT_SUFFIXES + (".target",)):
            lines = read_lines(ev, rel)
            if lines is not None:
                digest = hashlib.sha1("\n".join(lines).encode("utf-8", "replace")).hexdigest()
                vendor_content.setdefault((scope, digest), host_path(ev, rel))
    links, units, dropins = [], [], []
    for rel, scope, origin, base in entries:
        sub = rel[len(base) + 1:]
        parts = sub.split("/")
        name = parts[-1]
        if name in SKIP_NAMES:
            continue
        meta = ctx.meta.get(rel)
        if len(parts) == 2 and LINK_DIR_RE.search(parts[0]):
            links.append((rel, scope, origin, parts[0], name, meta))
        elif len(parts) == 2 and parts[0].endswith(".d") and name.endswith(".conf"):
            dropins.append((rel, scope, origin, parts[0][:-2], meta))
        elif len(parts) == 1 and meta.get("link") and "." in name:
            links.append((rel, scope, origin, None, name, meta))
        elif len(parts) == 1 and name.endswith(UNIT_SUFFIXES):
            units.append((rel, scope, origin, name, meta))
    # Enablement: unit name -> [(target, link)], plus masks.
    enabled_by, masked = {}, set()
    for rel, scope, origin, folder, name, meta in links:
        target = meta.get("target")
        if folder:
            wanted = LINK_DIR_RE.sub("", folder)
            enabled_by.setdefault((scope, name), []).append(wanted)
        if target == "/dev/null":
            masked.add((scope, name))
    seen_units = set()
    # Unit files (admin copies in zip form with the same content as a vendor unit are links).
    for rel, scope, origin, name, meta in units:
        lines = read_lines(ev, rel)
        if lines is None:
            continue
        inferred_target = None
        if origin == "admin" and meta.get("source") == "zip":
            digest = hashlib.sha1("\n".join(lines).encode("utf-8", "replace")).hexdigest()
            inferred_target = vendor_content.get((scope, digest))
            if inferred_target and posixpath.basename(inferred_target) != name:
                yield from systemd_link_doc(ctx, rel, scope, origin, None, name, meta, inferred_target)
                continue
            inferred_target = None
        seen_units.add((scope, name))
        yield from systemd_unit_doc(ctx, rel, scope, origin, name, meta, lines, enabled_by, masked, "unit")
    for rel, scope, origin, unit, meta in dropins:
        lines = read_lines(ev, rel)
        if lines is None:
            continue
        yield from systemd_unit_doc(ctx, rel, scope, origin, unit, meta, lines, enabled_by, masked, "dropin")
    for rel, scope, origin, folder, name, meta in links:
        if (scope, name) not in seen_units and folder:
            # The unit itself was not collected (or only its link copy was): describe it from the copy.
            lines = read_lines(ev, rel)  # a folder symlink is read from its target inside the evidence
            if lines:
                seen_units.add((scope, name))
                target = meta.get("target") or ""
                unit_origin = "vendor" if target.startswith(("/usr/lib/", "/lib/")) else origin
                yield from systemd_unit_doc(ctx, rel, scope, unit_origin, name, meta, lines, enabled_by, masked,
                                            "unit")
        yield from systemd_link_doc(ctx, rel, scope, origin, folder, name, meta, None)


def systemd_link_doc(ctx, rel, scope, origin, folder, name, meta, inferred_target):
    doc = new_doc(ctx, "linux.systemd_unit", "link", rel, meta)
    s = "linuxconfig.systemd."
    target = meta.get("target") or inferred_target
    set_field(doc, s + "unit", name)
    set_field(doc, s + "unit_type", name.rsplit(".", 1)[-1] if "." in name else None)
    set_field(doc, s + "scope", scope)
    set_field(doc, s + "origin", origin)
    set_field(doc, s + "link_target", target)
    set_field(doc, s + "link_inferred", True if inferred_target and not meta.get("target") else None)
    if folder:
        set_field(doc, s + "link_kind", LINK_DIR_RE.search(folder).group(1))
        set_field(doc, s + "enabled_by", [LINK_DIR_RE.sub("", folder)])
        set_field(doc, s + "enabled", True)
    elif target == "/dev/null":
        set_field(doc, s + "link_kind", "mask")
        set_field(doc, s + "masked", True)
    else:
        set_field(doc, s + "link_kind", "alias")
    set_field(doc, "user.name", ctx.user_for(meta.get("path") or "") if origin == "user_home" else None)
    yield ["systemd-link", rel], doc


def systemd_unit_doc(ctx, rel, scope, origin, name, meta, lines, enabled_by, masked, kind):
    sections = parse_unit_text(lines)
    doc = new_doc(ctx, "linux.systemd_unit", kind, rel, meta)
    s = "linuxconfig.systemd."
    unit_type = name.rsplit(".", 1)[-1] if "." in name else None
    set_field(doc, s + "unit", name)
    set_field(doc, s + "unit_type", unit_type)
    set_field(doc, s + "scope", scope)
    set_field(doc, s + "origin", origin)
    set_field(doc, s + "description", (unit_values(sections, "Unit", "Description") or [None])[-1])
    exec_start = [exec_command(v) for v in unit_values(sections, "Service", "ExecStart")]
    set_field(doc, s + "exec_start", exec_start)
    other = []
    for key in ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload", "ExecCondition"):
        other += [f"{key}={exec_command(v)}" for v in unit_values(sections, "Service", key)]
    set_field(doc, s + "exec_other", other)
    if exec_start:
        set_field(doc, "process.command_line", exec_start[0])
        set_field(doc, "process.executable", exec_start[0].split()[0] if exec_start[0].split() else None)
    set_field(doc, s + "service_type", (unit_values(sections, "Service", "Type") or [None])[-1])
    set_field(doc, s + "run_as_user", (unit_values(sections, "Service", "User") or [None])[-1])
    set_field(doc, s + "environment", unit_values(sections, "Service", "Environment")
              + [f"EnvironmentFile={v}" for v in unit_values(sections, "Service", "EnvironmentFile")])
    set_field(doc, s + "wanted_by", unit_values(sections, "Install", "WantedBy")
              + unit_values(sections, "Install", "RequiredBy"))
    if unit_type == "timer":
        timers = []
        for key in ("OnCalendar", "OnBootSec", "OnStartupSec", "OnActiveSec", "OnUnitActiveSec",
                    "OnUnitInactiveSec"):
            timers += [f"{key}={v}" for v in unit_values(sections, "Timer", key)]
        set_field(doc, s + "timer_schedule", timers)
        set_field(doc, s + "triggers_unit", (unit_values(sections, "Timer", "Unit") or
                                             [name[:-len(".timer")] + ".service"])[-1])
    elif unit_type == "socket":
        listen = []
        for key in ("ListenStream", "ListenDatagram", "ListenSequentialPacket", "ListenFIFO", "ListenNetlink"):
            listen += [f"{key}={v}" for v in unit_values(sections, "Socket", key)]
        set_field(doc, s + "listen", listen)
        set_field(doc, s + "triggers_unit", (unit_values(sections, "Socket", "Service") or [None])[-1])
    elif unit_type == "path":
        watch = []
        for key in ("PathExists", "PathExistsGlob", "PathChanged", "PathModified", "DirectoryNotEmpty"):
            watch += [f"{key}={v}" for v in unit_values(sections, "Path", key)]
        set_field(doc, s + "path_watch", watch)
        set_field(doc, s + "triggers_unit", (unit_values(sections, "Path", "Unit") or
                                             [name[:-len(".path")] + ".service"])[-1])
    if kind == "unit":
        by = sorted(set(enabled_by.get((scope, name), [])))
        set_field(doc, s + "enabled_by", by)
        set_field(doc, s + "enabled", bool(by))
        set_field(doc, s + "masked", True if (scope, name) in masked else None)
    flags = []
    for cmd in exec_start + other:
        flags += line_flags(cmd)
        if re.search(r"(?:^|[\s=])/(?:tmp|dev/shm|var/tmp)/", cmd):
            flags.append("runs_from_temp")
    set_field(doc, "linuxconfig.flags", sorted(set(flags)))
    set_field(doc, "user.name", ctx.user_for(meta.get("path") or "") if origin == "user_home" else None)
    yield ["systemd-" + kind, rel], doc


# --------------------------------------------------------------------------- init scripts and profiles

def init_files(ctx):
    ev = ctx.ev
    out = []
    for path in ("etc/rc.local", "etc/rc.d/rc.local"):
        if ev.exists(ev.root_path(path)):
            out.append((ev.root_path(path), "rc.local"))
    init_names = set()
    init_rel = ev.root_path("etc/init.d")
    init_is_link = False
    if ctx.meta.has_bodyfile:
        e = ctx.meta.bodyfile_entry("/etc/init.d")
        init_is_link = bool(e and e.get("link"))
    elif not ev.is_zip:
        init_is_link = (ev.path / init_rel).is_symlink()
    for folder in (["etc/rc.d/init.d"] if init_is_link else ["etc/init.d", "etc/rc.d/init.d"]):
        for rel in walk(ev, ev.root_path(folder)):
            name = rel.rsplit("/", 1)[-1]
            if name in SKIP_NAMES or name in init_names or name.startswith("."):
                continue
            init_names.add(name)
            out.append((rel, "init.d"))
    # rc?.d entries whose script is not in init.d (an orphan start link is worth a look)
    for parent in ("etc", "etc/rc.d"):
        _, dirs = ev.listdir(ev.root_path(parent))
        for d in dirs:
            if re.fullmatch(r"rc[0-6S]\.d", d):
                for rel in walk(ev, ev.root_path(f"{parent}/{d}")):
                    name = rel.rsplit("/", 1)[-1]
                    base = re.sub(r"^[SK]\d\d", "", name)
                    if base not in init_names and name not in SKIP_NAMES:
                        out.append((rel, "rc_link"))
    for rel in walk(ev, ev.root_path("etc/local.d")):
        if rel.endswith((".start", ".stop")):
            out.append((rel, "local.d"))
    for path in SYSTEM_PROFILE_FILES:
        rel = ev.root_path(posixpath.normpath(path))
        if ev.exists(rel):
            out.append((rel, "environment" if path.endswith("environment") else "profile"))
    for folder in ("etc/profile.d",):
        for rel in walk(ev, ev.root_path(folder)):
            if rel.endswith((".sh", ".bash", ".zsh", ".local")) or "." not in rel.rsplit("/", 1)[-1]:
                out.append((rel, "profile"))
    for home in user_homes(ctx):
        for name in USER_PROFILE_FILES:
            rel = ev.root_path(posixpath.join(home.lstrip("/"), name))
            if ev.exists(rel) or (not ev.is_zip and (ev.path / rel).is_symlink()):
                out.append((rel, "user_profile"))
    seen = set()
    return [x for x in out if not (x[0] in seen or seen.add(x[0]))]


def user_homes(ctx):
    """Home folders: /root, every /home/* folder present, and homes from /etc/passwd."""
    ev = ctx.ev
    homes = {"/root"}
    _, dirs = ev.listdir(ev.root_path("home"))
    homes.update(f"/home/{d}" for d in dirs)
    for home, name in ctx.homes.items():
        if ev.is_dir(ev.root_path(home.lstrip("/"))):
            homes.add(home)
    return sorted(homes)


# --------------------------------------------------------------------------- XDG autostart

def parse_autostart(ctx, rel, report):
    lines = read_lines(ctx.ev, rel) or []
    entry, section = {}, None
    for line in lines:
        line = line.strip()
        if line.startswith("["):
            section = line
            continue
        if section == "[Desktop Entry]" and "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            entry.setdefault(k.strip(), v.strip())
    if not entry:
        yield None, "autostart file without a [Desktop Entry]"
        return
    doc = new_doc(ctx, "linux.autostart", "autostart", rel)
    a = "linuxconfig.autostart."
    set_field(doc, a + "name", entry.get("Name"))
    set_field(doc, "process.command_line", entry.get("Exec"))
    set_field(doc, "process.executable", entry.get("Exec", "").split()[0] if entry.get("Exec", "").split() else None)
    set_field(doc, a + "hidden", entry.get("Hidden", "").lower() == "true" if "Hidden" in entry else None)
    enabled = entry.get("X-GNOME-Autostart-enabled")
    set_field(doc, a + "enabled", enabled.lower() != "false" if enabled else None)
    set_field(doc, a + "only_show_in", [x for x in entry.get("OnlyShowIn", "").split(";") if x])
    set_field(doc, a + "not_show_in", [x for x in entry.get("NotShowIn", "").split(";") if x])
    set_field(doc, "user.name", ctx.user_for(doc.get("file", {}).get("path", "")))
    set_field(doc, "linuxconfig.flags", line_flags(entry.get("Exec", "")))
    yield ["autostart", rel], doc


# --------------------------------------------------------------------------- SSH keys

KEY_TYPE_RE = re.compile(r"^(?:ssh-(?:rsa|dss|ed25519|ed448)|ecdsa-sha2-nistp\d+|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)"
                         r"@openssh\.com|ssh-(?:rsa|ed25519|dss)-cert-v01@openssh\.com|"
                         r"ecdsa-sha2-nistp\d+-cert-v01@openssh\.com)$")


def split_options(text):
    """authorized_keys options: comma-separated, commas inside quotes kept."""
    out, buf, quote = [], "", False
    for ch in text:
        if ch == '"':
            quote = not quote
        if ch == "," and not quote:
            out.append(buf)
            buf = ""
        else:
            buf += ch
    if buf:
        out.append(buf)
    return out


def tokenize_key_line(line):
    """Split a key line on whitespace outside double quotes."""
    tokens, buf, quote = [], "", False
    for ch in line:
        if ch == '"':
            quote = not quote
        if ch in " \t" and not quote:
            if buf:
                tokens.append(buf)
                buf = ""
        else:
            buf += ch
    if buf:
        tokens.append(buf)
    return tokens


def fingerprint(b64):
    try:
        raw = base64.b64decode(b64, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def ssh_files(ctx):
    ev = ctx.ev
    out = []
    for home in user_homes(ctx):
        for name, kind in (("authorized_keys", "authorized_keys"), ("authorized_keys2", "authorized_keys"),
                           ("known_hosts", "known_hosts")):
            rel = ev.root_path(posixpath.join(home.lstrip("/"), ".ssh", name))
            if ev.exists(rel):
                out.append((rel, kind))
    rel = ev.root_path("etc/ssh/ssh_known_hosts")
    if ev.exists(rel):
        out.append((rel, "known_hosts"))
    return out


def parse_ssh(ctx, rel, kind, report):
    meta = ctx.meta.get(rel)
    user = ctx.user_for(meta.get("path") or "")
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tokens = tokenize_key_line(line)
        idx = next((i for i, t in enumerate(tokens) if KEY_TYPE_RE.match(t)), None)
        if idx is None or idx + 1 >= len(tokens):
            yield None, f"{kind} line without a recognised key"
            continue
        doc = new_doc(ctx, "linux.ssh_key", kind, rel, meta)
        k = "linuxconfig.ssh."
        set_field(doc, k + "key_type", tokens[idx])
        set_field(doc, k + "fingerprint", fingerprint(tokens[idx + 1]))
        set_field(doc, k + "comment", " ".join(tokens[idx + 2:]) or None)
        set_field(doc, "user.name", user)
        set_field(doc, "linuxconfig.line_number", number)
        flags = []
        if kind == "authorized_keys":
            options = split_options(" ".join(tokens[:idx])) if idx else []
            set_field(doc, k + "options", options)
            for opt in options:
                name, _, value = opt.partition("=")
                value = value.strip('"')
                if name.lower() == "command":
                    set_field(doc, k + "forced_command", value)
                    set_field(doc, "process.command_line", value)
                    flags += line_flags(value)
                elif name.lower() == "from":
                    set_field(doc, k + "from", [x for x in value.split(",") if x])
            if user == "root":
                flags.append("root_authorized_key")
        else:
            pre = tokens[:idx]
            marker = pre[0] if pre and pre[0].startswith("@") else None
            hosts_field = pre[-1] if pre and not pre[-1].startswith("@") else ""
            set_field(doc, k + "marker", marker)
            hashed = hosts_field.startswith("|1|")
            set_field(doc, k + "hashed", hashed)
            if not hashed:
                set_field(doc, k + "hosts", [h for h in hosts_field.split(",") if h])
        set_field(doc, "linuxconfig.flags", flags)
        yield ["ssh", rel, number, line], doc


# --------------------------------------------------------------------------- hosts, resolver, loader

def valid_ip(text):
    try:
        return str(ipaddress.ip_address(text.split("%", 1)[0]))
    except ValueError:
        return None


def parse_hosts(ctx, rel, report):
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = raw.strip()
        if not line:
            continue
        commented = line.startswith("#")
        body = line.lstrip("#").strip() if commented else line
        body = strip_comment(body)
        parts = body.split()
        if len(parts) < 2 or not valid_ip(parts[0]):
            if not commented:
                yield None, "hosts line that is not an entry"
            continue
        doc = new_doc(ctx, "linux.hosts", "entry", rel)
        add_line(doc, line, number)
        set_field(doc, "linuxconfig.hosts.ip", valid_ip(parts[0]))
        set_field(doc, "linuxconfig.hosts.names", parts[1:])
        set_field(doc, "linuxconfig.hosts.commented", commented)
        yield ["hosts", rel, number, line], doc


def parse_resolver(ctx, rel, report):
    resolved = rel.endswith(".conf") and "resolved.conf" in rel
    section = None
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = strip_comment(raw.strip()) if not raw.strip().startswith(";") else ""
        if not line:
            continue
        if resolved:
            if line.startswith("["):
                section = line
                continue
            if "=" not in line or section not in (None, "[Resolve]"):
                continue
            key, value = [x.strip() for x in line.split("=", 1)]
            values = value.split()
        else:
            parts = line.split()
            key, values = parts[0], parts[1:]
        doc = new_doc(ctx, "linux.resolver", "setting", rel)
        add_line(doc, raw.strip(), number)
        set_field(doc, "linuxconfig.resolver.directive", key)
        set_field(doc, "linuxconfig.resolver.values", values)
        if key.lower() in ("nameserver", "dns", "fallbackdns"):
            ips = [valid_ip(v.split("#", 1)[0].split(":53")[0]) for v in values]
            set_field(doc, "linuxconfig.resolver.servers", [ip for ip in ips if ip])
        yield ["resolver", rel, number, line], doc


def parse_ld(ctx, rel, report):
    preload = rel.endswith("ld.so.preload")
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = strip_comment(raw.strip())
        if not line:
            continue
        for entry in (line.split() if preload else [line]):
            kind = "preload" if preload else ("include" if entry.startswith("include ") else "library_path")
            doc = new_doc(ctx, "linux.ld_preload", kind, rel)
            add_line(doc, raw.strip(), number)
            set_field(doc, "linuxconfig.ld.entry", entry)
            if preload:
                set_field(doc, "linuxconfig.flags", ["ld_preload"])
            yield ["ld", rel, number, entry], doc


def ld_files(ev):
    out = []
    for path in ("etc/ld.so.preload", "etc/ld.so.conf"):
        if ev.exists(ev.root_path(path)):
            out.append(ev.root_path(path))
    out += [r for r in walk(ev, ev.root_path("etc/ld.so.conf.d")) if r.endswith(".conf")]
    return out


# --------------------------------------------------------------------------- repositories

def repo_doc(ctx, rel, number, manager, line=None):
    doc = new_doc(ctx, "linux.repository", "repository", rel)
    set_field(doc, "linuxconfig.repository.manager", manager)
    if line is not None:
        add_line(doc, line, number)
    else:
        set_field(doc, "linuxconfig.line_number", number)
    return doc


def set_url(doc, url):
    if not url:
        return
    set_field(doc, "url.original", url)
    try:
        parts = urlsplit(url)
    except ValueError:
        return
    set_field(doc, "url.scheme", parts.scheme or None)
    set_field(doc, "url.domain", parts.hostname)


APT_LINE_RE = re.compile(r"^(?P<type>deb|deb-src)\s+(?:\[(?P<opts>[^\]]*)\]\s+)?(?P<url>\S+)\s+(?P<suite>\S+)"
                         r"(?:\s+(?P<comps>.*))?$")


def parse_apt_list(ctx, rel, report):
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = raw.strip()
        commented = line.startswith("#")
        body = line.lstrip("#").strip()
        m = APT_LINE_RE.match(body)
        if not m:
            continue
        doc = repo_doc(ctx, rel, number, "apt", line)
        r = "linuxconfig.repository."
        set_field(doc, r + "type", m.group("type"))
        set_url(doc, m.group("url"))
        set_field(doc, r + "suites", [m.group("suite")])
        set_field(doc, r + "components", (m.group("comps") or "").split())
        set_field(doc, r + "enabled", not commented)
        opts = dict(o.split("=", 1) for o in (m.group("opts") or "").split() if "=" in o)
        set_field(doc, r + "signed_by", opts.get("signed-by"))
        set_field(doc, r + "trusted", opts.get("trusted", "").lower() == "yes" if "trusted" in opts else None)
        set_field(doc, r + "options", (m.group("opts") or "").split())
        if opts.get("trusted", "").lower() == "yes":
            set_field(doc, "linuxconfig.flags", ["unsigned_repository"])
        yield ["repo", rel, number, line], doc


def parse_deb822(ctx, rel, report):
    stanzas, cur, start = [], {}, None
    for number, raw in enumerate((read_lines(ctx.ev, rel) or []) + [""], 1):
        if raw.startswith("#"):
            continue
        if not raw.strip():
            if cur:
                stanzas.append((start, cur))
            cur, start = {}, None
            continue
        if raw[0] in " \t" and cur:
            continue  # continuation (e.g. an inline Signed-By key)
        k, _, v = raw.partition(":")
        if start is None:
            start = number
        cur[k.strip().lower()] = v.strip()
    for start, st in stanzas:
        for url in st.get("uris", "").split():
            doc = repo_doc(ctx, rel, start, "apt")
            r = "linuxconfig.repository."
            set_field(doc, r + "type", st.get("types"))
            set_url(doc, url)
            set_field(doc, r + "suites", st.get("suites", "").split())
            set_field(doc, r + "components", st.get("components", "").split())
            set_field(doc, r + "enabled", st.get("enabled", "yes").lower() != "no")
            signed = st.get("signed-by")
            set_field(doc, r + "signed_by", signed if signed and not signed.startswith("-----") else
                      ("inline key" if signed is not None else None))
            if "trusted" in st:
                set_field(doc, r + "trusted", st["trusted"].lower() == "yes")
                if st["trusted"].lower() == "yes":
                    set_field(doc, "linuxconfig.flags", ["unsigned_repository"])
            yield ["repo", rel, start, url], doc


def parse_ini_repo(ctx, rel, manager, report):
    sections, cur, start = [], None, None
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = {"_id": line[1:-1], "_urls": []}
            sections.append((number, cur))
            continue
        if cur is None:
            continue
        if "=" in line:
            k, v = [x.strip() for x in line.split("=", 1)]
            k = k.lower()
            cur[k] = v
            last = k
            if k in ("baseurl", "mirrorlist", "metalink"):
                cur["_urls"] += v.split()
        elif cur and last == "baseurl":
            cur["_urls"] += line.split()  # continuation lines of baseurl
    for number, sec in sections:
        if sec["_id"] == "main":
            continue
        doc = repo_doc(ctx, rel, number, manager)
        r = "linuxconfig.repository."
        set_field(doc, r + "id", sec["_id"])
        set_field(doc, r + "name", sec.get("name"))
        set_field(doc, r + "type", sec.get("type"))
        set_url(doc, sec["_urls"][0] if sec["_urls"] else None)
        set_field(doc, r + "urls", sec["_urls"])
        set_field(doc, r + "enabled", sec.get("enabled", "1").strip().lower() not in ("0", "no", "false"))
        if "gpgcheck" in sec:
            gpg = sec["gpgcheck"].strip().lower() not in ("0", "no", "false")
            set_field(doc, r + "gpgcheck", gpg)
            if not gpg:
                set_field(doc, "linuxconfig.flags", ["unsigned_repository"])
        set_field(doc, r + "signed_by", sec.get("gpgkey"))
        yield ["repo", rel, number, sec["_id"]], doc


def parse_apk_repos(ctx, rel, report):
    for number, raw in enumerate(read_lines(ctx.ev, rel) or [], 1):
        line = raw.strip()
        if not line:
            continue
        commented = line.startswith("#")
        body = line.lstrip("#").strip()
        tag = None
        m = re.match(r"^(@\S+)\s+(\S+)$", body)
        if m:
            tag, body = m.group(1), m.group(2)
        if not re.match(r"^(https?|ftp)://|^/", body):
            continue
        doc = repo_doc(ctx, rel, number, "apk", line)
        set_url(doc, body)
        set_field(doc, "linuxconfig.repository.id", tag)
        set_field(doc, "linuxconfig.repository.enabled", not commented)
        yield ["repo", rel, number, line], doc


def repo_files(ev):
    out = []
    if ev.exists(ev.root_path("etc/apt/sources.list")):
        out.append((ev.root_path("etc/apt/sources.list"), "apt_list"))
    for rel in walk(ev, ev.root_path("etc/apt/sources.list.d")):
        if rel.endswith(".list"):
            out.append((rel, "apt_list"))
        elif rel.endswith(".sources"):
            out.append((rel, "deb822"))
    for folder, manager in (("etc/yum.repos.d", "dnf"), ("etc/distro.repos.d", "dnf"), ("etc/zypp/repos.d", "zypper")):
        for rel in walk(ev, ev.root_path(folder)):
            if rel.endswith(".repo"):
                out.append((rel, manager))
    if ev.exists(ev.root_path("etc/apk/repositories")):
        out.append((ev.root_path("etc/apk/repositories"), "apk"))
    return out


# --------------------------------------------------------------------------- collect / parse

def collect(ev, profile, args):
    ctx = Context(ev, profile)
    collect.ctx = ctx
    meta = ctx.meta
    meta.want("/etc/", "/root/", "/home/", "/var/spool/", "/usr/lib/systemd/", "/lib/systemd/",
              "/usr/local/lib/systemd/", "/run/systemd/", "/lib")
    for home in ctx.homes:
        meta.want(home.rstrip("/") + "/")
    ctx.sudo_users, ctx.sudo_groups = sudo_principals(ev)
    items = []
    if ev.exists(ev.root_path("etc/passwd")):
        items.append(("accounts", ev.root_path("etc/passwd")))
    if ev.exists(ev.root_path("etc/group")):
        items.append(("groups", ev.root_path("etc/group")))
    items += [("sudoers", rel) for rel in sudoers_files(ev)]
    items += [("cron_table:" + flavour, rel) for rel, flavour in cron_tables(ev)]
    items += [("cron_script:" + period, rel) for rel, period in cron_scripts(ev)]
    items.append(("systemd", "systemd unit folders"))
    items += [("init:" + kind, rel) for rel, kind in init_files(ctx)]
    autostart = ["etc/xdg/autostart"] + [posixpath.join(h.lstrip("/"), ".config/autostart") for h in user_homes(ctx)]
    for folder in autostart:
        items += [("autostart", rel) for rel in walk(ev, ev.root_path(folder)) if rel.endswith(".desktop")]
    items += [("ssh:" + kind, rel) for rel, kind in ssh_files(ctx)]
    if ev.exists(ev.root_path("etc/hosts")):
        items.append(("hosts", ev.root_path("etc/hosts")))
    for path in ("etc/resolv.conf", "etc/systemd/resolved.conf"):
        if ev.exists(ev.root_path(path)):
            items.append(("resolver", ev.root_path(path)))
    items += [("resolver", rel) for rel in walk(ev, ev.root_path("etc/systemd/resolved.conf.d"))
              if rel.endswith(".conf")]
    items += [("ld", rel) for rel in ld_files(ev)]
    items += [("repo:" + kind, rel) for rel, kind in repo_files(ev)]
    return items


collect.ctx = None


def item_label(item):
    return f"{item[0]}: {item[1]}"


def parse(ev, profile, args, item, report):
    kind, rel = item
    ctx = collect.ctx
    head, _, sub = kind.partition(":")
    if head == "accounts":
        gen = parse_accounts(ctx, rel, report)
    elif head == "groups":
        gen = parse_groups(ctx, rel, report)
    elif head == "sudoers":
        gen = parse_sudoers(ctx, rel, report)
    elif head == "cron_table":
        gen = parse_cron_table(ctx, rel, sub, report)
    elif head == "cron_script":
        gen = script_lines(ctx, rel, "linux.cron", "script_line",
                           {"linuxconfig.cron.source": "at" if sub == "at" else "periodic",
                            "linuxconfig.cron.schedule": None if sub == "at" else sub}, "cron-script")
    elif head == "systemd":
        gen = parse_systemd(ctx, report)
    elif head == "init":
        gen = script_lines(ctx, rel, "linux.init_script", sub, {"linuxconfig.init.kind": sub}, "init")
    elif head == "autostart":
        gen = parse_autostart(ctx, rel, report)
    elif head == "ssh":
        gen = parse_ssh(ctx, rel, sub, report)
    elif head == "hosts":
        gen = parse_hosts(ctx, rel, report)
    elif head == "resolver":
        gen = parse_resolver(ctx, rel, report)
    elif head == "ld":
        gen = parse_ld(ctx, rel, report)
    elif sub == "apt_list":
        gen = parse_apt_list(ctx, rel, report)
    elif sub == "deb822":
        gen = parse_deb822(ctx, rel, report)
    elif sub in ("dnf", "zypper"):
        gen = parse_ini_repo(ctx, rel, sub, report)
    elif sub == "apk":
        gen = parse_apk_repos(ctx, rel, report)
    else:
        return
    root = ev.root.strip("/")
    for parts, doc in gen:
        if parts is None:
            yield None, doc
        elif "@timestamp" not in doc:
            yield None, "no timestamp (file modification time unknown)"
        else:
            # ids use host paths, so a zip and its extracted folder give the same _id
            yield [host_path(ev, p) if isinstance(p, str) and root and p.startswith(root + "/") else p
                   for p in parts], doc


LINUXCONFIG = LogSource("linuxconfig", "linuxconfig", DATASETS, collect, parse, item_label)


def main(argv=None):
    return run_sources([LINUXCONFIG], __doc__.split("\n\n")[0], argv)


if __name__ == "__main__":
    sys.exit(main())

"""Message-level parsing shared by the journal and text syslog importers.

enrich(doc, appname, message) adds structured fields for the messages that matter most in a
Linux investigation. Field names follow SOF-ELK's own Logstash parsers where it has one:

  sshd      6015-sshd.conf     ssh.auth_result, ssh.login_method, ssh.user_validity, user.name,
                               source.ip/port, ssh.version, ssh.key_type, ssh.key_id,
                               ssh.disconnect_code/statement, ssh.auth_reason,
                               ssh.source_kex_methods, destination.ip/port, event.auth_result
  PAM       6016-pam.conf      pam.module, pam.service, pam.sessiontype, pam.event, user.name, user.id
  iptables  6017-iptables.conf iptables.label, observer.ingress/egress.interface.name, source.mac,
                               destination.mac, iptables.ether_type, source/destination.ip/port,
                               iptables.ttl, network.transport, source.bytes, network.bytes
  kernel    1100-preprocess-syslog.conf  host.uptime from a leading "[ 12.345678]"

SOF-ELK has no parser for these, so the toolkit adds its own (ECS where ECS has a name):

  sudo / su / pkexec   user.name (who ran it), user.effective.name (as whom),
                       process.command_line, process.working_directory, sudo.tty / su.tty /
                       pkexec.tty, sudo.result / su.result / pkexec.result, event.outcome
  useradd / groupadd / usermod / userdel / groupdel / gpasswd / passwd / chpasswd / chage
                       event.action, user.target.name/id, group.name/id, account.home/shell/tty
  systemd-logind       logind.session_id, user.name, event.action (session-created/-removed)
  cron                 user.name, process.command_line, event.action cron-command

Each recognised message also gets event.category/type/action/outcome and a tag
(got_ssh, got_pam, got_sudo, got_su, got_pkexec, got_account, got_logind, got_cron,
got_iptables, kernel_module, usb_device).
"""
from __future__ import annotations

import ipaddress
import re


def _set(doc, dotted, value):
    if value is None or value == "" or value == []:
        return
    parts = dotted.split(".")
    for p in parts[:-1]:
        doc = doc.setdefault(p, {})
    doc[parts[-1]] = value


def _ip(value):
    try:
        return str(ipaddress.ip_address(value.strip("[]")))
    except (ValueError, AttributeError):
        return None


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _tag(doc, tag):
    tags = doc.setdefault("tags", [])
    if tag not in tags:
        tags.append(tag)


def _event(doc, category=None, etype=None, action=None, outcome=None):
    if category:
        _set(doc, "event.category", category)
    if etype:
        _set(doc, "event.type", etype)
    _set(doc, "event.action", action)
    _set(doc, "event.outcome", outcome)


# --------------------------------------------------------------------------- sshd

HOST = r"(?P<ip>[0-9A-Fa-f:.]+|\S+)"
SSH_PATTERNS = [
    ("login", re.compile(
        r"^(?P<result>Accepted|Failed) (?P<method>\S+) for (?:(?P<validity>invalid) user )?(?P<user>.*?) from "
        r"(?P<ip>\S+) port (?P<port>\d+)(?: (?P<version>ssh\d?))?(?:: (?P<keytype>\S+) (?P<keyid>.+))?$")),
    ("invalid-user", re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port (?P<port>\d+))?$")),
    ("connection-closed", re.compile(
        r"^Connection closed by (?:(?P<validity>invalid|authenticating) user (?P<user>.*?) )?(?P<ip>\S+)"
        r"(?: port (?P<port>\d+))?(?: \[preauth\])?$")),
    ("disconnected", re.compile(
        r"^Disconnected from (?:(?:(?P<validity>invalid|authenticating) )?user (?P<user>\S+) )?(?P<ip>\S+)"
        r" port (?P<port>\d+)(?: \[preauth\])?$")),
    ("received-disconnect", re.compile(
        r"^Received disconnect from (?P<ip>\S+?)(?: port (?P<port>\d+))?:\s*(?P<code>\d+):\s*(?P<statement>.*?)"
        r"(?: \[preauth\])?$")),
    ("connection", re.compile(
        r"^Connection from (?P<ip>\S+) port (?P<port>\d+) on (?P<dip>\S+) port (?P<dport>\d+)(?: rdomain \S*)?$")),
    ("negotiation-failed", re.compile(
        r"^Unable to negotiate with (?P<ip>\S+) port (?P<port>\d+): (?P<reason>.*?)\. Their offer: "
        r"(?P<offer>\S+)(?: \[preauth\])?$")),
    ("max-auth-tries", re.compile(
        r"^(?:error: )?maximum authentication attempts exceeded for (?:(?P<validity>invalid) user )?(?P<user>.*?)"
        r" from (?P<ip>\S+) port (?P<port>\d+)")),
    ("listening", re.compile(r"^Server listening on (?P<dip>\S+) port (?P<dport>\d+)\.?$")),
]
SSHD_NAMES = {"sshd", "sshd-session", "sshd-auth"}


def _ssh(doc, msg):
    for action, rx in SSH_PATTERNS:
        m = rx.match(msg)
        if not m:
            continue
        g = m.groupdict()
        ip = _ip(g.get("ip") or "")
        _set(doc, "source.ip", ip)
        if g.get("ip") and not ip:
            _set(doc, "source.address", g["ip"])
        _set(doc, "source.port", _int(g.get("port")))
        _set(doc, "user.name", g.get("user"))
        _set(doc, "ssh.user_validity", g.get("validity"))
        if action == "login":
            result = g["result"].lower()
            _set(doc, "ssh.auth_result", result)
            _set(doc, "event.auth_result", result)
            _set(doc, "ssh.login_method", g["method"])
            _set(doc, "ssh.version", g.get("version"))
            _set(doc, "ssh.key_type", g.get("keytype"))
            _set(doc, "ssh.key_id", g.get("keyid"))
            _event(doc, ["authentication"], ["start"] if result == "accepted" else ["info"],
                   "ssh-login", "success" if result == "accepted" else "failure")
        elif action in ("invalid-user", "max-auth-tries"):
            _set(doc, "ssh.user_validity", "invalid" if action == "invalid-user" else g.get("validity"))
            _event(doc, ["authentication"], ["info"], f"ssh-{action}", "failure")
        elif action == "received-disconnect":
            _set(doc, "ssh.disconnect_code", g.get("code"))
            _set(doc, "ssh.disconnect_statement", g.get("statement"))
            _event(doc, ["network"], ["end"], "ssh-received-disconnect")
        elif action in ("connection-closed", "disconnected"):
            _event(doc, ["network"], ["end"], f"ssh-{action}")
        elif action == "connection":
            _set(doc, "destination.ip", _ip(g["dip"]))
            _set(doc, "destination.port", _int(g["dport"]))
            _event(doc, ["network"], ["start"], "ssh-connection")
        elif action == "negotiation-failed":
            _set(doc, "ssh.auth_reason", g.get("reason"))
            _set(doc, "ssh.source_kex_methods", [x for x in g["offer"].split(",") if x])
            _event(doc, ["network"], ["denied"], "ssh-negotiation-failed", "failure")
        elif action == "listening":
            _set(doc, "destination.ip", _ip(g["dip"]))
            _set(doc, "destination.port", _int(g["dport"]))
            _event(doc, ["network"], ["info"], "ssh-listening")
        _tag(doc, "got_ssh")
        return True
    return False


# --------------------------------------------------------------------------- PAM

PAM_RE = re.compile(r"^(?P<module>pam_[A-Za-z0-9_]+)\((?P<service>[^:()]*):(?P<stype>[A-Za-z]+)\): (?P<rest>.*)$")
PAM_SESSION_RE = re.compile(
    r"^session (?P<event>opened|closed) for user (?P<user>[^\s(]+)(?:\(uid=(?P<uid>\d+)\))?"
    r"(?: by (?P<by>[^\s(]*)\(uid=(?P<byuid>\d+)\))?")
PAM_ERRUSER_RE = re.compile(r"^error retrieving information about user (?P<user>\S+)")
PAM_AUTHFAIL_RE = re.compile(r"^authentication failure;(?P<kv>.*)$")
PAM_CHECKPASS_RE = re.compile(r"^check pass; user unknown$")
PAM_PASSWD_RE = re.compile(r"^password changed for (?P<user>\S+)$")
KV_RE = re.compile(r"(\w+)=(\S*)")


def _pam(doc, msg):
    m = PAM_RE.match(msg)
    if not m:
        return False
    _set(doc, "pam.module", m.group("module"))
    _set(doc, "pam.service", m.group("service"))
    _set(doc, "pam.sessiontype", m.group("stype"))
    rest = m.group("rest")
    s = PAM_SESSION_RE.match(rest)
    if s:
        _set(doc, "pam.event", s.group("event"))
        _set(doc, "user.name", s.group("user"))
        _set(doc, "user.id", s.group("uid") or (s.group("byuid") if not s.group("by") else None))
        _set(doc, "pam.by_user", s.group("by"))
        _set(doc, "pam.by_uid", s.group("byuid"))
        _event(doc, ["session"], ["start" if s.group("event") == "opened" else "end"],
               f"session-{s.group('event')}")
    elif PAM_AUTHFAIL_RE.match(rest):
        kv = dict(KV_RE.findall(PAM_AUTHFAIL_RE.match(rest).group("kv")))
        _set(doc, "pam.event", "authentication_failure")
        _set(doc, "pam.logname", kv.get("logname"))
        _set(doc, "pam.ruser", kv.get("ruser"))
        _set(doc, "pam.rhost", kv.get("rhost"))
        _set(doc, "pam.tty", kv.get("tty"))
        _set(doc, "user.id", kv.get("uid"))
        _set(doc, "user.effective.id", kv.get("euid"))
        _set(doc, "user.target.name", kv.get("user"))
        ip = _ip(kv.get("rhost") or "")
        _set(doc, "source.ip", ip)
        _event(doc, ["authentication"], ["info"], "authentication-failure", "failure")
    elif PAM_PASSWD_RE.match(rest):
        _set(doc, "pam.event", "password_changed")
        _set(doc, "user.target.name", PAM_PASSWD_RE.match(rest).group("user"))
        _event(doc, ["iam"], ["user", "change"], "password-changed", "success")
    elif PAM_ERRUSER_RE.match(rest):
        _set(doc, "user.name", PAM_ERRUSER_RE.match(rest).group("user"))
    elif PAM_CHECKPASS_RE.match(rest):
        _set(doc, "pam.event", "user_unknown")
        _event(doc, ["authentication"], ["info"], "authentication-failure", "failure")
    _tag(doc, "got_pam")
    return True


# --------------------------------------------------------------------------- sudo / su / pkexec

SUDO_RE = re.compile(r"^\s*(?P<user>[^\s:]+) : (?P<body>.*)$")
SUDO_FAIL = ("incorrect password attempt", "user NOT in sudoers", "command not allowed",
             "a password is required", "user NOT authorized on host", "unknown user", "authentication failure")


def _sudo(doc, msg):
    m = SUDO_RE.match(msg)
    if not m or not re.search(r"\b(?:TTY|PWD|USER|COMMAND)=", m.group("body")):
        return False
    parts = [p.strip() for p in m.group("body").split(" ; ")]
    result = "allowed"
    kv = {}
    command = None
    for i, part in enumerate(parts):
        if part.startswith("COMMAND="):
            command = " ; ".join(parts[i:])[len("COMMAND="):]
            break
        key, sep, value = part.partition("=")
        if sep and re.fullmatch(r"[A-Z]+", key):
            kv[key] = value
        else:
            result = part
    _set(doc, "user.name", m.group("user"))
    _set(doc, "sudo.tty", kv.get("TTY"))
    _set(doc, "process.working_directory", kv.get("PWD"))
    _set(doc, "user.effective.name", kv.get("USER"))
    _set(doc, "group.name", kv.get("GROUP"))
    _set(doc, "sudo.env", kv.get("ENV"))
    _set(doc, "process.command_line", command)
    _set(doc, "sudo.result", result)
    failed = result != "allowed"
    _event(doc, ["process"] if not failed else ["authentication"], ["start"] if not failed else ["denied"],
           "sudo-command", "failure" if failed else "success")
    _tag(doc, "got_sudo")
    return True


SU_RE = re.compile(r"^(?P<fail>FAILED SU|FAILED su(?: for \S+ by \S+)?)?\s*\(to (?P<target>[^)]+)\) (?P<user>\S+) on "
                   r"(?P<tty>\S+)$")
SU_FAIL2_RE = re.compile(r"^FAILED su for (?P<target>\S+) by (?P<user>\S+)$")
SU_OK2_RE = re.compile(r"^Successful su for (?P<target>\S+) by (?P<user>\S+)$")


def _su(doc, msg):
    m = SU_RE.match(msg)
    if m:
        failed = bool(m.group("fail"))
        _set(doc, "user.name", m.group("user"))
        _set(doc, "user.effective.name", m.group("target"))
        _set(doc, "su.tty", m.group("tty"))
    else:
        m = SU_FAIL2_RE.match(msg) or SU_OK2_RE.match(msg)
        if not m:
            return False
        failed = msg.startswith("FAILED")
        _set(doc, "user.name", m.group("user"))
        _set(doc, "user.effective.name", m.group("target"))
    _set(doc, "su.result", "failed" if failed else "success")
    _event(doc, ["authentication"], ["start"] if not failed else ["denied"], "su",
           "failure" if failed else "success")
    _tag(doc, "got_su")
    return True


PKEXEC_RE = re.compile(r"^(?P<user>[^\s:]+): (?P<result>Executing command|Error executing command as another user:"
                       r" .*?) \[USER=(?P<target>[^\]]*)\] \[TTY=(?P<tty>[^\]]*)\] \[CWD=(?P<cwd>[^\]]*)\]"
                       r" \[COMMAND=(?P<cmd>.*)\]$")


def _pkexec(doc, msg):
    m = PKEXEC_RE.match(msg)
    if not m:
        return False
    failed = not m.group("result").startswith("Executing")
    _set(doc, "user.name", m.group("user"))
    _set(doc, "user.effective.name", m.group("target"))
    _set(doc, "pkexec.tty", m.group("tty"))
    _set(doc, "process.working_directory", m.group("cwd"))
    _set(doc, "process.command_line", m.group("cmd"))
    _set(doc, "pkexec.result", "allowed" if not failed else m.group("result").split(": ", 1)[-1])
    _event(doc, ["process"] if not failed else ["authentication"], ["start"] if not failed else ["denied"],
           "pkexec-command", "failure" if failed else "success")
    _tag(doc, "got_pkexec")
    return True


# --------------------------------------------------------------------------- account management

ACCOUNT_PATTERNS = [
    ("user-created", re.compile(r"^new user: name=(?P<name>[^,]+), UID=(?P<uid>\d+), GID=(?P<gid>\d+),"
                                r" home=(?P<home>[^,]*), shell=(?P<shell>[^,]*)(?:, from=(?P<tty>\S+))?")),
    ("group-created", re.compile(r"^new group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")),
    ("group-created", re.compile(r"^group added to /etc/group: name=(?P<group>[^,]+), GID=(?P<gid>\d+)")),
    ("user-deleted", re.compile(r"^delete user '(?P<name>[^']+)'")),
    ("group-deleted", re.compile(r"^(?:removed group|group) '(?P<group>[^']+)'(?: removed)?(?: owned by '[^']*')?$")),
    ("group-membership-added", re.compile(r"^add '(?P<name>[^']+)' to (?:shadow )?group '(?P<group>[^']+)'")),
    ("group-membership-added", re.compile(r"^(?:user )?(?P<name>\S+) added by \S+ to group (?P<group>\S+)$")),
    ("group-membership-removed", re.compile(r"^delete '(?P<name>[^']+)' from (?:shadow )?group '(?P<group>[^']+)'")),
    ("group-membership-removed", re.compile(r"^(?:user )?(?P<name>\S+) removed by \S+ from group (?P<group>\S+)$")),
    ("user-changed", re.compile(r"^change user '(?P<name>[^']+)' (?P<what>.*)$")),
    ("password-changed", re.compile(r"^password (?:for '(?P<name>[^']+)' )?changed(?: by '[^']*')?(?: for (?P<name2>\S+))?")),
    ("user-locked", re.compile(r"^lock user '(?P<name>[^']+)' password")),
    ("password-aging-changed", re.compile(r"^changed password expiry for (?P<name>\S+)")),
]
ACCOUNT_TOOLS = {"useradd", "groupadd", "usermod", "userdel", "groupdel", "groupmod", "gpasswd", "passwd",
                 "chpasswd", "chage", "adduser", "deluser", "addgroup", "delgroup", "newusers"}


def _account(doc, msg):
    for action, rx in ACCOUNT_PATTERNS:
        m = rx.match(msg)
        if not m:
            continue
        g = m.groupdict()
        _set(doc, "user.target.name", g.get("name") or g.get("name2"))
        _set(doc, "user.target.id", g.get("uid"))
        _set(doc, "group.name", g.get("group"))
        _set(doc, "group.id", g.get("gid"))
        _set(doc, "account.home", g.get("home"))
        _set(doc, "account.shell", g.get("shell"))
        _set(doc, "account.tty", g.get("tty"))
        etype = (["creation"] if "created" in action or "added" in action
                 else ["deletion"] if "deleted" in action or "removed" in action else ["change"])
        etype = (["group"] if action.startswith("group") else ["user"]) + etype
        _event(doc, ["iam"], etype, action, "success")
        _tag(doc, "got_account")
        return True
    return False


# --------------------------------------------------------------------------- logind, cron

LOGIND_NEW_RE = re.compile(r"^New session (?P<sid>\S+) of user (?P<user>[^\s.]+)\.?$")
LOGIND_REMOVED_RE = re.compile(r"^Removed session (?P<sid>[^\s.]+)\.?$")
LOGIND_LOGOUT_RE = re.compile(r"^Session (?P<sid>\S+) logged out\.")


def _logind(doc, msg):
    m = LOGIND_NEW_RE.match(msg)
    if m:
        _set(doc, "logind.session_id", m.group("sid"))
        _set(doc, "user.name", m.group("user"))
        _event(doc, ["session"], ["start"], "session-created")
    else:
        m = LOGIND_REMOVED_RE.match(msg) or LOGIND_LOGOUT_RE.match(msg)
        if not m:
            return False
        _set(doc, "logind.session_id", m.group("sid"))
        _event(doc, ["session"], ["end"], "session-removed" if msg.startswith("Removed") else "session-logged-out")
    _tag(doc, "got_logind")
    return True


CRON_RE = re.compile(r"^\((?P<user>[^)]+)\) CMD \((?P<cmd>.*)\)\s*$")


def _cron(doc, msg):
    m = CRON_RE.match(msg)
    if not m:
        return False
    _set(doc, "user.name", m.group("user"))
    _set(doc, "process.command_line", m.group("cmd").strip())
    _event(doc, ["process"], ["start"], "cron-command")
    _tag(doc, "got_cron")
    return True


# --------------------------------------------------------------------------- kernel

UPTIME_RE = re.compile(r"^\[\s*(\d+\.\d+)\]:?\s?(.*)$", re.DOTALL)
IPTABLES_RE = re.compile(
    r"^(?:(?P<label>.*?):? )?IN=(?P<in>\S*) OUT=(?P<out>\S*) (?:MAC=(?P<mac>\S*) )?SRC=(?P<src>\S+) DST=(?P<dst>\S+)"
    r"(?P<rest>.*)$")
IPT_KV_RE = re.compile(r"\b([A-Z]+)=(\S*)")
MODULE_RE = re.compile(r"(module verification failed|taints kernel|loading out-of-tree module|"
                       r"module license '[^']*' taints kernel|unsigned module|tainting kernel)", re.IGNORECASE)
USB_RE = re.compile(r"^usb \S+: (New USB device found|Product:|Manufacturer:|SerialNumber:)|usb-storage|"
                    r"^sd \S+: \[sd[a-z]+\] Attached SCSI removable disk")


def _kernel(doc, msg):
    m = UPTIME_RE.match(msg)
    if m:
        try:
            doc.setdefault("host", {})["uptime"] = float(m.group(1))
        except ValueError:
            pass
        msg = m.group(2)
        doc["message"] = msg
    m = IPTABLES_RE.match(msg)
    if m:
        kv = dict(IPT_KV_RE.findall(m.group("rest")))
        label = (m.group("label") or "").strip().strip("[]").strip() or None
        _set(doc, "iptables.label", label)
        _set(doc, "observer.ingress.interface.name", m.group("in"))
        _set(doc, "observer.egress.interface.name", m.group("out"))
        mac = m.group("mac") or ""
        if mac.count(":") >= 13:
            octets = mac.split(":")
            _set(doc, "destination.mac", "-".join(octets[0:6]).upper())
            _set(doc, "source.mac", "-".join(octets[6:12]).upper())
            _set(doc, "iptables.ether_type", ":".join(octets[12:]))
        _set(doc, "source.ip", _ip(m.group("src")))
        _set(doc, "destination.ip", _ip(m.group("dst")))
        _set(doc, "iptables.ttl", _int(kv.get("TTL")))
        _set(doc, "network.transport", (kv.get("PROTO") or "").lower() or None)
        _set(doc, "source.port", _int(kv.get("SPT")))
        _set(doc, "destination.port", _int(kv.get("DPT")))
        length = _int(kv.get("LEN"))
        _set(doc, "source.bytes", length)
        _set(doc, "network.bytes", length)
        action = None
        if label:
            low = label.lower()
            action = ("firewall-block" if any(w in low for w in ("block", "drop", "reject", "deny"))
                      else "firewall-allow" if any(w in low for w in ("allow", "accept")) else "firewall-log")
        _event(doc, ["network"], ["connection"], action or "firewall-log")
        _tag(doc, "got_iptables")
        return True
    if MODULE_RE.search(msg):
        _event(doc, ["driver"], ["info"], "kernel-module-warning")
        _tag(doc, "kernel_module")
        return True
    if USB_RE.search(msg):
        _event(doc, ["host"], ["info"], "usb-device")
        _tag(doc, "usb_device")
        return True
    return False


# --------------------------------------------------------------------------- entry point

def enrich(doc, appname, message):
    """Add structured fields for a known message. Returns True when something matched."""
    if not message:
        return False
    app = (appname or "").strip()
    low = app.lower()
    if low == "kernel":
        return _kernel(doc, message)
    if message.startswith("pam_"):
        return _pam(doc, message)
    if low in SSHD_NAMES:
        return _ssh(doc, message)
    if low == "sudo":
        return _sudo(doc, message)
    if low == "su":
        return _su(doc, message)
    if low == "pkexec":
        return _pkexec(doc, message)
    if low in ACCOUNT_TOOLS:
        return _account(doc, message)
    if low == "systemd-logind":
        return _logind(doc, message)
    if low in ("cron", "crond", "anacron"):
        return _cron(doc, message)
    if "IN=" in message and "SRC=" in message:
        return _kernel(doc, message)
    return False

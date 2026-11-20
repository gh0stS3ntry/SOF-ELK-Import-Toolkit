#!/usr/bin/env python3
"""Build the LOLRMM hunting queries from the LOLRMM catalog (standard library only).

LOLRMM (https://lolrmm.io, Apache 2.0) catalogs remote monitoring and management (RMM) and
remote-access tools with their executables, install paths, services, registry keys, files and
network domains. This script turns that catalog into the RMM queries of the hunting pack:

  1. extract: read rmm_tools.json (from lolrmm.io, its GitHub mirror, or a local file) and
     reduce it to the indicators the toolkit's evidence can show, applying LOLRMM's own
     detection-generation safety rules (no generic process names without a directory, no
     extension-only or catch-all globs, no shared hosting or public-suffix domains, no records
     marked Detection: false). The result is hunting/intel/lolrmm/indicators.json, and the
     source file's SHA-256 and per-tool LastModified dates go to source.json;
  2. render: write each LOLRMM query.esql from indicators.json and the templates below.

Usage:
    python3 hunting/tools/lolrmm.py                    # fetch, extract, render, report changes
    python3 hunting/tools/lolrmm.py --check            # fetch and report only; exit 10 if the
                                                       # hunting indicators changed, else 0
    python3 hunting/tools/lolrmm.py --source FILE      # use a downloaded rmm_tools.json
    python3 hunting/tools/lolrmm.py --render-only      # rewrite the queries from the stored
                                                       # indicators.json (after a template edit)

Then run hunting/tools/check_queries.py and LuceneRegexCheck.java as for any query edit.
Edit the templates in this file, never the generated query.esql files.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
PACK = HERE.parent
INTEL = PACK / "intel" / "lolrmm"
INDICATORS = INTEL / "indicators.json"
SOURCE = INTEL / "source.json"
WIN_C2 = PACK / "queries" / "windows" / "TA0011-command-and-control"
LINUX_C2 = PACK / "queries" / "linux" / "TA0011-command-and-control"

# lolrmm.io publishes the files the GitHub repository's website build commits; the mirror is
# used when the site cannot be reached (some egress proxies only allow GitHub).
SOURCE_URLS = (
    "https://lolrmm.io/api/rmm_tools.json",
    "https://raw.githubusercontent.com/magicsword-io/LOLRMM/main/website/public/api/rmm_tools.json",
)

# ----------------------------------------------------------------------------- safety lists
# LOLRMM PROC-SCOPE-001 names svchost.exe, agent.exe and installer.exe; the rest are names that
# many unrelated products (or Windows itself) use. They are kept only with their directory.
GENERIC_EXE = {
    "agent.exe", "installer.exe", "svchost.exe", "setup.exe", "install.exe", "client.exe",
    "server.exe", "service.exe", "update.exe", "updater.exe", "launcher.exe", "helper.exe",
    "uninstall.exe", "uninst.exe", "unins000.exe", "main.exe", "app.exe", "run.exe", "start.exe",
    "tray.exe", "monitor.exe", "host.exe", "remote.exe", "support.exe", "viewer.exe", "cmd.exe",
    "powershell.exe", "pwsh.exe", "rundll32.exe", "msiexec.exe", "conhost.exe", "explorer.exe",
    "python.exe", "pythonw.exe", "java.exe", "javaw.exe", "node.exe", "wscript.exe",
    "cscript.exe", "dllhost.exe", "regsvr32.exe", "perl.exe", "ssh.exe", "sshd.exe", "curl.exe",
    "tunnel.exe", "proxy.exe", "watchdog.exe", "worker.exe", "daemon.exe", "core.exe",
    "console.exe", "manager.exe", "notifier.exe", "sc.exe", "net.exe", "reg.exe", "regedit.exe",
    "schtasks.exe", "taskkill.exe", "netsh.exe", "bash.exe", "wsl.exe", "electron.exe",
    "openssl.exe", "7z.exe", "unzip.exe", "plugin.exe", "connect.exe", "session.exe",
    "rdpclip.exe", "winlogon.exe", "lsass.exe", "services.exe", "csrss.exe", "smss.exe",
    "taskhostw.exe", "sihost.exe", "ctfmon.exe", "spoolsv.exe", "dwm.exe", "tar.exe",
    "winword.exe", "excel.exe", "chrome.exe", "msedge.exe", "firefox.exe", "notepad.exe",
}
# words that do not name a product inside a file-name glob (agent-*.exe, agentsetup-*.exe)
GENERIC_GLOB_WORDS = ("agent", "setup", "installer", "install", "windows", "win64", "win32",
                      "amd64", "x64", "x86", "client", "service", "update", "launcher", "portable")
# Windows' own remote-access programs: kept (LOLRMM PROC-SCOPE-004), but they run on most hosts,
# so the queries score them low.
BUILTIN_EXE = {"mstsc.exe", "msra.exe", "quickassist.exe", "rdpinit.exe", "rdpshell.exe",
               "tscon.exe", "mobsync.exe"}
EXE_EXT = (".exe", ".scr", ".com", ".cpl")
FILE_EXT_RE = (r"\.(exe|dll|sys|log|txt|json|conf|config|ini|xml|ya?ml|db|dat|toml|ps1|bat|cmd|vbs|"
               r"js|msi|zip|lnk|reg|cfg|py|sh|plist|crt|pem|key|sqlite3?|jar|ico|png|cab|tmp|bin|"
               r"scr|cpl|ocx|rdp|pfx|cer|exe\*|log\*)$")
# folder names that say nothing about a product: a path or registry pattern needs at least one
# segment outside this list
GENERIC_DIRS = {
    "", "c:", "windows", "system32", "syswow64", "sysnative", "drivers", "program files",
    "program files (x86)", "programdata", "users", "appdata", "local", "roaming", "locallow",
    "temp", "tmp", "downloads", "desktop", "documents", "public", "default", "common files",
    "microsoft", "bin", "lib", "app", "apps", "data", "logs", "log", "config", "files", "x64",
    "x86", "start menu", "programs", "startup", "tasks", "windows defender", "opt", "usr",
    "etc", "var", "home", "root", "share", "sbin", "srv", "run", "systemd", "system", "user",
    "~", "library", "application support", "applications", "agent", "agents", "client",
    "service", "server", "software", "wow6432node", "currentcontrolset", "controlset001",
    "control", "services", "classes", "currentversion", "uninstall", "policies", "run",
    "runonce", "lsa", "safeboot", "network", "minimal", "explorer", "shell", "open", "command",
    "appid", "clsid", "tracing", "print", "printers", "windows nt", "environment", "setup",
    "parameters", "security", "update", "updates", "cache", "plugins", "resources", "temp1",
    ".config", ".local", ".cache", "lib64", "include", "libexec", "init.d", "log", "logs",
}
# multi-label public suffixes (a pinned, partial copy of the ICANN section of the PSL)
PUBLIC_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "com.br",
    "net.br", "com.cn", "net.cn", "org.cn", "co.jp", "ne.jp", "or.jp", "co.kr", "co.nz",
    "com.tw", "com.hk", "co.in", "co.za", "com.mx", "com.sg", "com.tr", "com.ar", "com.my",
    "co.id", "com.vn", "com.ua", "com.pl", "co.il", "com.ru", "com.co", "com.pe", "co.th",
}
# shared hosting and platform domains: a hostname under them names a tenant, not a tool. The
# value is how many labels a tenant hostname must add (bucket.s3.region.amazonaws.com = 3).
SHARED_DOMAINS = {
    "amazonaws.com": 3, "cloudfront.net": 1, "azurewebsites.net": 1, "azureedge.net": 1,
    "windows.net": 2, "cloudapp.net": 1, "azure.com": 2, "trafficmanager.net": 1,
    "herokuapp.com": 1, "web.app": 1, "firebaseapp.com": 1, "appspot.com": 1,
    "github.com": 9, "githubusercontent.com": 9, "github.io": 1, "gitlab.com": 9, "ghcr.io": 9,
    "docker.io": 9, "docker.com": 9, "cloudflarestorage.com": 2, "workers.dev": 1,
    "pages.dev": 1, "cloudflare.com": 1, "cloudflare.net": 9, "akamaized.net": 9,
    "akamaiedge.net": 9, "akamai.net": 9, "edgekey.net": 9, "edgesuite.net": 9,
    "fastly.net": 9, "googleapis.com": 2, "gstatic.com": 9, "google.com": 1,
    "googleusercontent.com": 9, "microsoft.com": 1, "live.com": 1, "office.com": 1,
    "office365.com": 1, "apple.com": 1, "icloud.com": 9, "amazon.com": 1,
    "digitaloceanspaces.com": 1, "sourceforge.net": 9, "dropbox.com": 9,
    "dropboxusercontent.com": 9, "stunprotocol.org": 9, "npmjs.org": 9, "pypi.org": 9,
    "msedge.net": 9, "windowsupdate.com": 9, "digicert.com": 9, "sectigo.com": 9,
    "letsencrypt.org": 9, "verisign.com": 9, "globalsign.com": 9, "ipify.org": 9,
}
GENERIC_SERVICES = {"agent", "service", "client", "server", "update", "updater", "monitor",
                    "helper", "remote", "support", "tunnel", "proxy", "watchdog", "rmm"}
GENERIC_LINUX_NAMES = {"manager", "agent", "server", "client", "daemon", "service", "update",
                       "updater", "helper", "run", "start", "main", "app", "node", "python",
                       "python3", "java", "bash", "sh", "perl", "tunnel", "proxy", "watchdog",
                       "credentials", "config", "install", "install.sh", "uninstall", "worker",
                       "installer", "agentservice", "commandprocessor", "desktop", "launcher"}
SERVICE_TYPES = re.compile(r"(?i)^(windows ?)?(observed|default|reported|documented)?"
                           r"(windows)?(campaign)?service(name|displayname)?(fromcode)?$|"
                           r"^(windows )?service name$|^windowsservice$|^defaultwindowsservicename$|"
                           r"^(default)?servicedisplayname(fromcode)?$|^servicenamepattern$")
TASK_TYPES = re.compile(r"(?i)^(windows)?scheduledtask(name)?$")
UNIT_TYPES = re.compile(r"(?i)^(linux ?systemd ?(unit|service(name)?)|documentedlinuxservicename|"
                        r"optionalsystemdservicename|linuxservice|linux systemd service)$")
HASH_TYPE = re.compile(r"(?i)sha256|sha1|authentihash")

ENV_VARS = {
    "%programdata%": "*\\programdata", "%allusersprofile%": "*\\programdata",
    "%appdata%": "*\\appdata\\roaming", "%localappdata%": "*\\appdata\\local",
    "%userprofile%": "*\\users\\*", "%homepath%": "*\\users\\*", "%public%": "*\\users\\public",
    "%temp%": "*\\temp", "%tmp%": "*\\temp", "%windir%": "*\\windows",
    "%systemroot%": "*\\windows", "\\systemroot": "*\\windows",
    "%programfiles%": "*\\program files", "%programfiles(x86)%": "*\\program files (x86)",
    "%programw6432%": "*\\program files", "%commonprogramfiles%": "*\\program files\\common files",
    "%systemdrive%": "*",
}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def clean(s) -> str:
    s = str(s or "").strip().strip('"').strip("'").strip()
    s = re.sub(r"\\{2,}", r"\\", s)
    return s


def first_name(value: str) -> str:
    """'Rd_Service; vendor-documented as ...' -> 'Rd_Service'; 'MSPAgent (display name X)' -> 'MSPAgent'."""
    v = clean(value).split(";")[0]
    v = re.sub(r"\s+\((?![*<])[^)]*\)$", "", v)
    return v.strip()


def segments_specific(segs) -> bool:
    for s in segs:
        s = s.strip().lower()
        fixed = s.replace("*", "").replace("?", "")
        if len(fixed) >= 3 and s not in GENERIC_DIRS and fixed not in GENERIC_DIRS \
                and not re.fullmatch(r"[0-9._-]+|v?[0-9.]+", fixed):
            return True
    return False


# ----------------------------------------------------------------------------- Windows paths
def win_glob(path: str) -> str | None:
    """Turn a Windows path from the catalog into a lower-case LIKE glob (single backslashes)."""
    p = clean(path).lower().replace("/", "\\")
    if not p or "\\" not in p and not p.startswith("%"):
        return None
    for k, v in ENV_VARS.items():
        if p.startswith(k):
            p = v + p[len(k):]
    p = re.sub(r"%[a-z0-9_()]+%", "*", p)
    p = re.sub(r"<[^>]*>", "*", p)
    p = re.sub(r"\{sid\}|\{user(name)?\}|\{version\}", "*", p)
    p = re.sub(r"^[a-z]:", "*", p)
    p = re.sub(r"^\\\\\?\\[a-z]:", "*", p)
    if not p.startswith("*"):
        p = "*" + (p if p.startswith("\\") else "\\" + p)
    p = re.sub(r"\*{2,}", "*", p).rstrip("\\")
    if p.endswith("\\*"):
        pass
    elif not re.search(r"\.[a-z0-9]{1,5}\*?$", p.rsplit("\\", 1)[-1]):
        p += "\\*"                                  # a folder: anything inside it
    segs = p.split("\\")
    base = segs[-1]
    if not segments_specific(segs[:-1]):
        # no product folder: only a specific file name keeps the pattern
        if base in ("*", "") or base.startswith("*.") or base in GENERIC_EXE:
            return None
        # a lone file name must be a distinctive program name (not openssh.msi, config.json)
        if not segments_specific([base]) or not any(exe_name_of(base)):
            return None
    if base.startswith("*.") and not segments_specific(segs[:-1]):
        return None
    return p


def exe_name_of(path: str) -> tuple[str | None, str | None]:
    """(exact name, name glob) for a Windows executable path or bare file name."""
    base = clean(path).replace("/", "\\").split("\\")[-1].lower().strip()
    base = re.sub(r"<[^>]*>", "*", base)
    if not base.endswith(EXE_EXT) and not re.search(r"\.exe\*?$", base):
        return None, None
    if "*" in base or "?" in base:
        if "[" in base:
            return None, None
        stem = re.sub(r"[^a-z0-9]", "", base.rsplit(".", 1)[0])
        for w in GENERIC_GLOB_WORDS:
            stem = stem.replace(w, "")
        return (None, base) if len(stem) >= 4 else (None, None)
    # names of three letters or fewer (rd.exe, si.exe, g2m.exe) are kept only with their folder
    if base in GENERIC_EXE or len(base.rsplit(".", 1)[0]) < 4:
        return None, None
    return base, None


def image_from_command(cmd: str) -> str | None:
    """The program path at the start of a service ImagePath or command line."""
    c = clean(cmd)
    m = re.match(r'^"?([^"]*?\.(exe|sys|dll|bat|cmd|ps1|vbs|js))\b', c, re.I)
    return m.group(1) if m else None


# ----------------------------------------------------------------------------- other kinds
def registry_globs(key: str) -> list[str]:
    k = clean(key).lower().replace("/", "\\")
    k = re.sub(r"^(hkey_local_machine|hklm)\\(software\\)?", "", k)
    k = re.sub(r"^(hkey_current_user|hkcu)\\", "", k)
    k = re.sub(r"^(hkey_users|hku)\\[^\\]+\\", "", k)
    k = re.sub(r"^system\\(currentcontrolset|controlset00[0-9])\\", "", k)
    k = re.sub(r"(^|\\)wow6432node(?=\\|$)", "", k).strip("\\")
    k = re.sub(r"<[^>]*>|\{sid\}", "*", k)
    k = re.sub(r"\*{2,}", "*", k)
    if not k or not segments_specific(k.split("\\")):
        return []
    if k.endswith("*"):
        return ["*\\" + k]
    return ["*\\" + k, "*\\" + k + "\\*"]


def domain_entry(raw: str):
    """('suffix', d) for a domain matched with its subdomains, ('glob', g), ('ip', a) or None."""
    d = clean(raw).lower()
    d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split("?")[0]
    d = re.sub(r":\d+$", "", d).strip(".")
    if not d or "<" in d or "user_managed" in d or " " in d:
        return None
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", d):
        return ("ip", d)
    if not re.fullmatch(r"[a-z0-9*_.-]+", d) or "." not in d:
        return None
    if d.startswith("*."):
        d = d[2:]
    if "*" in d:
        tail = d.rsplit("*", 1)[1].lstrip(".-")
        if not domain_ok(tail.split(".", 1)[1] if tail.count(".") >= 2 else tail):
            return None
        return ("glob", d)
    return ("suffix", d) if domain_ok(d) else None


def domain_ok(d: str) -> bool:
    labels = d.split(".")
    if len(labels) < 2 or d in PUBLIC_SUFFIXES or "*" in d:
        return False
    for shared, extra in SHARED_DOMAINS.items():
        if d == shared:
            return False
        if d.endswith("." + shared) and len(labels) - len(shared.split(".")) < extra:
            return False
    return True


def linux_glob(path: str) -> str | None:
    p = clean(path)
    if not p.startswith(("/", "~/")) or p.startswith(("/Applications", "/Library", "/System",
                                                       "/Users/", "~/Library")) or ".app/" in p:
        return None
    p = re.sub(r"^~/", "/*/", p)
    p = re.sub(r"<[^>]*>|\$\{?[A-Za-z_]+\}?", "*", p)
    p = re.sub(r"\*{2,}", "*", p).rstrip("/")
    if not re.search(r"\.[A-Za-z0-9]{1,5}$", p.rsplit("/", 1)[-1]) and not p.endswith("*") \
            and "/" in p and not re.search(r"/(s?bin|libexec)/[^/]+$", p):
        p += "/*" if p.count("/") <= 3 else ""      # an install folder: anything inside it
    segs = p.strip("/").split("/")
    if not segments_specific(segs):
        return None
    if segs[-1] in ("*", "") and not segments_specific(segs[:-1]):
        return None
    return p


# ----------------------------------------------------------------------------- extraction
KINDS = ("win_exe", "win_exe_glob", "win_path", "win_file", "service", "service_glob", "task",
         "registry", "domain", "domain_glob", "ip", "sha256", "sha1",
         "linux_path", "linux_exe", "linux_unit")


def extract(tools: list) -> dict:
    ind = {k: defaultdict(set) for k in KINDS}

    def add(kind, value, tool):
        if value:
            ind[kind][value].add(tool)

    def add_exe_path(path, tool, kind="win_path"):
        name, glob = exe_name_of(path)
        add("win_exe", name, tool)
        if name and len(name) > 29:          # Prefetch keeps the first 29 characters
            add("win_exe", name[:29], tool)
        add("win_exe_glob", glob, tool)
        if "\\" in clean(path).replace("/", "\\") or clean(path).startswith("%"):
            g = win_glob(path)
            add(kind, g, tool)
            # C:\ProgramData\Getscreen.me is a folder: a last part that is not a known file type
            # is tested as a folder too
            if g and not g.endswith("*") and not re.search(FILE_EXT_RE, g.rsplit("\\", 1)[-1]):
                add(kind, g + "\\*", tool)

    for t in tools:
        tool = clean(t.get("Name"))
        if not tool:
            continue
        det = t.get("Details") or {}
        art = t.get("Artifacts") or {}
        paths = as_list(det.get("InstallationPaths")) + as_list(t.get("InstallationPaths")) \
            + as_list(art.get("InstallationPaths"))
        for p in paths:
            p = clean(p)
            if not p:
                continue
            if p.startswith(("/", "~/")):
                lg = linux_glob(p)
                add("linux_path", lg, tool)
                continue
            add_exe_path(p, tool)
        for pe in as_list(det.get("PEMetadata")):
            if isinstance(pe, dict):
                for key in ("Filename", "OriginalFileName"):
                    name, glob = exe_name_of(pe.get(key) or "")
                    add("win_exe", name, tool)
                    add("win_exe_glob", glob, tool)
        for f in as_list(art.get("Disk")):
            if not isinstance(f, dict):
                continue
            path, os_ = clean(f.get("File")), str(f.get("OS") or "").lower()
            if not path:
                continue
            if path.startswith(("/", "~/")) or "linux" in os_:
                if "linux" in os_ or not os_:
                    add("linux_path", linux_glob(path), tool)
                continue
            if "mac" in os_:
                continue
            if exe_name_of(path)[0] or exe_name_of(path)[1]:
                add_exe_path(path, tool, "win_file")
            else:
                add("win_file", win_glob(path), tool)
        for r in as_list(art.get("Registry")):
            if isinstance(r, dict):
                key = clean(r.get("Path"))
                for g in registry_globs(key):
                    add("registry", g, tool)
                m = re.match(r"(?i)^(hklm|hkey_local_machine)\\system\\(currentcontrolset|controlset00\d)"
                             r"\\services\\([^\\*]+)(\\|$)", key)
                if m:
                    add_service(ind, m.group(3), tool)
        for e in as_list(art.get("EventLog")):
            if not isinstance(e, dict):
                continue
            if e.get("ServiceName"):
                add_service(ind, e["ServiceName"], tool)
            if e.get("TaskName"):
                add("task", clean(e["TaskName"]).lower().split("\\")[-1], tool)
            for key in ("ImagePath", "CommandLine"):
                img = image_from_command(e.get(key) or "")
                if img and not img.lower().endswith((".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
                    add_exe_path(img, tool)
        for n in as_list(art.get("Network")):
            if not isinstance(n, dict) or n.get("Detection") is False:
                continue
            for raw in as_list(n.get("Domains")):
                de = domain_entry(raw)
                if de:
                    add({"suffix": "domain", "glob": "domain_glob", "ip": "ip"}[de[0]], de[1], tool)
        for o in as_list(art.get("Other")):
            if not isinstance(o, dict):
                continue
            typ, val = str(o.get("Type") or ""), str(o.get("Value") or "")
            if SERVICE_TYPES.match(typ.replace(" ", "")) or SERVICE_TYPES.match(typ):
                add_service(ind, val, tool)
            elif TASK_TYPES.match(typ.replace(" ", "")):
                name = first_name(val).lower().split("\\")[-1]
                if len(name) >= 5:
                    add("task", name, tool)
            elif UNIT_TYPES.match(typ):
                u = first_name(val).split()[0].lower() if first_name(val) else ""
                if u and "." not in u:
                    u += ".service"
                if len(u) >= 8 and u.split(".")[0] not in GENERIC_LINUX_NAMES:
                    add("linux_unit", u, tool)
            elif typ.upper() == "IP":
                de = domain_entry(val)
                if de and de[0] == "ip":
                    add("ip", de[1], tool)
            elif HASH_TYPE.search(typ):
                for h in re.findall(r"\b[0-9a-fA-F]{64}\b", val):
                    add("sha256", h.lower(), tool)
        for group in as_list(t.get("FileHashes")):
            if isinstance(group, dict):
                for entries in group.values():
                    for h in as_list(entries):
                        if isinstance(h, dict):
                            if re.fullmatch(r"[0-9a-fA-F]{64}", str(h.get("sha256") or "")) \
                                    and set(str(h["sha256"])) != {"0"}:
                                add("sha256", h["sha256"].lower(), tool)
                            if re.fullmatch(r"[0-9a-fA-F]{40}", str(h.get("sha1") or "")) \
                                    and set(str(h["sha1"])) != {"0"}:
                                add("sha1", h["sha1"].lower(), tool)
    # Linux executable names: only from absolute install paths, never bare names
    for g, owners in list(ind["linux_path"].items()):
        base = g.rsplit("/", 1)[-1]
        if "*" not in base and "." not in base and len(base) >= 5 and base.lower() not in GENERIC_LINUX_NAMES:
            for o in owners:
                ind["linux_exe"][base].add(o)
    # Windows built-in remote-access programs keep their name only
    return {k: {v: sorted(ts) for v, ts in sorted(d.items())} for k, d in ind.items()}


def add_service(ind, value, tool):
    name = first_name(value)
    if not name or len(name) > 80 or re.search(r"[:/]|^-", name):
        return
    low = re.sub(r"<[^>]*>", "*", name.lower())
    fixed = low.replace("*", "").strip()
    if len(fixed) < 4 or fixed in GENERIC_SERVICES:
        return
    ind["service_glob" if "*" in low else "service"][low].add(tool)


# ----------------------------------------------------------------------------- rendering
def q(s: str) -> str:
    """ES|QL string literal."""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def like(glob: str) -> str:
    """ES|QL LIKE literal for a glob whose backslashes are literal path separators."""
    return q(glob.replace("\\", "\\\\"))


def by_label(mapping: dict) -> dict:
    """{label: [values]} where label names every tool sharing the value."""
    out = defaultdict(list)
    for value, tools in mapping.items():
        out[" / ".join(tools)].append(value)
    return dict(sorted(out.items(), key=lambda kv: kv[0].lower()))


def chunks(seq, n):
    seq = list(seq)
    return [seq[i:i + n] for i in range(0, len(seq), n)]


def in_list(var, values, indent):
    """var IN (...) with the values wrapped over lines."""
    lines, cur = [], ""
    for v in values:
        item = q(v) + ", "
        if len(cur) + len(item) > 110 and cur:
            lines.append(cur.rstrip())
            cur = ""
        cur += item
    lines.append(cur.rstrip(", "))
    pad = "\n" + " " * (indent + 4)
    return f"{var} IN ({pad}" + pad.join(lines) + ")" if len(lines) > 1 else f"{var} IN ({lines[0]})"


def like_list(var, globs, indent, render=like):
    """var LIKE "a" OR var LIKE "b" ...: one automaton per pattern. A LIKE ("a", "b") list is
    compiled to one automaton, the union, which Lucene soon finds too complex to determinize
    when the patterns start with *."""
    items = [f"{var} LIKE {render(g)}" for g in globs]
    pad = "\n" + " " * (indent + 4)
    return items[0] if len(items) == 1 else ("(" + f"{pad}OR ".join(items) + ")")


def label_case(branches: list, indent: int = 4) -> str:
    """CASE(cond1, "label1", cond2, "label2", ..., "") over (label, [conditions])."""
    merged = defaultdict(list)
    for label, conds in branches:
        merged[label].extend(conds)
    pad = " " * indent
    parts = []
    for label in sorted(merged, key=str.lower):
        conds = merged[label]
        cond = conds[0] if len(conds) == 1 else "(" + f"\n{pad}    OR ".join(conds) + ")"
        parts.append(f"{pad}{cond}, {q(label)}")
    return "CASE(\n" + ",\n".join(parts) + f",\n{pad}\"\")"


def name_case(ind, var, kinds=("win_exe",), glob_kinds=("win_exe_glob",), lower=True):
    br = []
    for k in kinds:
        for label, vals in by_label(ind[k]).items():
            br.append((label, [in_list(var, vals, 4) if len(vals) > 1 else f"{var} == {q(vals[0])}"]))
    for k in glob_kinds:
        for label, vals in by_label(ind[k]).items():
            br.append((label, [like_list(var, vals, 4)]))
    return label_case(br)


def glob_case(ind, var, kinds, render=like):
    br = []
    for k in kinds:
        for label, vals in by_label(ind[k]).items():
            br.append((label, [like_list(var, vals, 4, render)]))
    return label_case(br)


def domain_case(ind, host_var="h"):
    br = []
    for label, vals in by_label(ind["domain"]).items():
        by_len = defaultdict(list)
        for v in vals:
            by_len[v.count(".") + 1].append(v)
        conds = []
        for n in sorted(by_len):
            var = f"s{n}"
            conds.append(in_list(var, by_len[n], 4) if len(by_len[n]) > 1 else f"{var} == {q(by_len[n][0])}")
        br.append((label, conds))
    for label, vals in by_label(ind["domain_glob"]).items():
        br.append((label, [like_list(host_var, vals, 4, render=q)]))
    return label_case(br)


def suffix_evals(ind, host_var="h"):
    lens = sorted({v.count(".") + 1 for v in ind["domain"]})
    out = []
    for n in lens:
        out.append(f'| EVAL s{n} = REPLACE({host_var}, "^.*?([^.]+([.][^.]+){{{n - 1}}})$", "$1")')
    return "\n".join(out)


JAVA_SPECIAL = set("\\.[]{}()*+?^$|-#&~<>/")


def jre(s: str) -> str:
    return "".join("\\" + c if c in JAVA_SPECIAL else c for c in s)


def trie_regex(words) -> str:
    """One Java regex alternation for a set of literal words, factored on common prefixes."""
    trie = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def build(node):
        alts, end = [], "" in node
        for ch in sorted(k for k in node if k):
            alts.append(jre(ch) + build(node[ch]))
        if not alts:
            return ""
        body = alts[0] if len(alts) == 1 and not end else "(?:" + "|".join(alts) + ")"
        return body + ("?" if end and alts else "") if not (len(alts) == 1 and not end) else body
    return build(trie)


def segment_of(seg: str, sep: str = "\\") -> str | None:
    """A path segment as a Java regex for one whole segment (None when it pins nothing)."""
    fixed = seg.replace("*", "").replace("?", "")
    if len(fixed) < 3 or seg.lower() in GENERIC_DIRS or fixed.lower() in GENERIC_DIRS:
        return None
    other = "[^" + jre(sep) + "]"
    return None if "*" not in seg and "?" not in seg else \
        "".join(other + "*" if c == "*" else other if c == "?" else jre(c) for c in seg)


def anchors(globs, names=(), name_globs=(), sep="\\"):
    """(literal segments, regex segments): every glob contains at least one of them as a whole
    path segment, so a path that has none cannot match any glob."""
    lit, rx = set(names), {segment_of(g, sep) or jre(g) for g in name_globs}
    for g in globs:
        segs = [x for x in g.split(sep) if x not in ("", "*")]
        plain = [x for x in segs if "*" not in x and "?" not in x and len(x) >= 3
                 and x.lower() not in GENERIC_DIRS and x not in GENERIC_EXE and x not in BUILTIN_EXE]
        plain = plain or [x for x in segs if "*" not in x and "?" not in x and len(x) >= 3
                          and x.lower() not in GENERIC_DIRS]
        if plain:
            # a product folder pins more than a file name such as agent.yaml: prefer names without a dot
            lit.add(max(plain, key=lambda x: ("." not in x, len(x))))
            continue
        wild = [segment_of(x, sep) for x in segs if segment_of(x, sep)]
        if not wild:
            raise ValueError(f"no anchor segment in {g}")
        rx.add(max(wild, key=len))
    return sorted(lit), sorted(rx)


def segment_filter(var, globs, names=(), name_globs=(), sep="\\"):
    """var has a whole path segment from the anchor set: one Java regex (REPLACE), whose cost does
    not grow with the number of indicators the way a chain of LIKE automata does."""
    lit, rx = anchors(globs, names, name_globs, sep)
    alt = "|".join(([trie_regex(lit)] if lit else []) + rx)
    s = jre(sep)
    pattern = "^.*?(?:^|" + s + ")(?:" + alt + ")(?:" + s + ".*)?$"
    return f"{var} != \"\" AND REPLACE({var}, {q(pattern)}, \"\") == \"\""


GENERATED = ("// GENERATED by hunting/tools/lolrmm.py from the LOLRMM catalog ({date}, {tools} tools, "
             "sha256 {sha12}); edit the template there, not this file")


def render(ind: dict, meta: dict) -> dict:
    """{relative query path: text}."""
    gen = GENERATED.format(date=meta["fetched_utc"][:10], tools=meta["tool_count"],
                           sha12=meta["sha256"][:12])
    ctx = {
        "GEN": gen,
        "NAME_CASE_KEY": name_case(ind, "key"),
        "PATH_CASE_KEY": glob_case(ind, "key", ("win_path",)),
        "FILE_CASE_KEY": glob_case(ind, "key", ("win_path", "win_file")),
        "SHA256_CASE_KEY": label_case([(l, [in_list("key", v, 4)]) for l, v in by_label(ind["sha256"]).items()]),
        "SHA1_CASE_KEY": label_case([(l, [in_list("key", v, 4)]) for l, v in by_label(ind["sha1"]).items()]),
        "SERVICE_CASE_KEY": label_case(
            [(l, [in_list("key", v, 4)]) for l, v in by_label(ind["service"]).items()]
            + [(l, [like_list("key", v, 4, render=q)]) for l, v in by_label(ind["service_glob"]).items()]),
        "TASK_CASE_KEY": label_case([(l, [in_list("key", v, 4)]) for l, v in by_label(ind["task"]).items()]),
        "REGISTRY_CASE_KEY": glob_case(ind, "key", ("registry",)),
        "DOMAIN_CASE": domain_case(ind),
        "SUFFIX_EVALS": suffix_evals(ind),
        "IP_CASE_ADDR": label_case([(l, [in_list("addresses", v, 4)]) for l, v in by_label(ind["ip"]).items()]),
        "FILE_PREFILTER": segment_filter("p", list(ind["win_path"]) + list(ind["win_file"]),
                                         ind["win_exe"], ind["win_exe_glob"]),
        "REGISTRY_PREFILTER": segment_filter("k", list(ind["registry"])),
        "LINUX_PREFILTER": segment_filter("program", list(ind["linux_path"]), ind["linux_exe"], (), "/"),
        "LINUX_PATH_CASE_KEY": glob_case(ind, "key", ("linux_path",), render=q),
        "LINUX_EXE_CASE_KEY": label_case([(l, [in_list("key", v, 4)]) for l, v in by_label(ind["linux_exe"]).items()]),
        "LINUX_UNIT_CASE_KEY": label_case([(l, [in_list("key", v, 4)]) for l, v in by_label(ind["linux_unit"]).items()]),
    }
    out = {}
    for rel, tmpl in TEMPLATES.items():
        text = tmpl
        for k, v in ctx.items():
            text = text.replace("{{" + k + "}}", v)
        out[rel] = text.rstrip() + "\n"
    return out


# ----------------------------------------------------------------------------- templates
USERPATH_RE = ('".*\\\\\\\\(users\\\\\\\\public|programdata|perflogs|windows\\\\\\\\temp|temp|appdata|'
               'downloads|desktop|[$]recycle[.]bin)\\\\\\\\.*"')

TEMPLATES = {}

TEMPLATES["windows/TA0011-command-and-control/C2-10-lolrmm-rmm-process-execution/query.esql"] = r'''// C2-10 | LOLRMM: RMM and remote-access tools in process creation events (4688, Sysmon 1): image, parent, PE original name, SHA-256
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1219.002, T1036.005
// Indexes: evtxlogs-* | Needs: Security 4688 and/or Sysmon 1
{{GEN}}
FROM evtxlogs-* METADATA _index
| EVAL eid = TO_STRING(winlog.event_id)
| EVAL ch = TO_STRING(winlog.channel)
| WHERE (ch == "Security" AND eid == "4688") OR (ch == "Microsoft-Windows-Sysmon/Operational" AND eid == "1")
| EVAL image = TO_LOWER(COALESCE(TO_STRING(winlog.payload.event_data.NewProcessName), TO_STRING(winlog.payload.event_data.Image), ""))
| EVAL parent = TO_LOWER(COALESCE(TO_STRING(winlog.payload.event_data.ParentProcessName), TO_STRING(winlog.payload.event_data.ParentImage), ""))
| EVAL original_name = TO_LOWER(COALESCE(TO_STRING(winlog.payload.event_data.OriginalFileName), ""))
| EVAL sha256 = TO_LOWER(REPLACE(COALESCE(TO_STRING(winlog.payload.event_data.Hashes), ""), "^(?i).*sha256=([0-9a-f]{64}).*$", "$1"))
| EVAL sha256 = CASE(LENGTH(sha256) == 64, sha256, "")
| EVAL account = COALESCE(TO_STRING(winlog.payload.event_data.User), TO_STRING(winlog.payload.event_data.TargetUserName), TO_STRING(winlog.payload.event_data.SubjectUserName), "")
| EVAL cmd = COALESCE(TO_STRING(winlog.payload.event_data.CommandLine), "")
| WHERE image != ""
// one row per distinct process before matching, so the indicator lists are tested once per program
| STATS
    executions = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp),
    accounts = VALUES(account),
    command_lines = VALUES(cmd)
  BY _index, image, parent, original_name, sha256
| EVAL image_name = REPLACE(image, "^.*\\\\", "")
| EVAL parent_name = REPLACE(parent, "^.*\\\\", "")
// test every indicator kind against its value: "role|value" pairs, expanded to one row each
| EVAL keys = MV_DEDUPE(MV_APPEND(MV_APPEND(MV_APPEND(
    CONCAT("image|", image_name), CONCAT("image_path|", image)),
    MV_APPEND(CONCAT("parent|", parent_name), CONCAT("parent_path|", parent))),
    MV_APPEND(CONCAT("original_name|", original_name), CONCAT("sha256|", sha256))))
| MV_EXPAND keys
| EVAL role = REPLACE(keys, "[|].*$", "")
| EVAL key = REPLACE(keys, "^[^|]*[|]", "")
| WHERE key != ""
| EVAL tool = CASE(
    role IN ("image", "parent", "original_name"), {{NAME_CASE_KEY}},
    role IN ("image_path", "parent_path"), {{PATH_CASE_KEY}},
    role == "sha256", {{SHA256_CASE_KEY}},
    "")
| WHERE COALESCE(tool, "") != ""
| EVAL side = CASE(STARTS_WITH(role, "parent"), "parent", "image")
| STATS
    tools = VALUES(tool),
    matched_on = VALUES(role),
    image_roles = COUNT(*) WHERE side == "image",
    executions = MAX(executions),
    first_seen = MIN(first_seen),
    last_seen = MAX(last_seen),
    accounts = VALUES(accounts),
    command_lines = VALUES(command_lines)
  BY _index, image, parent, original_name, sha256
| INLINE STATS image_hosts = COUNT_DISTINCT(_index) BY image
| EVAL image_name = REPLACE(image, "^.*\\\\", "")
| EVAL f_tool_image = image_roles > 0
// the RMM program started this process: a command run by whoever is connected through it
| EVAL f_tool_parent = image_roles == 0
| EVAL f_renamed = MV_CONTAINS(matched_on, "original_name") AND original_name != image_name AND original_name != ""
| EVAL f_hash = MV_CONTAINS(matched_on, "sha256")
| EVAL f_userpath = image RLIKE {{USERPATH}}
| EVAL f_child_shell = f_tool_parent AND image_name IN ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe", "net.exe", "net1.exe", "whoami.exe", "nltest.exe", "reg.exe", "sc.exe", "schtasks.exe", "wmic.exe", "vssadmin.exe", "bcdedit.exe", "wevtutil.exe")
| EVAL f_builtin = image_name IN ("mstsc.exe", "msra.exe", "quickassist.exe", "rdpinit.exe", "rdpshell.exe", "tscon.exe", "mobsync.exe")
| EVAL score = CASE(f_builtin, 0, f_tool_image, 2, 1)
    + CASE(f_renamed, 3, 0) + CASE(f_hash, 2, 0) + CASE(f_userpath AND f_tool_image, 2, 0)
    + CASE(f_child_shell, 3, 0) + CASE(image_hosts == 1, 1, 0)
| EVAL reasons = REPLACE(CONCAT(
    CASE(f_tool_image, "RMM program ran; ", "started by an RMM program; "),
    CASE(f_renamed, "renamed: PE original name differs; ", ""),
    CASE(f_hash, "SHA-256 listed by LOLRMM; ", ""),
    CASE(f_userpath AND f_tool_image, "runs from a user-writable folder; ", ""),
    CASE(f_child_shell, "shell, LOLBin or admin command started by the RMM program; ", ""),
    CASE(f_builtin, "Windows built-in remote-access program; ", ""),
    CASE(image_hosts == 1, "on one host only; ", "")
  ), "; $", "")
| EVAL command_lines = MV_SLICE(command_lines, 0, 9)
| KEEP
    _index,
    score,
    reasons,
    tools,
    matched_on,
    image,
    parent,
    original_name,
    executions,
    first_seen,
    last_seen,
    accounts,
    image_hosts,
    command_lines,
    sha256
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["windows/TA0011-command-and-control/C2-11-lolrmm-rmm-execution-artifacts/query.esql"] = r'''// C2-11 | LOLRMM: RMM and remote-access tools in execution and install artifacts (Prefetch, Amcache, ShimCache, SRUM, BAM, UserAssist, installed programs)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1219.002
// Indexes: prefetch-*, amcache-*, shimcache-*, srum-*, registry-* | Needs: any of them (registry-*: RECmd UserAssist and/or BamDam plugin output)
{{GEN}}
FROM prefetch-*, amcache-*, shimcache-*, srum-*, registry-* METADATA _index
| EVAL artifact = CASE(
    _index LIKE "prefetch-*", "prefetch",
    _index LIKE "amcache-*" AND TO_STRING(event.dataset) == "amcache.program_entries", "amcache program",
    _index LIKE "amcache-*", "amcache",
    _index LIKE "shimcache-*", "shimcache",
    _index LIKE "srum-*", "srum",
    TO_STRING(event.dataset) == "registry.bamdam", "bam",
    TO_STRING(event.dataset) == "registry.userassist", "userassist",
    "other")
| WHERE artifact != "other"
// Prefetch records the executable name only (file.path is the .pf file); the others the full path
| EVAL exe_path = TO_LOWER(CASE(
    artifact == "prefetch", COALESCE(TO_STRING(file.target.path), ""),
    // ProgramEntries: the install folder, tested against the LOLRMM folder patterns
    artifact == "amcache program", CASE(COALESCE(TO_STRING(package.path), "") == "", "", CONCAT(TO_STRING(package.path), "\\")),
    artifact == "srum", COALESCE(TO_STRING(process.executable), ""),
    artifact IN ("bam", "userassist"), COALESCE(TO_STRING(registry.plugin.program_name), TO_STRING(registry.plugin.program), ""),
    COALESCE(TO_STRING(file.path), "")))
// UserAssist writes known folders as GUIDs
| EVAL exe_path = REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(exe_path,
    "^[{]6d809377-6af0-444b-8957-a3773f02200e[}]", "c:\\\\program files"),
    "^[{]7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e[}]", "c:\\\\program files (x86)"),
    "^[{]62ab5d82-fdc1-4dc3-a9dd-070d1d495d97[}]", "c:\\\\programdata"),
    "^[{]1ac14e77-02e7-4e5d-b744-2eb1ae5198b7[}]", "c:\\\\windows\\\\system32"),
    "^[{]d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27[}]", "c:\\\\windows\\\\syswow64"),
    "^[{]f38bf404-1d43-42f2-9305-67de0b28fc23[}]", "c:\\\\windows")
| EVAL program = TO_LOWER(CASE(artifact == "amcache program", COALESCE(TO_STRING(package.name), ""), ""))
| EVAL sha1 = TO_LOWER(COALESCE(TO_STRING(file.hash.sha1), ""))
| WHERE exe_path != ""
| EVAL account = CASE(artifact IN ("bam", "userassist"),
    COALESCE(TO_STRING(user.name), REPLACE(TO_STRING(registry.key), "(?i)^.*\\\\(S-1-[0-9-]+).*$", "$1")),
    artifact == "srum", TO_STRING(user.name), null)
| EVAL ts = CASE(
    artifact == "prefetch", kape.prefetch.last_run,
    artifact == "amcache", amcache.file_key_last_write,
    artifact == "amcache program", COALESCE(package.installed, amcache.key_last_write),
    artifact == "shimcache", file.mtime,
    artifact == "srum", srum.timestamp,
    artifact == "bam", registry.plugin.execution_time,
    artifact == "userassist", registry.plugin.last_executed,
    null)
// one row per distinct program per artifact before matching
| STATS
    first_seen = MIN(ts),
    last_seen = MAX(ts),
    prefetch_runs = MAX(kape.prefetch.run_count),
    accounts = VALUES(account),
    sha1_values = VALUES(sha1)
  BY _index, artifact, exe_path, program
| EVAL exe_name = REPLACE(exe_path, "^.*\\\\", "")
| EVAL keys = MV_DEDUPE(MV_APPEND(MV_APPEND(
    CONCAT("name|", exe_name), CONCAT("path|", exe_path)),
    CONCAT("sha1|", COALESCE(MV_MAX(sha1_values), ""))))
| MV_EXPAND keys
| EVAL role = REPLACE(keys, "[|].*$", "")
| EVAL key = REPLACE(keys, "^[^|]*[|]", "")
| WHERE key != "" AND NOT (role == "path" AND artifact == "prefetch")
| EVAL tool = CASE(
    role == "name", {{NAME_CASE_KEY}},
    role == "path", {{PATH_CASE_KEY}},
    role == "sha1", {{SHA1_CASE_KEY}},
    "")
| WHERE COALESCE(tool, "") != ""
| EVAL exe_dir = REPLACE(REPLACE(exe_path, "\\\\[^\\\\]*$", ""), "^(\\\\device\\\\harddiskvolume[0-9]+|[a-z]:)", "")
| EVAL f_userpath = exe_path RLIKE {{USERPATH}}
| EVAL host = REPLACE(_index, "^[^-]+-", "")
| STATS
    artifacts = VALUES(artifact),
    matched_on = VALUES(role),
    exe_names = VALUES(exe_name),
    exe_dirs = VALUES(exe_dir),
    programs = VALUES(program),
    first_seen = MIN(first_seen),
    last_seen = MAX(last_seen),
    prefetch_runs = MAX(prefetch_runs),
    accounts = VALUES(accounts),
    in_userpath = MAX(TO_INTEGER(f_userpath)),
    sha1_values = VALUES(sha1_values),
    source_indices = VALUES(_index)
  BY host, tool
| INLINE STATS tool_hosts = COUNT_DISTINCT(host) BY tool
| EVAL f_ran = MV_CONTAINS(artifacts, "prefetch") OR MV_CONTAINS(artifacts, "bam") OR MV_CONTAINS(artifacts, "userassist") OR MV_CONTAINS(artifacts, "srum")
// only Windows' own remote-access programs (mstsc, msra, Quick Assist ...) matched
| EVAL f_builtin = COALESCE(MV_CONCAT(exe_names, ",") RLIKE "(mstsc|msra|quickassist|rdpinit|rdpshell|tscon|mobsync)[.]exe(,(mstsc|msra|quickassist|rdpinit|rdpshell|tscon|mobsync)[.]exe)*", false)
| EVAL score = CASE(f_builtin, 0, 2) + CASE(f_ran, 1, 0) + CASE(COALESCE(in_userpath, 0) == 1, 2, 0)
    + CASE(MV_CONTAINS(matched_on, "sha1"), 2, 0) + CASE(tool_hosts == 1, 1, 0)
| KEEP
    source_indices,
    host,
    score,
    tool,
    matched_on,
    artifacts,
    exe_names,
    exe_dirs,
    programs,
    first_seen,
    last_seen,
    prefetch_runs,
    accounts,
    in_userpath,
    tool_hosts,
    sha1_values
| SORT host ASC, score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["windows/TA0011-command-and-control/C2-12-lolrmm-rmm-services-and-tasks/query.esql"] = r'''// C2-12 | LOLRMM: RMM services and scheduled tasks (System 7045, Security 4697/4698, Task Scheduler, RECmd Services)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1543.003, T1053.005
// Indexes: evtxlogs-*, registry-* | Needs: any of System 7045, Security 4697/4698, Task Scheduler Operational, RECmd Services plugin output
{{GEN}}
FROM evtxlogs-*, registry-* METADATA _index
| EVAL eid = TO_STRING(winlog.event_id)
| EVAL ch = TO_STRING(winlog.channel)
| EVAL source = CASE(
    ch == "System" AND eid == "7045", "7045 service installed",
    ch == "Security" AND eid == "4697", "4697 service installed",
    ch == "Security" AND eid == "4698", "4698 task created",
    ch == "Microsoft-Windows-TaskScheduler/Operational" AND eid IN ("106", "140", "200", "201"), CONCAT("Task Scheduler ", eid),
    TO_STRING(event.dataset) == "registry.services", "registry Services",
    "")
| WHERE source != ""
| EVAL svc_name = TO_STRING(COALESCE(TO_STRING(winlog.payload.event_data.ServiceName), TO_STRING(registry.plugin.name), ""))
| EVAL svc_display = TO_STRING(COALESCE(TO_STRING(registry.plugin.display_name), ""))
| EVAL task = REPLACE(COALESCE(TO_STRING(winlog.payload.event_data.TaskName), ""), "^.*\\\\", "")
| EVAL command = TO_STRING(COALESCE(
    TO_STRING(winlog.payload.event_data.ImagePath),
    TO_STRING(winlog.payload.event_data.ServiceFileName),
    TO_STRING(winlog.payload.event_data.ActionName),
    TO_STRING(registry.plugin.image_path),
    REPLACE(COALESCE(TO_STRING(winlog.payload.event_data.TaskContent), ""), "(?s)^.*<Command>([^<]*)</Command>.*$", "$1"),
    ""))
| EVAL cmd_l = TO_LOWER(TRIM(command))
// program path at the start of the command: quoted, or up to the first executable extension
| EVAL image = REPLACE(cmd_l, "^\"?([^\"]*?[.](exe|sys|dll|bat|cmd|ps1|vbs|js))([\" ,].*)?$", "$1")
| EVAL image = REPLACE(REPLACE(image, "^\\\\[?][?]\\\\", ""), "^\\\\systemroot", "c:\\\\windows")
| EVAL account = COALESCE(TO_STRING(winlog.payload.event_data.SubjectUserName), TO_STRING(winlog.payload.event_data.AccountName), TO_STRING(winlog.payload.event_data.UserContext), TO_STRING(registry.plugin.object_name), "")
| EVAL ts = COALESCE(TO_DATETIME(registry.plugin.name_key_last_write), @timestamp)
| STATS
    events = COUNT(*),
    first_seen = MIN(ts),
    last_seen = MAX(ts),
    accounts = VALUES(account),
    commands = VALUES(command)
  BY _index, source, svc_name, svc_display, task, image
| EVAL keys = MV_DEDUPE(MV_APPEND(MV_APPEND(
    CONCAT("service|", TO_LOWER(svc_name)), CONCAT("service|", TO_LOWER(svc_display))),
    MV_APPEND(MV_APPEND(CONCAT("task|", TO_LOWER(task)), CONCAT("image|", REPLACE(image, "^.*\\\\", ""))), CONCAT("image_path|", image))))
| MV_EXPAND keys
| EVAL role = REPLACE(keys, "[|].*$", "")
| EVAL key = REPLACE(keys, "^[^|]*[|]", "")
| WHERE key != ""
| EVAL tool = CASE(
    role == "service", {{SERVICE_CASE_KEY}},
    role == "task", {{TASK_CASE_KEY}},
    role == "image", {{NAME_CASE_KEY}},
    role == "image_path", {{PATH_CASE_KEY}},
    "")
| WHERE COALESCE(tool, "") != ""
| STATS
    tools = VALUES(tool),
    matched_on = VALUES(role),
    events = MAX(events),
    first_seen = MIN(first_seen),
    last_seen = MAX(last_seen),
    accounts = VALUES(accounts),
    commands = VALUES(commands)
  BY _index, source, svc_name, svc_display, task, image
// one string, so that the host count below groups on the tool set and does not split the row
| EVAL tools = MV_CONCAT(MV_SORT(tools), " + ")
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tools
| EVAL f_userpath = image RLIKE {{USERPATH}}
| EVAL f_task = task != ""
| EVAL f_install_event = source IN ("7045 service installed", "4697 service installed", "4698 task created", "Task Scheduler 106")
| EVAL f_name_only = NOT MV_CONTAINS(matched_on, "image") AND NOT MV_CONTAINS(matched_on, "image_path")
| EVAL score = 2 + CASE(f_install_event, 1, 0) + CASE(f_userpath, 2, 0) + CASE(f_task, 1, 0) + CASE(tool_hosts == 1, 1, 0)
    + CASE(f_name_only AND image != "" AND NOT image RLIKE ".*\\\\program files( [(]x86[)])?\\\\.*", 1, 0)
| EVAL reasons = REPLACE(CONCAT(
    CASE(f_install_event, "installed or registered (event); ", ""),
    CASE(f_userpath, "program in a user-writable folder; ", ""),
    CASE(f_task, "scheduled task; ", ""),
    CASE(f_name_only AND image != "" AND NOT image RLIKE ".*\\\\program files( [(]x86[)])?\\\\.*", "RMM name, program outside Program Files; ", ""),
    CASE(tool_hosts == 1, "on one host only; ", "")
  ), "; $", "")
| KEEP
    _index,
    score,
    reasons,
    tools,
    matched_on,
    source,
    svc_name,
    svc_display,
    task,
    image,
    commands,
    accounts,
    events,
    first_seen,
    last_seen,
    tool_hosts
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["windows/TA0011-command-and-control/C2-13-lolrmm-rmm-domains-and-addresses/query.esql"] = r'''// C2-13 | LOLRMM: RMM vendor and relay domains and addresses contacted (Sysmon 22/3, DNS Client, BITS, URLs in command lines, browser history)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1071.001, T1105
// Indexes: evtxlogs-*, browsinghistory-* | Needs: any of Sysmon 22/3, DNS-Client Operational, BITS-Client Operational, Security 4688 / Sysmon 1 with command lines, BrowsingHistoryView output
{{GEN}}
FROM evtxlogs-*, browsinghistory-* METADATA _index
| EVAL eid = TO_STRING(winlog.event_id)
| EVAL ch = TO_STRING(winlog.channel)
| EVAL sysmon = ch == "Microsoft-Windows-Sysmon/Operational"
| EVAL cmd = COALESCE(TO_STRING(winlog.payload.event_data.CommandLine), "")
| EVAL bits_url = COALESCE(TO_STRING(winlog.payload.event_data.url), TO_STRING(winlog.payload_data.URL), "")
| EVAL source = CASE(
    sysmon AND eid == "22", "Sysmon 22 DNS query",
    sysmon AND eid == "3", "Sysmon 3 connection",
    ch == "Microsoft-Windows-DNS-Client/Operational" AND eid IN ("3006", "3008", "3020"), "DNS Client",
    ch == "Microsoft-Windows-Bits-Client/Operational" AND eid IN ("3", "59", "60", "61") AND bits_url != "", "BITS job",
    ((ch == "Security" AND eid == "4688") OR (sysmon AND eid == "1")) AND cmd LIKE "*://*", "URL in command line",
    _index LIKE "browsinghistory-*", "browser history",
    "")
| WHERE source != ""
| EVAL h = TO_LOWER(CASE(
    source IN ("Sysmon 22 DNS query", "DNS Client"), COALESCE(TO_STRING(winlog.payload.event_data.QueryName), ""),
    source == "Sysmon 3 connection", COALESCE(TO_STRING(winlog.payload.event_data.DestinationHostname), ""),
    source == "BITS job", REPLACE(bits_url, "^(?s)[a-zA-Z]+://([^/:?#\"' ]+).*$", "$1"),
    source == "URL in command line", REPLACE(cmd, "^(?s).*?[a-zA-Z]+://([^/:?#\"' ]+).*$", "$1"),
    COALESCE(TO_STRING(url.domain), "")))
| EVAL ip = CASE(source == "Sysmon 3 connection", TO_STRING(winlog.payload.event_data.DestinationIp), null)
| EVAL h = REPLACE(TRIM(h), "[.]$", "")
| EVAL program = TO_LOWER(COALESCE(TO_STRING(winlog.payload.event_data.Image), TO_STRING(winlog.payload.event_data.NewProcessName), TO_STRING(browsinghistory.web_browser), ""))
| EVAL account = COALESCE(TO_STRING(winlog.payload.event_data.User), TO_STRING(winlog.payload.event_data.SubjectUserName), TO_STRING(user.name), "")
| EVAL ts = COALESCE(TO_DATETIME(browsinghistory.visit_time), @timestamp)
| EVAL detail = CASE(source == "URL in command line", cmd, source == "BITS job", bits_url, source == "browser history", TO_STRING(url.original), "")
| WHERE h != "" OR COALESCE(ip, "") != ""
// one row per distinct host name per program before matching
| STATS
    events = COUNT(*),
    first_seen = MIN(ts),
    last_seen = MAX(ts),
    accounts = VALUES(account),
    details = VALUES(detail),
    addresses = VALUES(ip)
  BY _index, source, program, h
{{SUFFIX_EVALS}}
| EVAL tool = {{DOMAIN_CASE}}
| EVAL ip_tool = ""
| WHERE COALESCE(tool, "") != "" OR COALESCE(MV_COUNT(addresses), 0) > 0
| MV_EXPAND addresses
| EVAL ip_tool = CASE(COALESCE(addresses, "") == "", "", {{IP_CASE_ADDR}})
| WHERE COALESCE(tool, "") != "" OR COALESCE(ip_tool, "") != ""
| EVAL tool = CASE(COALESCE(tool, "") != "", tool, ip_tool)
| EVAL matched = CASE(COALESCE(ip_tool, "") != "" AND (h == "" OR COALESCE(tool, "") == ip_tool), CONCAT("ip ", addresses), CONCAT("domain ", h))
| STATS
    events = MAX(events),
    first_seen = MIN(first_seen),
    last_seen = MAX(last_seen),
    accounts = VALUES(accounts),
    details = VALUES(details),
    addresses = VALUES(addresses)
  BY _index, tool, source, program, matched
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tool
| EVAL f_not_browser = source != "browser history"
| EVAL f_cmdline = source IN ("URL in command line", "BITS job")
| EVAL score = 2 + CASE(f_not_browser, 1, 0) + CASE(f_cmdline, 2, 0) + CASE(tool_hosts == 1, 1, 0)
| EVAL details = MV_SLICE(details, 0, 9)
| KEEP
    _index,
    score,
    tool,
    matched,
    source,
    program,
    events,
    first_seen,
    last_seen,
    accounts,
    tool_hosts,
    addresses,
    details
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["windows/TA0011-command-and-control/C2-14-lolrmm-rmm-files-on-disk/query.esql"] = r'''// C2-14 | LOLRMM: RMM install folders, programs, logs and configuration files on disk ($MFT, Sysmon 11)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1105
// Indexes: filesystem-*, evtxlogs-* | Needs: MFTECmd $MFT output and/or Sysmon 11
{{GEN}}
FROM filesystem-*, evtxlogs-* METADATA _index
| EVAL eid = TO_STRING(winlog.event_id)
| EVAL source = CASE(
    _index LIKE "filesystem-*" AND TO_STRING(file.update_reasons) IS NULL AND NOT COALESCE(kape.mft.isads, false), "$MFT",
    TO_STRING(winlog.channel) == "Microsoft-Windows-Sysmon/Operational" AND eid == "11", "Sysmon 11 file created",
    "")
| WHERE source != ""
| EVAL p = TO_LOWER(CASE(source == "$MFT",
    CONCAT(COALESCE(TO_STRING(file.directory), ""), "\\", COALESCE(TO_STRING(file.name), "")),
    COALESCE(TO_STRING(winlog.payload.event_data.TargetFilename), "")))
| EVAL p = REPLACE(p, "^[.]", "c:")
| EVAL fname = REPLACE(p, "^.*\\\\", "")
// first pass over every file, one regex: a folder or file name that an LOLRMM path pattern
// requires, or an RMM program name (the patterns themselves are tested below, on what is left)
| WHERE {{FILE_PREFILTER}}
| EVAL ts = COALESCE(file.stdinfo.created, @timestamp)
| EVAL keys = MV_APPEND(CONCAT("path|", p), CONCAT("name|", fname))
| MV_EXPAND keys
| EVAL role = REPLACE(keys, "[|].*$", "")
| EVAL key = REPLACE(keys, "^[^|]*[|]", "")
| EVAL tool = CASE(
    role == "path", {{FILE_CASE_KEY}},
    role == "name", {{NAME_CASE_KEY}},
    "")
| WHERE COALESCE(tool, "") != ""
| EVAL dir = REPLACE(p, "\\\\[^\\\\]*$", "")
| EVAL is_exe = fname RLIKE ".*[.](exe|dll|sys|msi|ps1|bat|cmd|vbs|js)"
| EVAL f_userpath = p RLIKE {{USERPATH}}
| STATS
    files = COUNT_DISTINCT(p),
    executables = COUNT_DISTINCT(p) WHERE is_exe,
    sample_files = VALUES(fname),
    matched_on = VALUES(role),
    sources = VALUES(source),
    first_created = MIN(ts),
    last_created = MAX(ts),
    deleted = COUNT(*) WHERE kape.mft.inuse == false,
    in_userpath = MAX(TO_INTEGER(f_userpath))
  BY _index, tool, dir
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tool
| EVAL score = 2 + CASE(executables > 0, 1, 0) + CASE(COALESCE(in_userpath, 0) == 1, 2, 0)
    + CASE(COALESCE(deleted, 0) > 0, 1, 0) + CASE(tool_hosts == 1, 1, 0)
| EVAL sample_files = MV_SLICE(sample_files, 0, 19)
| KEEP
    _index,
    score,
    tool,
    dir,
    files,
    executables,
    deleted,
    in_userpath,
    first_created,
    last_created,
    matched_on,
    sources,
    tool_hosts,
    sample_files
| SORT score DESC, first_created ASC
| LIMIT 10000
'''

TEMPLATES["windows/TA0011-command-and-control/C2-15-lolrmm-rmm-registry-keys/query.esql"] = r'''// C2-15 | LOLRMM: RMM registry keys (RECmd batch output, Sysmon 12/13/14)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1112
// Indexes: registry-*, evtxlogs-* | Needs: RECmd batch output that dumps the keys, and/or Sysmon 12/13/14
{{GEN}}
FROM registry-*, evtxlogs-* METADATA _index
| EVAL eid = TO_STRING(winlog.event_id)
| EVAL source = CASE(
    TO_STRING(event.dataset) == "registry.batch", "RECmd batch",
    TO_STRING(winlog.channel) == "Microsoft-Windows-Sysmon/Operational" AND eid IN ("12", "13", "14"), CONCAT("Sysmon ", eid),
    "")
| WHERE source != ""
| EVAL k = TO_LOWER(COALESCE(TO_STRING(registry.key), TO_STRING(winlog.payload.event_data.TargetObject), ""))
| EVAL k = REPLACE(k, "\\\\wow6432node(?=\\\\|$)", "")
| WHERE k != ""
// first pass, one regex: a key name that an LOLRMM key pattern requires
| WHERE {{REGISTRY_PREFILTER}}
| EVAL ts = COALESCE(TO_DATETIME(registry.last_write), @timestamp)
| EVAL value = COALESCE(TO_STRING(registry.value), "")
| EVAL data = COALESCE(MV_CONCAT(TO_STRING(registry.data.strings), " "), TO_STRING(winlog.payload.event_data.Details), "")
| EVAL program = TO_LOWER(COALESCE(TO_STRING(winlog.payload.event_data.Image), ""))
| EVAL key = k
| EVAL tool = {{REGISTRY_CASE_KEY}}
| WHERE COALESCE(tool, "") != ""
| STATS
    events = COUNT(*),
    first_seen = MIN(ts),
    last_seen = MAX(ts),
    values = VALUES(value),
    data = VALUES(data),
    programs = VALUES(program)
  BY _index, tool, source, k
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tool
| EVAL f_event = source != "RECmd batch"
| EVAL f_policy_or_boot = k RLIKE ".*\\\\(safeboot|policies|services|run|runonce)\\\\.*"
| EVAL score = 2 + CASE(f_event, 1, 0) + CASE(f_policy_or_boot, 1, 0) + CASE(tool_hosts == 1, 1, 0)
| EVAL values = MV_SLICE(values, 0, 19)
| EVAL data = MV_SLICE(data, 0, 19)
| KEEP
    _index,
    score,
    tool,
    source,
    k,
    events,
    first_seen,
    last_seen,
    values,
    data,
    programs,
    tool_hosts
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["linux/TA0011-command-and-control/LC2-05-lolrmm-rmm-tools-on-linux/query.esql"] = r'''// LC2-05 | LOLRMM: RMM and remote-access tools on Linux: programs run, files on disk, systemd units
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1543.002
// Indexes: logstash-*, auditd-*, bodyfile-*, linuxconfig-* | Needs: any of logstash-*, auditd-*, bodyfile-*, linuxconfig-*
{{GEN}}
FROM logstash-*, auditd-*, bodyfile-*, linuxconfig-* METADATA _index
| WHERE host.os.type == "linux"
| EVAL source = CASE(
    event.dataset == "bodyfile", "bodyfile",
    event.dataset == "linux.systemd_unit", "systemd unit",
    STARTS_WITH(event.dataset, "linux."), "",
    process.executable IS NOT NULL OR process.command_line IS NOT NULL, CONCAT("process (", event.dataset, ")"),
    "")
| WHERE source != ""
| EVAL program = CASE(
    source == "bodyfile", COALESCE(file.path, ""),
    source == "systemd unit", REPLACE(COALESCE(MV_FIRST(linuxconfig.systemd.exec_start), ""), "^([^ ]+).*$", "$1"),
    COALESCE(process.executable, REPLACE(COALESCE(process.command_line, ""), "^([^ ]+).*$", "$1")))
| EVAL unit = CASE(source == "systemd unit", TO_LOWER(COALESCE(linuxconfig.systemd.unit, "")), "")
| EVAL detail = CASE(source == "bodyfile", "", source == "systemd unit", COALESCE(file.path, ""), COALESCE(process.command_line, ""))
// first pass, one regex: a folder or program name that an LOLRMM Linux path requires (or a unit)
| WHERE unit != "" OR ({{LINUX_PREFILTER}})
| STATS
    records = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp),
    accounts = VALUES(user.name),
    details = VALUES(detail)
  BY _index, source, program, unit
| EVAL keys = MV_DEDUPE(MV_APPEND(MV_APPEND(CONCAT("path|", program), CONCAT("name|", REPLACE(program, "^.*/", ""))), CONCAT("unit|", unit)))
| MV_EXPAND keys
| EVAL role = REPLACE(keys, "[|].*$", "")
| EVAL key = REPLACE(keys, "^[^|]*[|]", "")
| WHERE key != ""
| EVAL tool = CASE(
    role == "path", {{LINUX_PATH_CASE_KEY}},
    role == "name", {{LINUX_EXE_CASE_KEY}},
    role == "unit", {{LINUX_UNIT_CASE_KEY}},
    "")
| WHERE COALESCE(tool, "") != ""
| STATS
    matched_on = VALUES(role),
    records = MAX(records),
    first_seen = MIN(first_seen),
    last_seen = MAX(last_seen),
    accounts = VALUES(accounts),
    details = VALUES(details)
  BY _index, tool, source, program, unit
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tool
| EVAL f_ran = STARTS_WITH(source, "process")
| EVAL f_tmp = program RLIKE "/(tmp|var/tmp|dev/shm|home/[^/]+|root)/.*"
| EVAL score = 2 + CASE(f_ran, 2, 0) + CASE(source == "systemd unit", 1, 0) + CASE(f_tmp, 2, 0) + CASE(tool_hosts == 1, 1, 0)
| EVAL details = MV_SLICE(details, 0, 9)
| KEEP
    _index,
    score,
    tool,
    matched_on,
    source,
    program,
    unit,
    records,
    first_seen,
    last_seen,
    accounts,
    tool_hosts,
    details
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''

TEMPLATES["linux/TA0011-command-and-control/LC2-06-lolrmm-rmm-domains-on-linux/query.esql"] = r'''// LC2-06 | LOLRMM: RMM vendor and relay domains in URLs fetched or configured on Linux (command lines, cron and unit lines, browser history)
// Tactic: TA0011 Command and Control | ATT&CK: T1219, T1105, T1071.001
// Indexes: logstash-*, auditd-*, linuxconfig-*, browsinghistory-* | Needs: any of logstash-*, auditd-*, linuxconfig-*, browsinghistory-*
{{GEN}}
FROM logstash-*, auditd-*, linuxconfig-*, browsinghistory-* METADATA _index
| WHERE host.os.type == "linux"
| EVAL text = COALESCE(process.command_line, linuxconfig.line, MV_CONCAT(linuxconfig.systemd.exec_start, " "), "")
| EVAL source = CASE(
    _index LIKE "browsinghistory-*", "browser history",
    text LIKE "*://*", CONCAT("URL in ", event.dataset),
    "")
| WHERE source != ""
| EVAL h = TO_LOWER(CASE(source == "browser history", COALESCE(url.domain, ""),
    REPLACE(text, "^(?s).*?[a-zA-Z]+://([^/:?#\"' ]+).*$", "$1")))
| EVAL h = REPLACE(TRIM(h), "[.]$", "")
| WHERE h != ""
| EVAL detail = CASE(source == "browser history", COALESCE(url.original, ""), text)
| STATS
    records = COUNT(*),
    first_seen = MIN(@timestamp),
    last_seen = MAX(@timestamp),
    accounts = VALUES(user.name),
    details = VALUES(detail)
  BY _index, source, h
{{SUFFIX_EVALS}}
| EVAL tool = {{DOMAIN_CASE}}
| WHERE COALESCE(tool, "") != ""
| INLINE STATS tool_hosts = COUNT_DISTINCT(_index) BY tool
| EVAL f_cmd = source != "browser history"
| EVAL f_pipe_shell = COALESCE(MV_CONCAT(details, " ") RLIKE ".*[|] *(sudo +)?(ba|z|da)?sh.*|.*[|] *(sudo +)?python.*", false)
| EVAL score = 2 + CASE(f_cmd, 2, 0) + CASE(f_pipe_shell, 2, 0) + CASE(tool_hosts == 1, 1, 0)
| EVAL details = MV_SLICE(details, 0, 9)
| KEEP
    _index,
    score,
    tool,
    h,
    source,
    records,
    first_seen,
    last_seen,
    accounts,
    tool_hosts,
    details
| SORT score DESC, first_seen ASC
| LIMIT 10000
'''


def fill_static(templates):
    for rel in list(templates):
        templates[rel] = templates[rel].replace("{{USERPATH}}", USERPATH_RE)


fill_static(TEMPLATES)


# ----------------------------------------------------------------------------- main
def fetch(source: str | None) -> tuple[bytes, str]:
    if source and not re.match(r"^https?://", source):
        return Path(source).read_bytes(), Path(source).resolve().as_uri()
    errors = []
    for url in ([source] if source else SOURCE_URLS):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "sof-elk-import-toolkit-lolrmm"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read(), url
        except Exception as e:  # noqa: BLE001 - report and try the next mirror
            errors.append(f"{url}: {e}")
    sys.exit("could not fetch rmm_tools.json:\n  " + "\n  ".join(errors))


def diff(old: dict, new: dict) -> list[str]:
    lines = []
    for kind in KINDS:
        o, n = old.get(kind, {}), new.get(kind, {})
        added = sorted(set(n) - set(o))
        removed = sorted(set(o) - set(n))
        moved = sorted(v for v in set(o) & set(n) if o[v] != n[v])
        if added or removed or moved:
            lines.append(f"  {kind}: +{len(added)} -{len(removed)} ~{len(moved)}"
                         + (f"  (+ {', '.join(added[:8])}{' ...' if len(added) > 8 else ''})" if added else ""))
    return lines


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--source", help="rmm_tools.json file or URL (default: lolrmm.io, then its GitHub mirror)")
    ap.add_argument("--check", action="store_true",
                    help="only report; exit 10 when the hunting indicators changed")
    ap.add_argument("--render-only", action="store_true",
                    help="rewrite the queries from the stored indicators.json")
    args = ap.parse_args()

    if args.render_only:
        ind = json.loads(INDICATORS.read_text(encoding="utf-8"))
        meta = json.loads(SOURCE.read_text(encoding="utf-8"))
    else:
        raw, url = fetch(args.source)
        tools = json.loads(raw)
        sha = hashlib.sha256(raw).hexdigest()
        old_meta = json.loads(SOURCE.read_text(encoding="utf-8")) if SOURCE.exists() else {}
        old_ind = json.loads(INDICATORS.read_text(encoding="utf-8")) if INDICATORS.exists() else {}
        ind = extract(tools)
        manifest = {clean(t.get("Name")): str(t.get("LastModified") or t.get("Created") or "")
                    for t in tools if clean(t.get("Name"))}
        meta = {
            "source_url": url,
            "sha256": sha,
            "fetched_utc": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tool_count": len(manifest),
            "tools_last_modified": dict(sorted(manifest.items(), key=lambda kv: kv[0].lower())),
        }
        old_tools = old_meta.get("tools_last_modified", {})
        added = sorted(set(manifest) - set(old_tools))
        removed = sorted(set(old_tools) - set(manifest))
        modified = sorted(n for n in set(manifest) & set(old_tools) if manifest[n] != old_tools[n])
        print(f"source: {url}\nsha256: {sha} (stored: {old_meta.get('sha256', 'none')})")
        print(f"tools: {len(manifest)}; added {len(added)}, removed {len(removed)}, modified {len(modified)}")
        for label, names in (("added", added), ("removed", removed), ("modified", modified)):
            if names:
                print(f"  {label}: {', '.join(names)}")
        changes = diff(old_ind, ind)
        print("hunting indicators: " + ("changed" if changes else "unchanged"))
        print("\n".join(changes))
        print("counts: " + ", ".join(f"{k} {len(v)}" for k, v in ind.items()))
        if args.check:
            return 10 if changes else 0
        INTEL.mkdir(parents=True, exist_ok=True)
        INDICATORS.write_text(json.dumps(ind, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        SOURCE.write_text(json.dumps(meta, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    for rel, text in render(ind, meta).items():
        path = PACK / "queries" / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(PACK.parent)} ({len(text) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

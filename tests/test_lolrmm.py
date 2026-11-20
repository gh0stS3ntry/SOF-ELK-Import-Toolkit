#!/usr/bin/env python3
"""Tests for hunting/tools/lolrmm.py (LOLRMM indicator extraction and query rendering).

    python3 tests/test_lolrmm.py -v
"""
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("lolrmm", ROOT / "hunting" / "tools" / "lolrmm.py")
L = importlib.util.module_from_spec(spec)
sys.modules["lolrmm"] = L
spec.loader.exec_module(L)

STORED = json.loads(L.INDICATORS.read_text(encoding="utf-8"))
META = json.loads(L.SOURCE.read_text(encoding="utf-8"))


def tool(name, **kw):
    t = {"Name": name, "Category": "RMM", "Details": {"PEMetadata": {}, "InstallationPaths": []},
         "Artifacts": {"Disk": [], "EventLog": [], "Registry": [], "Network": [], "Other": []}}
    for k, v in kw.items():
        (t["Details"] if k in ("PEMetadata", "InstallationPaths") else t["Artifacts"])[k] = v
    return t


def unescape(lit):
    return re.sub(r"\\(.)", lambda m: m.group(1), lit)


def filter_regex(expr):
    """The Java regex of a segment_filter() expression, compiled with Python's re (same syntax here)."""
    lit = re.search(r'REPLACE\(\w+, ("(?:[^"\\]|\\.)*")', expr).group(1)
    return re.compile(unescape(lit[1:-1]))


def glob_match(glob, value):
    """ES|QL LIKE semantics for the generator's globs (no escapes other than the separators)."""
    rx = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in glob)
    return re.fullmatch(rx, value, re.S) is not None


class Extraction(unittest.TestCase):
    def setUp(self):
        self.ind = L.extract([
            tool("Acme RMM",
                 InstallationPaths=["C:\\Program Files\\Acme RMM\\agent.exe", "AcmeRemote.exe", "agent.exe",
                                    "*.exe", "C:\\Program Files\\*", "Acme*.exe", "C:\\\\ProgramData\\\\AcmeData"],
                 PEMetadata={"Filename": "AcmeRemote.exe", "OriginalFileName": "svchost.exe"},
                 Network=[{"Domains": ["*.acme-rmm.com", "user_managed", "github.com", "relay-*.acme-rmm.net",
                                       "mybucket.s3.eu-west-1.amazonaws.com", "s3.eu-west-1.amazonaws.com",
                                       "1.2.3.4"]},
                          {"Domains": ["shared.example.org"], "Detection": False, "DetectionReason": "shared"}],
                 Registry=[{"Path": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\AcmeSvc\\ImagePath"},
                           {"Path": "HKLM\\SOFTWARE\\WOW6432Node\\Acme Inc\\Agent"},
                           {"Path": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"}],
                 Other=[{"Type": "ServiceName", "Value": "AcmeAgent; vendor default, see notes"},
                        {"Type": "WindowsScheduledTaskName", "Value": "AcmeWatchdog"},
                        {"Type": "LinuxSystemdUnit", "Value": "acme-agent"}],
                 Disk=[{"File": "/opt/acme/bin/acme-agent", "OS": "Linux"},
                       {"File": "C:\\ProgramData\\Acme\\logs\\acme.log", "OS": "Windows"},
                       {"File": "C:\\bin\\openssh.msi", "OS": "Windows"}],
                 EventLog=[{"EventID": 7045, "ServiceName": "Acme Remote Service",
                            "ImagePath": "\"C:\\Program Files\\Acme RMM\\AcmeSvc.exe\" --service"}]),
        ])

    def test_generic_names_only_with_folder(self):
        self.assertIn("acmeremote.exe", self.ind["win_exe"])
        self.assertIn("acmesvc.exe", self.ind["win_exe"])
        self.assertNotIn("agent.exe", self.ind["win_exe"])
        self.assertNotIn("svchost.exe", self.ind["win_exe"])
        self.assertIn("*\\program files\\acme rmm\\agent.exe", self.ind["win_path"])
        self.assertIn("acme*.exe", self.ind["win_exe_glob"])

    def test_unsafe_globs_dropped(self):
        globs = set(self.ind["win_path"]) | set(self.ind["win_file"])
        self.assertNotIn("*\\program files\\*", globs)
        self.assertFalse(any(g.endswith("openssh.msi") for g in globs))
        self.assertIn("*\\programdata\\acmedata\\*", globs)          # folder, doubled backslashes collapsed
        self.assertIn("*\\programdata\\acme\\logs\\acme.log", self.ind["win_file"])

    def test_domains(self):
        self.assertEqual(set(self.ind["domain"]), {"acme-rmm.com", "mybucket.s3.eu-west-1.amazonaws.com"})
        self.assertEqual(set(self.ind["domain_glob"]), {"relay-*.acme-rmm.net"})
        self.assertEqual(set(self.ind["ip"]), {"1.2.3.4"})

    def test_services_tasks_registry(self):
        self.assertIn("acmeagent", self.ind["service"])
        self.assertIn("acmesvc", self.ind["service"])              # from the Services registry key
        self.assertIn("acme remote service", self.ind["service"])
        self.assertIn("acmewatchdog", self.ind["task"])
        self.assertIn("*\\acme inc\\agent", self.ind["registry"])
        self.assertFalse(any("currentversion\\run" in g for g in self.ind["registry"]))

    def test_linux(self):
        self.assertIn("/opt/acme/bin/acme-agent", self.ind["linux_path"])
        self.assertIn("acme-agent", self.ind["linux_exe"])
        self.assertIn("acme-agent.service", self.ind["linux_unit"])

    def test_diff(self):
        new = json.loads(json.dumps(self.ind))
        self.assertEqual(L.diff(self.ind, new), [])
        new["win_exe"]["newtool.exe"] = ["New Tool"]
        self.assertTrue(any(line.strip().startswith("win_exe: +1") for line in L.diff(self.ind, new)))


class Rendering(unittest.TestCase):
    def test_committed_queries_are_current(self):
        """The query.esql files are exactly what the stored indicators and the templates give."""
        for rel, text in L.render(STORED, META).items():
            path = L.PACK / "queries" / rel
            self.assertEqual(path.read_text(encoding="utf-8"), text,
                             f"{rel} is stale: run python3 hunting/tools/lolrmm.py --render-only")

    def test_segment_filter_keeps_every_pattern(self):
        """The one-regex first pass never drops a path that a full pattern would match."""
        win = list(STORED["win_path"]) + list(STORED["win_file"])
        rx = filter_regex(L.segment_filter("p", win, STORED["win_exe"], STORED["win_exe_glob"]))
        for g in win:
            self.assertEqual(rx.sub("", "c:" + g[1:].replace("*", "x").replace("?", "y")), "", g)
        for n in STORED["win_exe"]:
            self.assertEqual(rx.sub("", "c:\\users\\bob\\downloads\\" + n), "", n)
        for n in STORED["win_exe_glob"]:
            self.assertEqual(rx.sub("", "c:\\temp\\" + n.replace("*", "x")), "", n)
        for neg in ("c:\\windows\\system32\\svchost.exe", "c:\\windows\\system32\\dwm.exe",
                    "c:\\program files\\microsoft office\\root\\office16\\winword.exe"):
            self.assertNotEqual(rx.sub("", neg), "", neg)
        reg = filter_regex(L.segment_filter("k", list(STORED["registry"])))
        for g in STORED["registry"]:
            self.assertEqual(reg.sub("", "root" + g[1:].replace("*", "x")), "", g)
        lin = filter_regex(L.segment_filter("program", list(STORED["linux_path"]), STORED["linux_exe"], (), "/"))
        for g in STORED["linux_path"]:
            self.assertEqual(lin.sub("", g.replace("*", "x")), "", g)
        self.assertNotEqual(lin.sub("", "/usr/bin/bash"), "")

    def test_domain_suffixes(self):
        """sN = last N labels; a catalog domain of N labels matches itself and its subdomains only."""
        def suffix(h, n):
            return re.sub(r"^.*?([^.]+([.][^.]+){%d})$" % (n - 1), r"\1", h)
        self.assertEqual(suffix("relay-1.net.anydesk.com", 3), "net.anydesk.com")
        self.assertEqual(suffix("xnet.anydesk.com", 3), "xnet.anydesk.com")
        self.assertEqual(suffix("anydesk.com", 3), "anydesk.com")      # fewer labels: unchanged, no match
        for d in STORED["domain"]:
            n = d.count(".") + 1
            self.assertEqual(suffix("a.b." + d, n), d)

    def test_like_patterns_match_their_examples(self):
        self.assertTrue(glob_match("*\\program files\\acme rmm\\*", "c:\\program files\\acme rmm\\x.exe"))
        self.assertFalse(glob_match("*\\program files\\acme rmm\\*", "c:\\program files\\acme rmmx\\x.exe"))

    def test_no_reserved_names_or_like_lists(self):
        """No column named by/first/last, and no LIKE (...) list (one automaton, often too complex)."""
        for rel, text in L.render(STORED, META).items():
            self.assertIsNone(re.search(r"\b(by|first|last) =", text), rel)
            self.assertIsNone(re.search(r"\bLIKE \(", text), rel)


if __name__ == "__main__":
    unittest.main()

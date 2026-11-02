#!/usr/bin/env python3
"""Tests for SOF-ELK_RunChecklists.py against an in-process mock Elasticsearch.

    python3 tests/test_run_checklists.py -v

The mock answers the three calls the runner makes: the case search aggregated by _index,
the per-index profile search (host.name, labels.evidence_source, cloud.provider,
host.os.type), and POST /_query. ES|QL is not evaluated: the mock reads the rewritten
FROM line and the inserted `WHERE _index IN (...)`, and returns one row per index it
would read, so the routing, file layout, summary and super timeline can be checked.
"""
import contextlib
import csv
import importlib.util
import io
import json
import re
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("run_checklists", ROOT / "SOF-ELK_RunChecklists.py")
r = importlib.util.module_from_spec(spec)
sys.modules["run_checklists"] = r
spec.loader.exec_module(r)

CASE = "IR-2026-042"


def doc(case=CASE, **fields):
    return {"case": case, **fields}


# index -> list of flat documents
INDICES = {
    "amcache-rd01": [doc(**{"host.name": "RD01"})] * 3,
    "evtxlogs-rd01": [doc(**{"host.name": "RD01"})] * 5,
    "registry-rd01": [doc(**{"host.name": "RD01"})],
    "amcache-ws-02": [doc(**{"host.name": "WS-02"})],
    "logstash-kali": [doc(**{"host.name": "kali", "host.os.type": "linux"})] * 4,
    "bodyfile-kali": [doc(**{"host.name": "kali", "host.os.type": "linux"})],
    "httpdlog-kali": [doc(**{"host.name": "kali", "host.os.type": "linux"})],
    "aws-cloudtrail-111122223333": [doc(**{"labels.evidence_source": "111122223333", "cloud.provider": "aws"})],
    "httpdlog-111122223333": [doc(**{"labels.evidence_source": "111122223333", "cloud.provider": "aws"})],
    "logstash-2026.10": [doc()],                       # SOF-ELK dated index: ignored
    "amcache-other": [doc(case="IR-OTHER", **{"host.name": "OTHER"})],
}
QUERIES = []        # every /_query body received
FAIL_IDS = {"TRI-02"}


def case_match(d, query):
    term = query["term"]["case"]
    return str(d.get("case", "")).lower() == term["value"].lower()


def esql_result(text):
    """Fake ES|QL answer: one row per index read (after the inserted _index filter)."""
    qid = re.match(r"//\s*(\S+)", text).group(1)
    sources = re.search(r"^FROM (.+?) METADATA _index", text, re.M).group(1)
    indexes = [s.strip().strip('"') for s in sources.split(",")]
    keep = re.search(r"^\| WHERE _index IN \((.+)\)$", text, re.M)
    if keep:
        allowed = set(json.loads(f"[{keep.group(1)}]"))
        indexes = [i for i in indexes if i in allowed]
    if qid in FAIL_IDS:
        return 400, {"error": {"type": "verification_exception",
                               "reason": f"Found 1 problem\nline 5:9: Unknown column [x] in {qid}"}}
    if qid in ("EX-10", "PE-02"):
        # Stacked across hosts: one row listing every host's index.
        return 200, {"columns": [{"name": "source_indices", "type": "keyword"},
                                 {"name": "host_count", "type": "long"},
                                 {"name": "first_seen", "type": "date"},
                                 {"name": "file.path", "type": "keyword"}],
                     "values": [[indexes, len(indexes), "2023-01-17T10:00:00.000Z", "c:\\temp\\evil.exe"]]}
    if qid == "PR-01":
        # Case-wide stack, no index or host column.
        return 200, {"columns": [{"name": "account", "type": "keyword"}, {"name": "hosts", "type": "long"},
                                 {"name": "first_seen", "type": "date"}],
                     "values": [["svc_backup", 2, "2023-01-18T01:02:03.000Z"]]}
    if qid.startswith("L") and qid != "LTRI-01" and qid[1:3] != "TR":
        # Linux queries group by host.name and list their indexes.
        hosts = sorted({i.split("-", 1)[1] for i in indexes})
        return 200, {"columns": [{"name": "host.name", "type": "keyword"}, {"name": "score", "type": "integer"},
                                 {"name": "last_seen", "type": "date"}, {"name": "indexes", "type": "keyword"}],
                     "values": [[h, 3, "2026-10-31T10:41:00.000Z", [i for i in indexes if i.endswith(h)]]
                                for h in hosts]}
    rows = []
    for n, index in enumerate(indexes):
        rows.append([index, f"2023-01-{10 + n:02d}T08:00:0{n % 10}.123Z", "tdungan", f"{qid} row {n}",
                     "2023-01-01T00:00:00.000Z"])
    return 200, {"columns": [{"name": "_index", "type": "keyword"}, {"name": "@timestamp", "type": "date"},
                             {"name": "user.name", "type": "keyword"}, {"name": "message", "type": "keyword"},
                             {"name": "file.created", "type": "date"}],
                 "values": rows}


class MockEs(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length))
        path = unquote(urlsplit(self.path).path)
        if path == "/_query":
            QUERIES.append(body)
            return self.reply(*esql_result(body["query"]))
        target, endpoint = path.split("/")[1:3]
        if endpoint != "_search":
            return self.reply(404, {})
        if target == "*,-.*":
            buckets = [{"key": name, "doc_count": n} for name, docs in sorted(INDICES.items())
                       if (n := sum(case_match(d, body["query"]) for d in docs))]
            return self.reply(200, {"aggregations": {"indexes": {"buckets": buckets}}})
        docs = [d for d in INDICES.get(target, []) if case_match(d, body["query"])]
        aggs = {}
        for name, agg in body["aggs"].items():
            values = [d[agg["terms"]["field"]] for d in docs if agg["terms"]["field"] in d]
            aggs[name] = {"buckets": [{"key": values[0], "doc_count": len(values)}] if values else []}
        self.reply(200, {"aggregations": aggs})


class Answers:
    def __init__(self, *answers):
        self.answers = list(answers)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return self.answers.pop(0)


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.reader(fh))


class RunnerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), MockEs)
        cls.url = f"http://127.0.0.1:{cls.server.server_address[1]}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        QUERIES.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *extra, answers=None):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = r.main([CASE, str(self.out), "--es", self.url, "--max-retries", "0", *extra],
                          input_fn=answers or Answers())
        return code, stdout.getvalue()

    def test_full_run(self):
        # Prompt order: hosts sorted by name (kali, RD01, WS-02); AWS is never asked.
        answers = Answers("linux-web-server", "bogus", "1", "2,5")
        code, output = self.run_main(answers=answers)
        self.assertEqual(code, 1, output)                     # TRI-02 fails on purpose
        self.assertEqual([p.split(":")[0] for p in answers.prompts],
                         ["Role of kali", "Role of RD01", "Role of RD01", "Role of WS-02"])
        self.assertIn("is not a role number or name", output)
        self.assertIn("ignoring logstash-2026.10", output)
        self.assertNotIn("amcache-other", output)

        # Folder per host, sub-folder per category, <ID>_<host>.csv.
        tri05 = read_csv(self.out / "RD01" / "00-triage" / "TRI-05_RD01.csv")
        self.assertEqual(tri05[0], ["_index", "@timestamp", "user.name", "message", "file.created"])
        self.assertEqual({row[0] for row in tri05[1:]}, {"amcache-rd01"})
        self.assertTrue((self.out / "WS-02" / "00-triage" / "TRI-05_WS-02.csv").is_file())
        self.assertTrue((self.out / "kali" / "00-triage" / "LTRI-01_kali.csv").is_file())
        self.assertTrue((self.out / "AWS" / "00-triage" / "ATRI-01_AWS.csv").is_file())
        self.assertTrue((self.out / "AWS" / "TA0001-initial-access" / "AIA-04_AWS.csv").is_file())

        # A row stacked across hosts goes to every host it lists.
        for host in ("RD01", "WS-02"):
            rows = read_csv(self.out / host / "TA0002-execution" / f"EX-10_{host}.csv")
            self.assertEqual(len(rows), 2, host)
            self.assertEqual(rows[1][0], "amcache-rd01 | amcache-ws-02")
        # Linux rows are routed by host.name.
        lpe = read_csv(next((self.out / "kali").glob("*/LPE-01_kali.csv")))
        self.assertEqual([row[0] for row in lpe[1:]], ["kali"])

        # Every query is filtered on the case and reads only this group's indexes.
        self.assertTrue(QUERIES)
        for body in QUERIES:
            self.assertEqual(body["filter"]["term"]["case"]["value"], CASE)
            text = body["query"]
            sources = re.search(r"^FROM (.+?) METADATA _index", text, re.M).group(1)
            self.assertNotIn("logstash-2026.10", sources)
            self.assertNotIn("amcache-other", sources)
            if text.startswith("// A"):
                self.assertNotIn("kali", sources)
            else:
                self.assertNotIn("111122223333", sources)
        # Each query runs once, not once per host.
        ids = [re.match(r"//\s*(\S+)", b["query"]).group(1) for b in QUERIES]
        self.assertEqual(len(ids), len(set(ids)))
        # TRI-05 keeps _index, so it reads both Windows hosts but keeps rows of the requesting ones.
        tri05_text = next(b["query"] for b in QUERIES if b["query"].startswith("// TRI-05"))
        self.assertIn("FROM amcache-rd01, amcache-ws-02 METADATA _index", tri05_text)

        # Run summary: errors, skipped pivots, no-data rows.
        summary = list(csv.DictReader(open(self.out / f"{CASE}_run_summary.csv", newline="", encoding="utf-8")))
        by = {(row["host"], row["query_id"]): row for row in summary}
        self.assertEqual(by[("RD01", "TRI-02")]["status"], "error")
        self.assertIn("Unknown column", by[("RD01", "TRI-02")]["error"])
        self.assertEqual(by[("RD01", "EX-15")]["status"], "skipped")
        self.assertEqual(by[("WS-02", "TRI-02")]["status"], "no-data")      # no evtxlogs on WS-02
        self.assertEqual(by[("RD01", "TRI-05")]["status"], "ok")
        self.assertIn("Baseline (all Windows hosts) 1.2", by[("RD01", "TRI-05")]["checklist_rows"])
        self.assertIn("case-wide", by[("RD01", "PR-01")]["error"])
        # WS-02 is a web + file server: its role checklists add PE-17 (web shells, filesystem-*),
        # which finds no filesystem index there; RD01 (end user) does not run it at all.
        self.assertEqual(by[("WS-02", "PE-17")]["status"], "no-data")
        self.assertNotIn(("RD01", "PE-17"), by)

        # Super timeline: l2tcsv header, sorted by time, coverage queries left out.
        timeline = read_csv(self.out / f"{CASE}_supertimeline.csv")
        self.assertEqual(timeline[0], r.L2T_HEADER)
        rows = timeline[1:]
        self.assertTrue(rows)
        keys = [(row[0][6:10], row[0][0:2], row[0][3:5], row[1]) for row in rows]
        self.assertEqual(keys, sorted(keys))
        self.assertFalse(any("TRI-01" in row[15] for row in rows))
        tri05_events = [row for row in rows if row[15] == "esql/TRI-05" and row[8] == "RD01"]
        self.assertEqual({row[6] for row in tri05_events}, {"@timestamp", "file.created"})
        created = next(row for row in tri05_events if row[6] == "file.created")
        self.assertEqual(created[3], "...B")
        self.assertEqual(created[0:3], ["01/01/2023", "00:00:00", "UTC"])
        self.assertEqual(created[4], "AMCACHE")
        self.assertEqual(created[7], "tdungan")
        self.assertTrue(created[10].startswith("[TRI-05] Installed software"))
        self.assertTrue(any(row[8] == "111122223333" and row[5] == "AWS CloudTrail" for row in rows))
        self.assertFalse(any(p.name.startswith(".timeline-") for p in self.out.iterdir()))

    def test_roles_from_command_line_and_skip(self):
        code, output = self.run_main("--role", "RD01=windows-end-user", "--role", "ws-02=skip",
                                     "--role", "kali=skip", "--no-aws")
        self.assertEqual(code, 1, output)
        self.assertTrue((self.out / "RD01").is_dir())
        self.assertFalse((self.out / "WS-02").exists())
        self.assertFalse((self.out / "AWS").exists())
        # Only RD01 asks, but the stacked query still reads WS-02 for rarity.
        ex10 = next(b["query"] for b in QUERIES if b["query"].startswith("// EX-10"))
        self.assertIn("amcache-ws-02", ex10)
        self.assertNotIn("WHERE _index IN", ex10)          # EX-10 does not return _index
        tri05 = next(b["query"] for b in QUERIES if b["query"].startswith("// TRI-05"))
        self.assertIn('| WHERE _index IN ("amcache-rd01")\n| LIMIT', tri05)
        rows = read_csv(self.out / "RD01" / "TA0002-execution" / "EX-10_RD01.csv")
        self.assertEqual(len(rows), 2)

    def test_dry_run_runs_nothing(self):
        code, output = self.run_main("--dry-run", "--role", "RD01=1", "--role", "WS-02=s", "--role", "kali=s")
        self.assertEqual(code, 0, output)
        self.assertEqual(QUERIES, [])
        self.assertIn("00-triage/TRI-05_RD01.csv  [runs]", output)
        self.assertIn("[pivot, skipped]", output)
        self.assertIn("AWS (AWS)", output)
        self.assertFalse(self.out.exists())

    def test_unknown_case(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = r.main(["IR-NOPE", str(self.out), "--es", self.url], input_fn=Answers())
        self.assertEqual(code, 1)
        self.assertIn("No index holds documents with case = 'IR-NOPE'", stdout.getvalue())


class UnitTest(unittest.TestCase):
    def test_parse_role_answer(self):
        self.assertEqual(r.parse_role_answer("1"), ["windows-end-user"])
        self.assertEqual(r.parse_role_answer(" 6, 5 "), ["windows-domain-controller", "windows-file-server"])
        self.assertEqual(r.parse_role_answer("linux-web-server+8"), ["linux-web-server", "linux-database-server"])
        self.assertEqual(r.parse_role_answer("skip"), [])
        for bad in ("0", "15", "web", "", "1,7"):
            with self.assertRaises(ValueError, msg=bad):
                r.parse_role_answer(bad)

    def test_every_role_has_checklists(self):
        for role in r.ROLES:
            target = r.Target("x", "X", roles=[role])
            files = r.checklists_for(target)
            self.assertEqual(files[0], r.BASELINES[r.ROLES[role][0]])
            self.assertTrue(r.build_plan(files), role)
        self.assertEqual(len(r.build_plan(r.checklists_for(r.Target("aws", "AWS")))), 31)

    def test_build_query(self):
        query = r.load_query(r.QUERIES / "windows" / "00-triage" / "TRI-05-installed-software")
        text = r.build_query(query, ["amcache-rd01", "amcache-ws-02"], ["amcache-rd01"])
        self.assertIn("\nFROM amcache-rd01, amcache-ws-02 METADATA _index\n", text)
        self.assertTrue(text.rstrip().endswith('| WHERE _index IN ("amcache-rd01")\n| LIMIT 10000'))
        self.assertNotIn("amcache-*", text.split("\n", 3)[3])
        linux = r.load_query(next((r.QUERIES / "linux" / "TA0003-persistence").glob("LPE-01-*")))
        text = r.build_query(linux, ["logstash-kali"], None, "2026-10-01T00:00:00Z")
        self.assertIn('| EVAL since = TO_DATETIME("2026-10-01T00:00:00Z")', text)
        self.assertNotIn("WHERE _index IN", text)

    def test_outputs_index(self):
        def q(rel):
            return r.load_query(next(r.QUERIES.glob(rel)))
        self.assertTrue(q("windows/00-triage/TRI-05-*").keeps_index)
        self.assertFalse(q("windows/TA0002-execution/EX-10-*").keeps_index)
        self.assertFalse(q("linux/TA0003-persistence/LPE-01-*").keeps_index)
        self.assertTrue(q("aws/00-triage/ATRI-01-*").keeps_index)

    def test_every_pack_query_loads(self):
        folders = [p.parent for p in r.QUERIES.rglob("query.esql")]
        self.assertGreater(len(folders), 150)
        for folder in folders:
            query = r.load_query(folder)
            self.assertTrue(query.families, folder)
            self.assertTrue(set(query.families) <= set(r.KNOWN_FAMILIES), (folder, query.families))

    def test_sort_key(self):
        self.assertEqual(r.sort_key("2023-01-01T00:02:46.527Z"), "2023-01-01T00:02:46.527000000")
        self.assertEqual(r.sort_key("2023-01-01T00:02:46.527959123Z"), "2023-01-01T00:02:46.527959123")
        self.assertEqual(r.sort_key("2023-01-01T08:02:46+08:00"), "2023-01-01T00:02:46.000000000")
        self.assertIsNone(r.sort_key("yesterday"))
        self.assertEqual(r.macb(["file.mtime", "file.ctime"]), "M.C.")
        self.assertEqual(r.macb(["@timestamp"]), "....")

    def test_timeline_external_sort_and_dedupe(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            timeline = r.Timeline(work, chunk_rows=1000)
            timeline.chunk_rows = 7                 # force many on-disk runs
            target = r.Target("rd01", "RD01", {"amcache": ["amcache-rd01"]})
            query = r.load_query(r.QUERIES / "windows" / "00-triage" / "TRI-05-installed-software")
            item = r.PlanItem(query, ["Baseline 1.2"])
            names = ["_index", "@timestamp", "name"]
            for n in range(200):
                row = ["amcache-rd01", f"2023-01-01T00:{(n * 37) % 60:02d}:{n % 60:02d}.000Z", f"tool{n % 60}"]
                timeline.add_row(target, item, names, [1], row, "RD01/x.csv")
            self.assertGreater(len(timeline.runs), 20)
            out = work / "timeline.csv"
            written = timeline.write(out)
            rows = read_csv(out)[1:]
            self.assertEqual(written, len(rows))
            self.assertEqual(len(rows), len({tuple(row) for row in rows}))     # duplicates dropped
            self.assertEqual(len(rows), 60)
            times = [row[1] for row in rows]
            self.assertEqual(times, sorted(times))
            self.assertEqual([p.name for p in work.iterdir()], ["timeline.csv"])


if __name__ == "__main__":
    unittest.main()

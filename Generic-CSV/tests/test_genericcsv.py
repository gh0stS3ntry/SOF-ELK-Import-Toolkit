#!/usr/bin/env python3
"""Tests for genericcsv2sofelk.py (standard library only, no Elasticsearch needed).

    python3 Generic-CSV/tests/test_genericcsv.py -v
"""
import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import genericcsv2sofelk as g  # noqa: E402


def write(folder, rel, text, encoding="utf-8"):
    path = Path(folder) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(text.encode(encoding))
    return path


def docs_for(path, **kw):
    csvf = g.CsvFile(path)
    ts = g.choose_timestamp(csvf, kw.pop("wanted", []), kw.pop("detect", True), "Z", "mdy")
    out = []
    for n, cells in csvf.rows():
        out.append(g.make_doc(csvf, n, cells, abs_path=str(path), rel_path=path.name,
                              hostname="rd01", case=kw.get("case"), ts_index=ts,
                              default_tz="Z", date_order="mdy", ingested="2026-10-27T00:00:00.000Z"))
    return csvf, ts, out


class FieldNames(unittest.TestCase):
    def test_sanitize(self):
        self.assertEqual(
            g.sanitize_columns(["Time Created", "user.name", "", "1st", "Host", "@timestamp",
                                "Event ID", "event id", "Path (Full)"]),
            ["Time_Created", "user_name", "column_3", "f_1st", "Host_csv", "timestamp",
             "Event_ID", "event_id_2", "Path_Full"])

    def test_long_names_are_truncated(self):
        (name,) = g.sanitize_columns(["x" * 400])
        self.assertEqual(len(name.encode()), g.MAX_FIELD_BYTES)


class Times(unittest.TestCase):
    def test_formats(self):
        cases = {
            "2026-10-25 08:19:00.0483730": "2026-10-25T08:19:00.048Z",
            "2026-10-25T08:19:00Z": "2026-10-25T08:19:00.000Z",
            "2026-10-25T08:19:00+0800": "2026-10-25T08:19:00.000+08:00",
            "2026-10-25 08:19": "2026-10-25T08:19:00.000Z",
            "2026-10-25": "2026-10-25T00:00:00.000Z",
            "10/25/2026 8:19 PM": "2026-10-25T20:19:00.000Z",
            "10/25/2026 12:05:09 AM": "2026-10-25T00:05:09.000Z",
        }
        for raw, want in cases.items():
            self.assertEqual(g.parse_time(raw), want, raw)
        self.assertEqual(g.parse_time("25/10/2026 08:19", date_order="dmy"), "2026-10-25T08:19:00.000Z")
        self.assertEqual(g.parse_time("2026-10-25 08:19:00", default_tz="+08:00"), "2026-10-25T08:19:00.000+08:00")
        for bad in ("", "hello", "13/45/2026", "2026-02-30 00:00:00", "1729845540"):
            self.assertIsNone(g.parse_time(bad), bad)


class Reading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_basic_document(self):
        p = write(self.dir, "a/logons.csv",
                  "TimeCreated,User Name,Count,\n2026-10-25 08:19:00,tdungan,3,\n\n2026-10-25 09:00:00,,4,x\n")
        csvf, ts, docs = docs_for(p, case="IR-1")
        self.assertEqual(csvf.fields, ["TimeCreated", "User_Name", "Count"])
        self.assertEqual(ts, 0)
        self.assertEqual(len(docs), 2)
        d = docs[0]
        self.assertEqual(d["@timestamp"], "2026-10-25T08:19:00.000Z")
        self.assertEqual(d["log"]["file"]["path"], str(p))
        self.assertEqual(d["host"]["name"], "rd01")
        self.assertEqual(d["case"], "IR-1")
        self.assertEqual(d["Count"], "3")                       # kept as a string (keyword)
        self.assertEqual(d["event"]["sequence"], 1)
        self.assertEqual(d["genericcsv"]["timestamp_source"], "TimeCreated")
        self.assertNotIn("User_Name", docs[1])                   # empty cells are left out
        self.assertEqual(docs[1]["event"]["sequence"], 2)        # blank lines are not counted
        self.assertEqual(docs[1]["genericcsv"]["extra_cells"], ["x"])

    def test_timestamp_choice(self):
        p = write(self.dir, "t.csv", "Id,Name,When\n1,a,10/25/2026 8:19 AM\n2,b,bad\n")
        _, ts, docs = docs_for(p)
        self.assertIsNone(ts)                                   # 1 of 2 values is not enough
        self.assertEqual(docs[0]["genericcsv"]["timestamp_source"], "ingest_time")
        p = write(self.dir, "u.csv", "Id,Value,Other\n1,2026-10-25 01:02:03,x\n")
        _, ts, _ = docs_for(p)
        self.assertEqual(ts, 1)                                 # unnamed date column still found
        _, ts, _ = docs_for(p, detect=False)
        self.assertIsNone(ts)
        p = write(self.dir, "v.csv", "Created,Modified,LocalTime\n2026-01-01,2026-02-02,2026-03-03\n")
        _, ts, docs = docs_for(p, wanted=["modified"])
        self.assertEqual(ts, 1)
        self.assertEqual(docs[0]["@timestamp"], "2026-02-02T00:00:00.000Z")

    def test_encodings_and_delimiters(self):
        p = write(self.dir, "u16.csv", "﻿Name\tSize\nnotepad.exe\t100\n", "utf-16")
        csvf, _, docs = docs_for(p)
        self.assertEqual(csvf.fields, ["Name", "Size"])
        self.assertEqual(docs[0]["Name"], "notepad.exe")
        p = write(self.dir, "excel.csv", "sep=;\nA;B\n1,5;2\n")
        csvf, _, docs = docs_for(p)
        self.assertEqual((docs[0]["A"], docs[0]["B"]), ("1,5", "2"))
        p = write(self.dir, "ps.csv", '#TYPE System.Diagnostics.Process\n"Name","Id"\n"svchost","4"\n')
        csvf, _, docs = docs_for(p)
        self.assertEqual(docs[0], {**docs[0], "Name": "svchost", "Id": "4"})
        p = write(self.dir, "latin.csv", "Name\ncaf\xe9\n", "cp1252")
        _, _, docs = docs_for(p)
        self.assertEqual(docs[0]["Name"], "caf\xe9")

    def test_find_files_and_exclude(self):
        write(self.dir, "a/one.csv", "x\n1\n")
        write(self.dir, "a/b/TWO.CSV", "x\n1\n")
        write(self.dir, "a/b/skip_EvtxECmd.csv", "x\n1\n")
        write(self.dir, "a/notes.txt", "x\n")
        found = [p.relative_to(self.dir).as_posix() for p in g.find_csv_files(self.dir, ["*EvtxECmd*"])]
        self.assertEqual(found, ["a/one.csv", "a/b/TWO.CSV"])

    def test_ids_are_stable(self):
        self.assertEqual(g.doc_id("rd01", "/x/a.csv", 1), g.doc_id("rd01", "/x/a.csv", 1))
        self.assertNotEqual(g.doc_id("rd01", "/x/a.csv", 1), g.doc_id("rd01", "/y/a.csv", 1))

    def test_dry_run(self):
        write(self.dir, "a.csv", "TimeCreated,Name\n2026-10-25 08:19:00,a\n")
        write(self.dir, "b/c.csv", "Other\nz\n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = g.main([str(self.dir), "--hostname", "RD01", "--dry-run"])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("2 CSV file(s)", text)
        self.assertIn("genericcsv-rd01", text)
        self.assertIn("3 distinct column(s)", text)


if __name__ == "__main__":
    unittest.main()

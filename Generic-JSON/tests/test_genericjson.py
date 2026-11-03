#!/usr/bin/env python3
"""Tests for genericjson2sofelk.py (standard library only, no Elasticsearch needed).

    python3 Generic-JSON/tests/test_genericjson.py -v
"""
import contextlib
import gzip
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import genericjson2sofelk as g  # noqa: E402


def write(folder, rel, text, encoding="utf-8"):
    path = Path(folder) / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    data = text.encode(encoding)
    path.write_bytes(gzip.compress(data) if rel.endswith(".gz") else data)
    return path


def docs_for(path, wanted=(), detect=True, records_keys=(), case=None, conv=None, unwrap=True):
    """Scan then convert one file the way main() does."""
    jf = g.JsonFile(path, records_keys, unwrap)
    conv = conv or g.Converter()
    sampler = g.TimestampSampler("Z", "mdy")
    _, err = g.scan_file(jf, conv, sampler)
    ts = sampler.choose(list(wanted), detect)
    out = []
    for n, record in jf.records():
        leaves = {}
        fields = conv.convert(record, leaves)
        raw = leaves.get(ts, (None, None))[1] if ts else None
        out.append(g.make_doc(fields, n, raw, jf=jf, abs_path=str(path), rel_path=path.name,
                              hostname="rd01", case=case, ts_path=ts, default_tz="Z",
                              date_order="mdy", ingested="2026-11-03T00:00:00.000Z"))
    return jf, ts, out, err


class FieldNames(unittest.TestCase):
    def test_sanitize_and_nesting(self):
        conv = g.Converter()
        doc = conv.convert({"Time Created": "x", "user.name": "a", "": "b", "1st": "c", "Host": "h",
                            "@timestamp": "t", "_id": "i", "event": {"host": "kept"},
                            "Event ID": 1, "event id": 2})
        self.assertEqual(doc, {"Time_Created": "x", "user_name": "a", "field": "b", "f_1st": "c",
                               "Host_json": "h", "timestamp": "t", "id": "i",
                               "event_json": {"host": "kept"},     # reserved only at the top level
                               "Event_ID": "1", "event_id_2": "2"})

    def test_values_are_text(self):
        doc = g.Converter().convert({"n": 5, "f": 1.5, "b": True, "z": None, "e": "", "o": {},
                                     "l": [1, "a", None, [2, False]], "lo": [{"a": 1}, {"a": 2, "b": None}],
                                     "mix": [1, {"a": 1}]})
        self.assertEqual(doc, {"n": "5", "f": "1.5", "b": "true", "l": ["1", "a", "2", "false"],
                               "lo": [{"a": "1"}, {"a": "2"}], "mix": ["1", '{"a": 1}']})

    def test_depth_limit(self):
        doc = g.Converter(max_depth=2).convert({"a": {"b": {"c": 1}}, "x": {"y": [{"z": 1}]}})
        self.assertEqual(doc, {"a": {"b": '{"c": 1}'}, "x": {"y": ['{"z": 1}']}})

    def test_shape_conflicts(self):
        conv = g.Converter()
        self.assertEqual(conv.convert({"user": "bob"}), {"user": "bob"})
        self.assertEqual(conv.convert({"user": {"name": "amy"}}), {"user_obj": {"name": "amy"}})
        self.assertEqual(conv.convert({"user": "carl"}), {"user": "carl"})
        self.assertEqual(conv.kinds["user"], g.LEAF)
        self.assertEqual(conv.kinds["user_obj.name"], g.LEAF)
        # an existing index mapping wins over the first record
        conv = g.Converter(kinds=g.mapping_kinds({"user": {"properties": {"name": {"type": "keyword"}}}}))
        self.assertEqual(conv.convert({"user": "bob"}), {"user_value": "bob"})

    def test_mapping_for(self):
        conv = g.Converter()
        conv.convert({"a": {"b": 1, "c": [{"d": 1}]}, "e": "x"})
        props = g.mapping_for(conv.kinds, conv.kinds)
        kw = {"type": "keyword", "ignore_above": 8191}
        self.assertEqual(props, {"a": {"properties": {"b": kw, "c": {"properties": {"d": kw}}}}, "e": kw})


class Times(unittest.TestCase):
    def test_text_and_epoch(self):
        self.assertEqual(g.parse_time("2026-10-25T08:19:00.0483730Z"), "2026-10-25T08:19:00.048Z")
        self.assertEqual(g.parse_time("10/25/2026 8:19 PM"), "2026-10-25T20:19:00.000Z")
        self.assertEqual(g.parse_epoch(1761380340), "2025-10-25T08:19:00.000Z")
        self.assertEqual(g.parse_epoch(1761380340123), "2025-10-25T08:19:00.123Z")
        self.assertEqual(g.parse_epoch(1761380340.5), "2025-10-25T08:19:00.500Z")
        for bad in (True, 42, "1761380340", 9e30):
            self.assertIsNone(g.parse_epoch(bad), bad)
        # epoch numbers count only under a time-like name
        self.assertIsNotNone(g.to_time(1761380340, "eventTime", "Z", "mdy"))
        self.assertIsNone(g.to_time(1761380340, "pid", "Z", "mdy"))


class Reading(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_array_document(self):
        p = write(self.dir, "a/logons.json", json.dumps([
            {"TimeCreated": "2026-10-25 08:19:00", "User": {"Name": "tdungan", "Sid": "S-1-5"}, "Count": 3},
            {"TimeCreated": "2026-10-25 09:00:00", "Count": 4}]))
        jf, ts, docs, err = docs_for(p, case="IR-1")
        self.assertIsNone(err)
        self.assertEqual((jf.layout, ts, len(docs)), ("array", "TimeCreated", 2))
        d = docs[0]
        self.assertEqual(d["@timestamp"], "2026-10-25T08:19:00.000Z")
        self.assertEqual(d["User"], {"Name": "tdungan", "Sid": "S-1-5"})
        self.assertEqual(d["Count"], "3")
        self.assertEqual(d["log"]["file"]["path"], str(p))
        self.assertEqual(d["host"]["name"], "rd01")
        self.assertEqual(d["case"], "IR-1")
        self.assertEqual(d["event"]["sequence"], 1)
        self.assertEqual(d["genericjson"]["timestamp_source"], "TimeCreated")
        self.assertEqual(docs[1]["event"]["sequence"], 2)

    def test_json_lines_with_bad_line(self):
        p = write(self.dir, "e.jsonl", '{"ts": 1761380340, "msg": "a"}\n\nnot json\n{"ts": 1761380341, "msg": "b"}\n')
        jf, ts, docs, _ = docs_for(p)
        self.assertEqual((jf.layout, ts, len(docs)), ("lines", "ts", 2))
        self.assertEqual(docs[1]["@timestamp"], "2025-10-25T08:19:01.000Z")
        self.assertEqual([n for n, _ in jf.line_errors], [3])

    def test_concatenated_and_single_objects(self):
        p = write(self.dir, "c.json", '{\n "a": 1\n}\n{\n "a": 2\n}\n')
        jf, _, docs, _ = docs_for(p)
        self.assertEqual((jf.layout, [d["a"] for d in docs]), ("object", ["1", "2"]))
        p = write(self.dir, "s.json", '{"a": {"b": "x"}}')
        _, _, docs, _ = docs_for(p)
        self.assertEqual(docs[0]["a"], {"b": "x"})

    def test_unwrap(self):
        body = json.dumps({"Records": [{"eventTime": "2026-10-20T01:05:00Z", "eventName": "GetObject"},
                                       {"eventTime": "2026-10-20T01:06:00Z", "eventName": "PutObject"}]})
        p = write(self.dir, "ct.json.gz", body)
        jf, ts, docs, _ = docs_for(p)
        self.assertEqual((ts, [d["eventName"] for d in docs]), ("eventTime", ["GetObject", "PutObject"]))
        self.assertEqual(jf.unwrapped_from, {"Records"})
        _, _, docs, _ = docs_for(p, unwrap=False)
        self.assertEqual(len(docs), 1)
        p = write(self.dir, "es.json", json.dumps({"took": 1, "hits": {"hits": [{"_source": {"a": 1}}, {"_source": {"a": 2}}]}}))
        _, _, docs, _ = docs_for(p, records_keys=["hits.hits"])
        self.assertEqual([d["source"]["a"] for d in docs], ["1", "2"])

    def test_timestamp_choice(self):
        p = write(self.dir, "t.json", json.dumps([{"Id": 1, "When": "10/25/2026 8:19 AM"}, {"Id": 2, "When": "bad"}]))
        _, ts, docs, _ = docs_for(p)
        self.assertIsNone(ts)
        self.assertEqual(docs[0]["genericjson"]["timestamp_source"], "ingest_time")
        p = write(self.dir, "v.json", json.dumps([{"meta": {"Created": "2026-01-01", "Modified": "2026-02-02"}}]))
        _, ts, docs, _ = docs_for(p, wanted=["META.modified"])
        self.assertEqual((ts, docs[0]["@timestamp"]), ("meta.Modified", "2026-02-02T00:00:00.000Z"))
        _, ts, _, _ = docs_for(p, detect=False)
        self.assertIsNone(ts)
        p = write(self.dir, "w.json", json.dumps([{"@timestamp": "2026-03-03T00:00:00Z"}]))
        _, ts, _, _ = docs_for(p, wanted=["@timestamp"])
        self.assertEqual(ts, "timestamp")

    def test_large_array_streams_across_chunks(self):
        old = g.CHUNK_CHARS
        g.CHUNK_CHARS = 64
        try:
            records = [{"i": i, "pad": "x" * (i % 50), "n": 12345678901234} for i in range(300)]
            p = write(self.dir, "big.json", json.dumps(records, indent=1))
            _, _, docs, err = docs_for(p)
        finally:
            g.CHUNK_CHARS = old
        self.assertIsNone(err)
        self.assertEqual([d["i"] for d in docs], [str(i) for i in range(300)])
        self.assertTrue(all(d["n"] == "12345678901234" for d in docs))

    def test_truncated_array_reports_error(self):
        p = write(self.dir, "cut.json", '[{"a": 1}, {"a": 2}, {"a"')
        jf = g.JsonFile(p)
        got = []
        with self.assertRaises(g.JsonFileError):
            for _, rec in jf.records():
                got.append(rec)
        self.assertEqual(len(got), 2)

    def test_encodings(self):
        p = write(self.dir, "u16.json", '﻿[{"Name": "caf\xe9"}]', "utf-16")
        _, _, docs, _ = docs_for(p)
        self.assertEqual(docs[0]["Name"], "caf\xe9")
        p = write(self.dir, "bom.json", '﻿{"a": "b"}')
        _, _, docs, _ = docs_for(p)
        self.assertEqual(docs[0]["a"], "b")

    def test_scalars_become_value(self):
        p = write(self.dir, "s.json", '["a", 2]')
        _, _, docs, _ = docs_for(p)
        self.assertEqual([d["value"] for d in docs], ["a", "2"])

    def test_find_files_and_exclude(self):
        for rel in ("a/one.json", "a/b/TWO.JSONL", "a/b/c.ndjson.gz", "a/skip-Digest.json", "a/notes.txt"):
            write(self.dir, rel, "{}")
        found = [p.relative_to(self.dir).as_posix() for p in g.find_json_files(self.dir, ["*Digest*"])]
        self.assertEqual(found, ["a/one.json", "a/b/c.ndjson.gz", "a/b/TWO.JSONL"])

    def test_ids_are_stable(self):
        self.assertEqual(g.doc_id("rd01", "/x/a.json", 1), g.doc_id("rd01", "/x/a.json", 1))
        self.assertNotEqual(g.doc_id("rd01", "/x/a.json", 1), g.doc_id("rd01", "/y/a.json", 1))

    def test_dry_run(self):
        write(self.dir, "a.json", '[{"TimeCreated": "2026-10-25 08:19:00", "Name": "a"}]')
        write(self.dir, "b/c.jsonl", '{"Other": {"x": 1}}\n')
        write(self.dir, "b/empty.json", "  \n")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = g.main([str(self.dir), "--hostname", "RD01", "--dry-run", "--keep-original"])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("2 JSON file(s)", text)
        self.assertIn("genericjson-rd01", text)
        self.assertIn("3 new value field(s) and 1 new object(s)", text)
        self.assertIn('"original": "{\\"TimeCreated\\"', text)


if __name__ == "__main__":
    unittest.main()

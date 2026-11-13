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
        found = [p.relative_to(self.dir).as_posix() for p in g.find_input_files(self.dir, ["*EvtxECmd*"])]
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


# --------------------------------------------------------------------------- XLSX

NS = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
NS_R = 'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"'
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"


def make_xlsx(path, sheets, shared=(), date1904=False, chartsheet=False):
    """Write a minimal .xlsx by hand (stdlib only). sheets: [(name, state, sheetData xml)].

    Styles: s=0 General, 1 = m/d/yyyy (14), 2 = custom datetime with ms (164),
    3 = h:mm:ss (21), 4 = [h]:mm:ss (46, elapsed), 5 = 0.00% (10).
    """
    import zipfile
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    sheet_xml, rels = [], []
    for i, (name, state, _) in enumerate(sheets, 1):
        st = f' state="{state}"' if state != "visible" else ""
        sheet_xml.append(f'<sheet name="{name}" sheetId="{i}"{st} r:id="rId{i}"/>')
        rels.append(f'<Relationship Id="rId{i}" Type="{REL}/worksheet" Target="worksheets/sheet{i}.xml"/>')
    if chartsheet:
        n = len(sheets) + 1
        sheet_xml.append(f'<sheet name="Chart1" sheetId="{n}" r:id="rId{n}"/>')
        rels.append(f'<Relationship Id="rId{n}" Type="{REL}/chartsheet" Target="chartsheets/sheet1.xml"/>')
    rels.append(f'<Relationship Id="rS" Type="{REL}/sharedStrings" Target="sharedStrings.xml"/>')
    rels.append(f'<Relationship Id="rT" Type="{REL}/styles" Target="/xl/styles.xml"/>')
    pr = '<workbookPr date1904="1"/>' if date1904 else "<workbookPr/>"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("_rels/.rels",
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    f'<Relationship Id="rId1" Type="{REL}/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        zf.writestr("xl/workbook.xml", f'<workbook {NS} {NS_R}>{pr}<sheets>{"".join(sheet_xml)}</sheets></workbook>')
        zf.writestr("xl/_rels/workbook.xml.rels",
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                    + "".join(rels) + "</Relationships>")
        zf.writestr("xl/sharedStrings.xml", f'<sst {NS}>' + "".join(shared) + "</sst>")
        zf.writestr("xl/styles.xml",
                    f'<styleSheet {NS}><numFmts count="1"><numFmt numFmtId="164"'
                    ' formatCode="yyyy\\-mm\\-dd hh:mm:ss.000;@"/></numFmts><cellXfs count="6">'
                    '<xf numFmtId="0"/><xf numFmtId="14"/><xf numFmtId="164"/><xf numFmtId="21"/>'
                    '<xf numFmtId="46"/><xf numFmtId="10"/></cellXfs></styleSheet>')
        for i, (_, _, data) in enumerate(sheets, 1):
            zf.writestr(f"xl/worksheets/sheet{i}.xml", f'<worksheet {NS}><sheetData>{data}</sheetData></worksheet>')
        if chartsheet:
            zf.writestr("xl/chartsheets/sheet1.xml", f'<chartsheet {NS}/>')
    return path


SHARED = [
    "<si><t>TimeCreated</t></si>",                                   # 0
    "<si><t>User Name</t></si>",                                     # 1
    "<si><r><t>rich </t></r><r><rPr><b/></rPr><t>text</t></r><rPh><t>x</t></rPh></si>",  # 2
    "<si><t>tab_x0009_here _x005F_x0041_</t></si>",                  # 3
    "<si><t>Count</t></si>",                                         # 4
]
LOGONS = (
    '<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>4</v></c>'
    '<c r="D1" t="inlineStr"><is><t>Flag</t></is></c><c r="E1" t="inlineStr"><is><t>Day</t></is></c>'
    '<c r="F1" t="inlineStr"><is><t>Clock</t></is></c><c r="G1" t="inlineStr"><is><t>Elapsed</t></is></c></row>'
    '<row r="2"><c r="A2" s="2"><v>46320.34652777778</v></c><c r="B2" t="s"><v>2</v></c><c r="C2" s="5"><v>3.0</v></c>'
    '<c r="D2" t="b"><v>1</v></c><c r="E2" s="1"><v>46319</v></c><c r="F2" s="3"><v>0.5</v></c><c r="G2" s="4"><v>1.5</v></c></row>'
    '<row r="4"><c r="A4" t="str"><v>2026-10-25 09:00:00</v></c><c r="B4" t="s"><v>3</v></c><c r="C4" t="e"><v>#N/A</v></c>'
    '<c r="J4" t="inlineStr"><is><t>extra</t></is></c></row>'
    '<row r="5"><c r="A5" t="s"><v>99</v></c></row>'                 # bad shared index -> blank row
    '<row><c s="2"><v>46320</v></c><c><v>7.0</v></c><c t="inlineStr"><is><t>n</t></is></c></row>'   # row 6, no refs
)
OFFSET = (
    '<row r="3"><c r="C3" t="inlineStr"><is><t>Note</t></is></c><c r="D3" t="inlineStr"><is><t>When</t></is></c></row>'
    '<row r="5"><c r="A5" t="inlineStr"><is><t>margin</t></is></c><c r="C5" t="inlineStr"><is><t>n1</t></is></c>'
    '<c r="D5" s="1"><v>46320</v></c></row>'
)


class XlsxReader(unittest.TestCase):
    def test_formats(self):
        xr = g.xlsx_reader
        for code, want in {"yyyy-mm-dd": "date", "m/d/yyyy h:mm AM/PM": "datetime", "hh:mm:ss": "time",
                           "[h]:mm:ss": None, "0.00%": None, "General": None, '"day" 0': None,
                           "mmm": "date", "[$-409]dddd, mmmm d, yyyy": "date", "[Red]0.00": None,
                           "dd/mm/yyyy;@": "date", "mm:ss.0": "time"}.items():
            self.assertEqual(xr.classify_format(code), want, code)
        self.assertEqual(xr.classify_builtin(22), "datetime")
        self.assertIsNone(xr.classify_builtin(46))

    def test_serials(self):
        xr = g.xlsx_reader
        self.assertEqual(xr.serial_to_text(46320.34652777778, "datetime"), "2026-10-25 08:19:00")
        self.assertEqual(xr.serial_to_text(46320, "date"), "2026-10-25")
        self.assertEqual(xr.serial_to_text(46320.5, "date"), "2026-10-25 12:00:00")   # time kept
        self.assertEqual(xr.serial_to_text(0.25, "time"), "06:00:00")
        self.assertEqual(xr.serial_to_text(44858, "date", date1904=True), "2026-10-25")
        self.assertEqual(xr.serial_to_text(59, "date"), "1900-02-28")
        self.assertEqual(xr.serial_to_text(61, "date"), "1900-03-01")
        self.assertIsNone(xr.serial_to_text(60, "date"))                # Excel's 29 Feb 1900
        self.assertIsNone(xr.serial_to_text(-1, "date"))
        self.assertEqual(xr.unescape("a_x000D__x000A_b _x005F_x0041_"), "a\r\nb _x0041_")
        self.assertEqual(xr.unescape("_xD83D__xDE00_"), "\U0001F600")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def sheets(self, path, **kw):
        book = g.xlsx_reader.Workbook(path)
        return [g.XlsxSheet(book, n, p, st) for n, p, st in book.sheets]

    def docs(self, sheet):
        ts = g.choose_timestamp(sheet, [], True, "Z", "mdy")
        return ts, [g.make_doc(sheet, n, cells, abs_path=str(sheet.path), rel_path=sheet.path.name,
                               hostname="rd01", case=None, ts_index=ts, default_tz="Z",
                               date_order="mdy", ingested="2026-10-27T00:00:00.000Z")
                    for n, cells in sheet.rows()]

    def test_workbook(self):
        p = make_xlsx(self.dir / "book.xlsx",
                      [("Logons", "visible", LOGONS), ("Notes", "hidden", OFFSET), ("Blank", "visible", "")],
                      shared=SHARED, chartsheet=True)
        logons, notes, blank = self.sheets(p)
        self.assertEqual([s.state for s in (logons, notes)], ["visible", "hidden"])
        self.assertEqual(blank.header, [])
        self.assertEqual(logons.fields, ["TimeCreated", "User_Name", "Count", "Flag", "Day", "Clock", "Elapsed"])
        ts, docs = self.docs(logons)
        self.assertEqual(ts, 0)
        self.assertEqual(len(docs), 3)                                  # blank row 5 skipped
        d = docs[0]
        self.assertEqual(d["TimeCreated"], "2026-10-25 08:19:00")
        self.assertEqual(d["@timestamp"], "2026-10-25T08:19:00.000Z")
        self.assertEqual(d["User_Name"], "rich text")                  # rich runs joined, rPh dropped
        self.assertEqual((d["Count"], d["Flag"], d["Day"], d["Clock"], d["Elapsed"]),
                         ("3", "TRUE", "2026-10-24", "12:00:00", "1.5"))
        self.assertEqual(d["genericcsv"]["sheet_name"], "Logons")
        self.assertEqual(d["genericcsv"]["sheet_row"], 2)
        self.assertEqual(d["event"]["sequence"], 1)
        d = docs[1]
        self.assertEqual(d["@timestamp"], "2026-10-25T09:00:00.000Z")
        self.assertEqual(d["User_Name"], "tab\there _x0041_")
        self.assertEqual(d["Count"], "#N/A")
        self.assertEqual(d["genericcsv"]["extra_cells"], ["extra"])
        self.assertEqual(d["genericcsv"]["sheet_row"], 4)
        d = docs[2]
        self.assertEqual((d["TimeCreated"], d["User_Name"], d["Count"]), ("2026-10-25 00:00:00", "7", "n"))
        self.assertEqual(d["genericcsv"]["sheet_row"], 6)
        # table starting at C3: margin columns dropped, a stray margin value kept as extra
        self.assertEqual(notes.fields, ["Note", "When"])
        ts, docs = self.docs(notes)
        self.assertEqual(ts, 1)
        self.assertEqual(docs[0]["Note"], "n1")
        self.assertEqual(docs[0]["@timestamp"], "2026-10-25T00:00:00.000Z")
        self.assertEqual(docs[0]["genericcsv"]["extra_cells"], ["margin"])

    def test_1904_and_ids(self):
        p = make_xlsx(self.dir / "mac.xlsx", [("S", "visible",
                      '<row r="1"><c t="inlineStr"><is><t>Day</t></is></c></row>'
                      '<row r="2"><c s="1"><v>44858</v></c></row>')], date1904=True)
        (sheet,) = self.sheets(p)
        _, docs = self.docs(sheet)
        self.assertEqual(docs[0]["Day"], "2026-10-25")
        self.assertNotEqual(g.doc_id("rd01", "/x/b.xlsx", 1, "A"), g.doc_id("rd01", "/x/b.xlsx", 1, "B"))
        self.assertEqual(g.doc_id("rd01", "/x/a.csv", 1), g.doc_id("rd01", "/x/a.csv", 1, None))

    def test_unreadable(self):
        p = self.dir / "locked.xlsx"
        p.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 64)
        with self.assertRaises(g.xlsx_reader.XlsxError):
            g.xlsx_reader.Workbook(p)
        p = self.dir / "junk.xlsx"
        p.write_bytes(b"not a zip")
        with self.assertRaises(g.xlsx_reader.XlsxError):
            g.xlsx_reader.Workbook(p)

    def test_find_and_dry_run(self):
        write(self.dir, "a.csv", "TimeCreated,Name\n2026-10-25 08:19:00,a\n")
        make_xlsx(self.dir / "sub" / "book.xlsx",
                  [("Logons", "visible", LOGONS), ("Notes", "hidden", OFFSET)], shared=SHARED)
        write(self.dir, "sub/~$book.xlsx", "lock")
        write(self.dir, "sub/old.xls", "legacy")
        found = [p.relative_to(self.dir).as_posix() for p in g.find_input_files(self.dir, [])]
        self.assertEqual(found, ["a.csv", "sub/book.xlsx"])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = g.main([str(self.dir), "--hostname", "RD01", "--dry-run"])
        self.assertEqual(rc, 0)
        text = out.getvalue()
        self.assertIn("1 CSV file(s) and 1 XLSX workbook(s) (2 worksheet(s))", text)
        self.assertIn("sub/book.xlsx [Notes] (hidden sheet): 1 row(s)", text)
        self.assertIn("5 row(s) read", text)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            g.main([str(self.dir / "sub" / "book.xlsx"), "--hostname", "RD01", "--dry-run", "--sheet", "note*"])
        text = out.getvalue()
        self.assertIn("1 XLSX workbook(s) (1 worksheet(s))", text)
        self.assertNotIn("CSV file(s)", text)
        self.assertIn("1 row(s) read", text)


if __name__ == "__main__":
    unittest.main()

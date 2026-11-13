#!/usr/bin/env python3
"""xlsx_reader.py - read Excel .xlsx / .xlsm worksheets with the Python standard library.

Used by genericcsv2sofelk.py so that workbooks load like CSVs. An .xlsx file is a zip of
XML parts (Office Open XML / ECMA-376); this module reads them with zipfile and
xml.etree.ElementTree.iterparse, streaming each worksheet so that large sheets are not
held in memory.

What it handles:
  * every worksheet in the workbook, in workbook order (hidden sheets included; chart,
    dialog and macro sheets have no cells and are skipped);
  * shared strings, inline strings and rich-text runs (phonetic runs are ignored), with
    Excel's _xHHHH_ escapes for control characters decoded;
  * numbers, booleans (TRUE / FALSE), errors (#N/A ...), formula results (the value Excel
    last calculated and saved) and ISO date cells (t="d");
  * date / time number formats, built-in and custom, in the 1900 and 1904 date systems:
    such cells come back as text, "2026-10-25 08:19:00" (milliseconds when present),
    "2026-10-25" for a date-only format, or "08:19:00" for a time-only format below one day;
  * sparse rows and cells without an r= reference;
  * transitional and strict OOXML namespaces.

Values are the stored values, not the displayed ones: a number formatted as 12.5% comes
back as 0.125, a currency cell as its plain number. Elapsed-time formats ([h]:mm:ss) stay
numbers. Merged cells keep their value in the top-left cell only, as in the file.

Not supported: legacy .xls (BIFF) and password-protected workbooks, which are OLE files
rather than zips; open them in Excel and save as an unprotected .xlsx.
"""
from __future__ import annotations

import datetime as dt
import posixpath
import re
import zipfile
import xml.etree.ElementTree as ET

XLSX_SUFFIXES = (".xlsx", ".xlsm")
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

# Built-in number formats (ECMA-376 Part 1, 18.8.30) that show dates or times.
# 27-36 and 50-58 are the East Asian locale date formats.
BUILTIN_DATE = set(range(14, 18)) | set(range(27, 37)) | set(range(50, 59))
BUILTIN_DATETIME = {22}
BUILTIN_TIME = {18, 19, 20, 21, 45, 47}      # 46 is [h]:mm:ss, an elapsed time

ELAPSED_RE = re.compile(r"^\[(h+|m+|s+)\]$", re.I)
CELL_REF_RE = re.compile(r"^([A-Za-z]{1,3})(\d+)$")


class XlsxError(Exception):
    """The file is not a readable .xlsx workbook."""


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _rel_id(elem):
    for key, value in elem.attrib.items():
        if key.endswith("}id") or key == "id":
            return value
    return None


ESCAPE_RE = re.compile(r"_x([0-9A-Fa-f]{4})_")


def unescape(text):
    """Undo the OOXML _xHHHH_ escape that Excel uses for control characters (and for a
    literal "_x" sequence, written _x005F_xHHHH_)."""
    if "_x" not in text:
        return text
    out = ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    try:
        return out.encode("utf-16", "surrogatepass").decode("utf-16")   # rejoin surrogate pairs
    except UnicodeDecodeError:
        return out


def _text(elem):
    """Text of an <si> or <is> element: plain <t>, or the <t> of each rich-text run <r>."""
    parts = []
    for child in elem:
        name = _local(child.tag)
        if name == "t":
            parts.append(child.text or "")
        elif name == "r":
            for sub in child:
                if _local(sub.tag) == "t":
                    parts.append(sub.text or "")
        # rPh (phonetic run) and phoneticPr are not part of the cell's text
    return unescape("".join(parts))


def column_index(letters):
    """'A' -> 0, 'Z' -> 25, 'AA' -> 26."""
    n = 0
    for ch in letters.upper():
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def classify_format(code):
    """Custom number format code -> 'date', 'datetime', 'time' or None (not a date)."""
    if not code:
        return None
    section = []
    i, quoted = 0, False
    while i < len(code):                       # first section only (up to an unquoted ';')
        ch = code[i]
        if ch == '"':
            quoted = not quoted
        elif ch == ";" and not quoted:
            break
        section.append(ch)
        i += 1
    s = "".join(section)
    s = re.sub(r'"[^"]*"', "", s)              # literal text
    s = re.sub(r"\\.", "", s)                  # escaped characters
    s = re.sub(r"[_*].", "", s)                # padding / fill characters
    for bracket in re.findall(r"\[[^\]]*\]", s):
        if ELAPSED_RE.match(bracket):
            return None                        # [h]:mm:ss is a duration, not a clock time
    s = re.sub(r"\[[^\]]*\]", "", s).lower()   # colours, conditions, locale tags
    if "general" in s:
        return None
    s = s.replace("am/pm", "").replace("a/p", "")
    has_date = any(c in s for c in "yd")
    has_time = any(c in s for c in "hs")
    if not has_date and not has_time and "m" in s:
        has_date = True                        # "mmm" / "mmmm": a month name
    if has_date and has_time:
        return "datetime"
    if has_date:
        return "date"
    if has_time:
        return "time"
    return None


def classify_builtin(num_fmt_id):
    if num_fmt_id in BUILTIN_DATE:
        return "date"
    if num_fmt_id in BUILTIN_DATETIME:
        return "datetime"
    if num_fmt_id in BUILTIN_TIME:
        return "time"
    return None


def serial_to_text(value, kind, date1904=False):
    """Excel serial date number -> text, or None when it cannot be a date.

    kind is 'date', 'datetime' or 'time' (from the cell's number format).
    """
    if value < 0:
        return None
    ms = int(round(value * 86400000))
    days, ms_of_day = divmod(ms, 86400000)
    if kind == "time" and days == 0:
        h, rem = divmod(ms_of_day, 3600000)
        mi, rem = divmod(rem, 60000)
        s, frac = divmod(rem, 1000)
        return "%02d:%02d:%02d" % (h, mi, s) + (".%03d" % frac if frac else "")
    if date1904:
        base = dt.datetime(1904, 1, 1)
    elif days >= 61:
        base = dt.datetime(1899, 12, 30)       # Excel counts a 29 Feb 1900 that never was
    elif days == 60:
        return None
    else:
        base = dt.datetime(1899, 12, 31)
    if days == 0 and not date1904:
        return None                            # serial 0 shows as 00/01/1900 in Excel
    try:
        stamp = base + dt.timedelta(days=days, milliseconds=ms_of_day)
    except OverflowError:
        return None
    if kind == "date" and ms_of_day == 0:
        return stamp.strftime("%Y-%m-%d")
    text = stamp.strftime("%Y-%m-%d %H:%M:%S")
    if stamp.microsecond:
        text += ".%03d" % (stamp.microsecond // 1000)
    return text


def format_number(raw):
    """Stored number text, tidied: '3.0' -> '3'; anything else is kept as written."""
    v = raw.strip()
    m = re.fullmatch(r"(-?\d+)\.0+", v)
    return m.group(1) if m else v


class Row(list):
    """The cells of one worksheet row; .excel_row is its 1-based row number in the sheet."""
    excel_row = None


class Workbook:
    """An open description of an .xlsx file: its worksheets, shared strings and styles."""

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            magic = fh.read(8)
        if magic == OLE_MAGIC:
            raise XlsxError("password-protected workbook or legacy .xls content (an OLE file, not"
                            " a zip); open it in Excel and save as an unprotected .xlsx")
        try:
            with zipfile.ZipFile(path) as zf:
                self.members = {n.lower(): n for n in zf.namelist()}
                self._read_structure(zf)
        except zipfile.BadZipFile as exc:
            raise XlsxError(f"not a valid .xlsx (zip) file: {exc}") from exc
        except ET.ParseError as exc:
            raise XlsxError(f"malformed workbook XML: {exc}") from exc
        self._shared = None

    # ------------------------------------------------------------------ structure

    def _member(self, name):
        return self.members.get(name.lstrip("/").lower())

    def _parse(self, zf, name):
        real = self._member(name)
        if real is None:
            return None
        with zf.open(real) as fh:
            return ET.parse(fh).getroot()

    @staticmethod
    def _resolve(base_dir, target):
        if target.startswith("/"):
            return target.lstrip("/")
        return posixpath.normpath(posixpath.join(base_dir, target))

    def _rels(self, zf, part):
        """{rId: (type, target path)} for a part such as xl/workbook.xml."""
        folder, name = posixpath.split(part)
        root = self._parse(zf, posixpath.join(folder, "_rels", name + ".rels"))
        out = {}
        if root is None:
            return out
        for rel in root:
            if rel.get("TargetMode", "").lower() == "external":
                continue
            out[rel.get("Id")] = (rel.get("Type", ""), self._resolve(folder, rel.get("Target", "")))
        return out

    def _read_structure(self, zf):
        workbook_part = "xl/workbook.xml"
        for rtype, target in self._rels(zf, "").values():
            if rtype.endswith("/officeDocument"):
                workbook_part = target
        root = self._parse(zf, workbook_part)
        if root is None:
            raise XlsxError("no workbook part (xl/workbook.xml) in the zip; not an Excel workbook")
        rels = self._rels(zf, workbook_part)

        self.date1904 = False
        self.sheets = []           # (name, part, state)
        for elem in root.iter():
            name = _local(elem.tag)
            if name == "workbookPr":
                self.date1904 = elem.get("date1904", "").lower() in ("1", "true")
            elif name == "sheet":
                rtype, target = rels.get(_rel_id(elem), ("", None))
                if target and rtype.endswith("/worksheet") and self._member(target):
                    self.sheets.append((elem.get("name") or target, target, elem.get("state") or "visible"))

        self.shared_part = self.styles_part = None
        for rtype, target in rels.values():
            if rtype.endswith("/sharedStrings"):
                self.shared_part = target
            elif rtype.endswith("/styles"):
                self.styles_part = target
        self.shared_part = self.shared_part or ("xl/sharedStrings.xml" if self._member("xl/sharedStrings.xml") else None)
        self.styles_part = self.styles_part or ("xl/styles.xml" if self._member("xl/styles.xml") else None)
        self.style_kinds = self._read_styles(zf)

    def _read_styles(self, zf):
        """Index of each cellXfs entry -> 'date' / 'datetime' / 'time' / None."""
        root = self._parse(zf, self.styles_part) if self.styles_part else None
        if root is None:
            return []
        custom = {}
        kinds = []
        for elem in root:
            name = _local(elem.tag)
            if name == "numFmts":
                for fmt in elem:
                    try:
                        custom[int(fmt.get("numFmtId"))] = fmt.get("formatCode", "")
                    except (TypeError, ValueError):
                        pass
            elif name == "cellXfs":
                for xf in elem:
                    try:
                        fid = int(xf.get("numFmtId", "0"))
                    except ValueError:
                        fid = 0
                    kinds.append(classify_format(custom[fid]) if fid in custom else classify_builtin(fid))
        return kinds

    def shared_strings(self):
        if self._shared is None:
            self._shared = []
            if self.shared_part:
                with zipfile.ZipFile(self.path) as zf, zf.open(self._member(self.shared_part)) as fh:
                    for _, elem in ET.iterparse(fh, events=("end",)):
                        if _local(elem.tag) == "si":
                            self._shared.append(_text(elem))
                            elem.clear()
        return self._shared

    # ------------------------------------------------------------------ cells

    def cell_value(self, c, shared):
        ctype = c.get("t", "n")
        if ctype == "inlineStr":
            for child in c:
                if _local(child.tag) == "is":
                    return _text(child)
            return ""
        v = None
        for child in c:
            if _local(child.tag) == "v":
                v = child.text or ""
                break
        if v is None:
            return ""
        if ctype == "s":
            try:
                return shared[int(v)]
            except (ValueError, IndexError):
                return ""
        if ctype == "b":
            return "TRUE" if v.strip() in ("1", "true") else "FALSE"
        if ctype == "str":
            return unescape(v)
        if ctype in ("e", "d"):
            return v
        try:
            style = int(c.get("s", "0"))
        except ValueError:
            style = 0
        kind = self.style_kinds[style] if 0 <= style < len(self.style_kinds) else None
        if kind:
            try:
                text = serial_to_text(float(v), kind, self.date1904)
            except ValueError:
                text = None
            if text:
                return text
        return format_number(v)

    def iter_rows(self, part):
        """Row objects (lists of cell text, '' for empty cells) for each <row> in the sheet."""
        shared = self.shared_strings()
        with zipfile.ZipFile(self.path) as zf, zf.open(self._member(part)) as fh:
            parent = None
            next_row = 1
            for event, elem in ET.iterparse(fh, events=("start", "end")):
                name = _local(elem.tag)
                if event == "start":
                    if name == "sheetData":
                        parent = elem
                    continue
                if name != "row":
                    continue
                try:
                    number = int(elem.get("r"))
                except (TypeError, ValueError):
                    number = next_row
                next_row = number + 1
                row = Row()
                row.excel_row = number
                col = 0
                for c in elem:
                    if _local(c.tag) != "c":
                        continue
                    m = CELL_REF_RE.match(c.get("r") or "")
                    if m:
                        col = column_index(m.group(1))
                    value = self.cell_value(c, shared)
                    if value != "":
                        while len(row) < col:
                            row.append("")
                        if len(row) == col:
                            row.append(value)
                        else:
                            row[col] = value
                    col += 1
                elem.clear()
                if parent is not None:
                    parent.clear()      # drop finished rows so memory stays flat
                yield row

#!/usr/bin/env python3
"""Load NirSoft BrowsingHistoryView CSV/TXT/TSV exports into browsinghistory-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-browsinghistory.json (plus the shared component-toolkit-common.json):
the URL is ECS url.original (url.domain / url.scheme derived), the profile owner is user.name, and
every other column is browsinghistory.<snake_case>.

BrowsingHistoryView writes visit times in the regional format and clock of the machine that RAN it,
so --tz is required and day/month order is detected (or forced with --date-order). The converted
UTC time is browsinghistory.visit_time and @timestamp; the text as exported is kept in
browsinghistory.visit_time_local.

Template install, index creation and bulk sending come from sof_elk_template_importer.py.
Full field reference: docs/schemas/browsinghistory.md.
"""
import argparse
import codecs
import csv
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib import error
from urllib.parse import urlsplit

import sof_elk_index_templates as templates
import sof_elk_template_importer as engine
from sof_elk_template_importer import add_client_arguments, apply_client_arguments, resolve_index

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

# BrowsingHistoryView's default column order, used only when the export has no header line
DEFAULT_COLUMNS = [
    "URL", "Title", "Visit Time", "Visit Count", "Visited From", "Visit Type",
    "Visit Duration", "Web Browser", "User Profile", "Browser Profile", "URL Length",
    "Typed Count", "History File", "Record ID",
]
KNOWN_HEADERS = {c.lower() for c in DEFAULT_COLUMNS}

# ISO-style: 2026-10-08 09:12:44(.fff)(Z|+08:00)
ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|[+-]\d{2}:?\d{2})?$")
# Regional: 10/08/2026 9:12:44 AM, 08.10.2026 21:12, 2026/10/08 21:12:44
LOCALE_RE = re.compile(
    r"^(\d{1,4})[/.-](\d{1,2})[/.-](\d{1,4})[ T,]+(\d{1,2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*([AaPp]\.?[Mm]\.?)?$")
TZ_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

ARTIFACT_NAME = "browsinghistory"

# Column (lower-case, spaces removed) -> list of (field, conversion). "visit" is the regional
# visit-time conversion below; the others are sof_elk_template_importer.CONV_TYPE conversions.
COLUMNS = {
    "url": [("url.original", "keyword")],
    "title": [("browsinghistory.title", "keyword")],
    "visittime": [("browsinghistory.visit_time", "visit"), ("browsinghistory.visit_time_local", "keyword")],
    "visitcount": [("browsinghistory.visit_count", "long")],
    "visitedfrom": [("browsinghistory.visited_from", "keyword")],
    "visittype": [("browsinghistory.visit_type", "keyword")],
    "visitduration": [("browsinghistory.visit_duration", "keyword")],
    "webbrowser": [("browsinghistory.web_browser", "keyword")],
    "userprofile": [("browsinghistory.user_profile", "keyword")],
    "browserprofile": [("browsinghistory.browser_profile", "keyword")],
    "urllength": [("browsinghistory.url_length", "long")],
    "typedcount": [("browsinghistory.typed_count", "long")],
    "historyfile": [("browsinghistory.history_file", "keyword")],
    "recordid": [("browsinghistory.record_id", "long")],
}
CONV_TYPE = {**engine.CONV_TYPE, "visit": "date"}
TIME_FIELD, TIME_COLUMN = "browsinghistory.visit_time", "visittime"


def col_key(name):
    return re.sub(r"[\s_]+", "", name.strip().lower())


# --------------------------------------------------------------------------- reading

def detect_encoding(path):
    with open(path, "rb") as fh:
        head = fh.read(4)
        if head.startswith((b"\xff\xfe", b"\xfe\xff")):
            return "utf-16"
        if head.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
        fh.seek(0)
        dec = codecs.getincrementaldecoder("utf-8")()
        try:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                dec.decode(chunk)
            dec.decode(b"", final=True)
            return "utf-8"
        except UnicodeDecodeError:
            return "cp1252"  # NirSoft's ANSI export on Western Windows


class Table:
    """A NirSoft export: encoding, delimiter and header (or lack of one) worked out once."""

    def __init__(self, path):
        self.path = path
        self.encoding = detect_encoding(path)
        with open(path, encoding=self.encoding, errors="replace", newline="") as fh:
            first = fh.readline()
        counts = {d: first.count(d) for d in (",", "\t", ";")}
        self.delimiter = max(counts, key=counts.get)
        first_row = next(csv.reader([first], delimiter=self.delimiter), [])
        names = {c.strip().lower() for c in first_row}
        self.has_header = bool(names & KNOWN_HEADERS) or not re.match(r"^[a-z][a-z0-9+.-]*:", first_row[0].strip().lower() if first_row else "")
        if self.has_header:
            self.raw_header = first_row
            self.note = None
        else:
            n = len(first_row)
            if n == len(DEFAULT_COLUMNS):
                self.raw_header = list(DEFAULT_COLUMNS)
                self.note = "no header line - assumed BrowsingHistoryView's default column order"
            else:
                self.raw_header = [f"col_{i + 1}" for i in range(n)]
                self.note = (f"no header line and {n} columns (default layout has"
                             f" {len(DEFAULT_COLUMNS)}) - columns named col_1..col_{n}")

    def rows(self):
        with open(self.path, encoding=self.encoding, errors="replace", newline="") as fh:
            reader = csv.reader(fh, delimiter=self.delimiter)
            if self.has_header:
                next(reader, None)
            for row in reader:
                if any(c.strip() for c in row):
                    yield row


# --------------------------------------------------------------------------- dates

def resolve_order(ev):
    """Day/month order from evidence. Returns 'ymd'|'dmy'|'mdy'|'conflict'|None (ambiguous)."""
    if ev["ymd"] and not (ev["day_first"] or ev["month_first"] or ev["other"]):
        return "ymd"
    if ev["day_first"] and ev["month_first"]:
        return "conflict"
    if ev["day_first"]:
        return "dmy"
    if ev["month_first"]:
        return "mdy"
    return None


def to_utc(y, mo, d, h, mi, ss, frac, offset):
    """Local wall-clock parts + offset ('Z' or +HH:MM) -> '2026-09-13T14:05:10.000Z', or None."""
    try:
        if offset == "Z":
            tzinfo = dt.timezone.utc
        else:
            sign = 1 if offset[0] == "+" else -1
            tzinfo = dt.timezone(sign * dt.timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6])))
        local = dt.datetime(int(y), int(mo), int(d), h, int(mi), int(ss or 0),
                            int(frac) * 1000, tzinfo=tzinfo)
    except ValueError:
        return None
    u = local.astimezone(dt.timezone.utc)
    return u.strftime("%Y-%m-%dT%H:%M:%S.") + f"{u.microsecond // 1000:03d}Z"


def parse_datetime(value, order, tz):
    """Any supported date string -> ISO 8601 in UTC ('...Z'), or None."""
    v = value.strip()
    m = ISO_RE.match(v)
    if m:
        y, mo, d, hh, mi, ss, frac, z = m.groups()
        h = int(hh)
        offset = tz if not z else ("Z" if z == "Z" else (z if ":" in z else z[:3] + ":" + z[3:]))
    else:
        m = LOCALE_RE.match(v)
        if not m or not order:
            return None
        a, b, c, hh, mi, ss, frac, ampm = m.groups()
        if order == "ymd" or len(a) == 4:
            y, mo, d = a, b, c
        elif order == "dmy":
            d, mo, y = a, b, c
        else:
            mo, d, y = a, b, c
        if len(y) == 2:
            y = "20" + y
        h = int(hh)
        if ampm:
            pm = ampm[0].lower() == "p"
            if h == 12:
                h = 0
            if pm:
                h += 12
        offset = tz
    frac = (frac or "")[:3].ljust(3, "0")
    return to_utc(y, mo, d, h, mi, ss, frac, offset)



# --------------------------------------------------------------------------- visit-time order

def new_stat():
    return {"filled": 0, "iso": 0, "ymd": 0, "day_first": 0, "month_first": 0, "other": 0,
            "bad": 0, "bad_example": None}


def scan(table, stat):
    """Count rows and gather day/month evidence from the Visit Time column."""
    keys = [col_key(c) for c in table.raw_header]
    i = keys.index(TIME_COLUMN) if TIME_COLUMN in keys else None
    count = 0
    for row in table.rows():
        count += 1
        v = row[i].strip() if i is not None and i < len(row) else ""
        if not v:
            continue
        stat["filled"] += 1
        if ISO_RE.match(v):
            stat["iso"] += 1
            continue
        m = LOCALE_RE.match(v)
        if not m:
            stat["bad"] += 1
            stat["bad_example"] = stat["bad_example"] or v[:60]
            continue
        a, b = m.group(1), m.group(2)
        if len(a) == 4:
            stat["ymd"] += 1
        elif int(a) > 12:
            stat["day_first"] += 1
        elif int(b) > 12:
            stat["month_first"] += 1
        else:
            stat["other"] += 1
    return count


def decide_order(stat, forced):
    if stat["filled"] and stat["iso"] == stat["filled"] - stat["bad"]:
        return "iso"
    return forced or resolve_order(stat)


def timestamp_check(tables, stat, order, tz, rows_total, forced):
    """Print the timestamp report. Returns True if it's safe to load."""
    print("\nTimestamp check")
    for t in tables:
        enc = {"utf-16": "UTF-16", "utf-8-sig": "UTF-8 (BOM)", "utf-8": "UTF-8", "cp1252": "ANSI"}[t.encoding]
        delim = {",": "comma", "\t": "tab", ";": "semicolon"}[t.delimiter]
        print(f"  file: {t.path.name}  [{enc}, {delim}-delimited]")
        if t.note:
            print(f"    WARN {t.note}")
    if not stat["filled"]:
        print("  WARN no Visit Time values -> every row uses ingest time")
        return True
    ok = True
    if order == "iso":
        desc = "ISO format"
    elif order in ("dmy", "mdy", "ymd"):
        if forced:
            how = "from --date-order"
            against = {"dmy": stat["month_first"], "mdy": stat["day_first"], "ymd": 0}[order]
            if against:
                how += f"; WARNING {against} value(s) are impossible that way and go to browsinghistory.malformed"
        else:
            how = (f"detected: {stat['day_first'] or stat['month_first'] or stat['ymd']} value(s)"
                   f" only make sense that way")
        desc = {"dmy": "day/month/year", "mdy": "month/day/year", "ymd": "year/month/day"}[order] + f" ({how})"
    elif order == "conflict":
        desc, ok = "MIXED day-first and month-first values", False
    else:
        desc, ok = "AMBIGUOUS: every date has day and month <= 12", False
    print(f"  {'OK  ' if ok else 'STOP'} Visit Time: {desc}, times read as {tz}  <- @timestamp")
    if order is None:
        print("       Can't tell 08/10 = 8 Oct from 10 Aug. Re-run with --date-order dmy (e.g. SG/UK"
              " regional settings) or --date-order mdy (US) to match the machine that ran"
              " BrowsingHistoryView.")
    elif order == "conflict":
        print("       Some values only work day-first and others only month-first: the file mixes"
              " formats. Check the export; use --date-order to force one reading.")
    if stat["filled"] < rows_total:
        print(f"    - {rows_total - stat['filled']} row(s) have no Visit Time -> those use ingest time")
    if stat["bad"]:
        print(f"    - {stat['bad']} value(s) are not dates (e.g. \"{stat['bad_example']}\")"
              f" -> kept in browsinghistory.malformed")
    if tz == "Z":
        print("  note: --tz UTC assumes BrowsingHistoryView's GMT/UTC time option was ON")
    else:
        print(f"  note: --tz {tz} must be the clock of the machine that RAN BrowsingHistoryView"
              f" (not necessarily the suspect host)")
    return ok


# --------------------------------------------------------------------------- documents

def column_plan(header):
    """[(column, [(field, conv), ...])] for one file, plus columns not in the schema."""
    plan, unknown, used = [], [], set()
    for col in header:
        targets = COLUMNS.get(col_key(col))
        if targets is None:
            name = engine.snake(col)
            base, i = name, 2
            while name in used:
                name, i = f"{base}_{i}", i + 1
            used.add(name)
            targets = [(f"{ARTIFACT_NAME}.unmapped.{name}", "keyword")]
            unknown.append(col.strip())
        plan.append((col.strip(), targets))
    return plan, unknown


def user_from_profile(value):
    v = value.strip().rstrip("\\/")
    if not v:
        return None
    return re.split(r"[\\/]", v)[-1].lower() or None


def build_doc(row, plan, order, tz, meta, ingest_time, issues):
    doc, malformed = {}, []
    for i, (col, targets) in enumerate(plan):
        v = row[i].strip() if i < len(row) else ""
        if not v:
            continue
        for field, conv in targets:
            if conv == "visit":
                val = parse_datetime(v, None if order == "iso" else order, tz)
            else:
                val = engine.convert(v, conv)
            if val is None:
                malformed.append(f"{col}={v}")
                issues[(col, field)] = issues.get((col, field), 0) + 1
                continue
            if engine.get_field(doc, field) is None:
                engine.set_field(doc, field, val)
    if malformed:
        engine.set_field(doc, f"{ARTIFACT_NAME}.malformed", malformed)

    ts = engine.get_field(doc, TIME_FIELD)
    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": meta["host"]}
    doc["event"] = {"dataset": ARTIFACT_NAME}
    profile = engine.get_field(doc, "browsinghistory.user_profile")
    if profile and user_from_profile(profile):
        doc["user"] = {"name": user_from_profile(profile)}
    original = engine.get_field(doc, "url.original")
    if original:
        try:
            u = urlsplit(original)
            if u.scheme:
                doc["url"]["scheme"] = u.scheme.lower()
            if u.hostname:
                doc["url"]["domain"] = u.hostname.lower()
        except ValueError:
            pass
    doc["kape"] = {
        "source_file": meta["source_file"],
        "timestamp_source": "Visit Time" if ts else "ingest_time",
        "timestamp_meaning": ("Page visit time, converted from the exporting machine's clock (--tz)"
                              if ts else "No usable time in this row - time the row was loaded"),
    }
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc


def check_against_template(types):
    problems = []
    for col, targets in COLUMNS.items():
        for field, conv in targets:
            if types.get(field) != CONV_TYPE[conv]:
                problems.append(f"{col} -> {field}: template has {types.get(field) or 'nothing'},"
                                f" needs {CONV_TYPE[conv]}")
    for field in ("url.domain", "url.scheme", "user.name", "event.dataset", "kape.timestamp_meaning",
                  f"{ARTIFACT_NAME}.malformed"):
        if field not in types:
            problems.append(f"{field}: missing from template")
    return problems


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Load NirSoft BrowsingHistoryView CSVs into SOF-ELK with a fixed schema.")
    ap.add_argument("paths", nargs="+", help="BrowsingHistory CSV file(s) or folders")
    ap.add_argument("--hostname", required=True, help="Host the browser history came from")
    ap.add_argument("--tz", required=True, metavar="+HH:MM|UTC",
                    help="UTC offset of the machine that RAN BrowsingHistoryView (e.g. +08:00),"
                         " or UTC if its GMT time option was on")
    ap.add_argument("--date-order", choices=["dmy", "mdy", "ymd"],
                    help="Force day/month order when it can't be detected")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None, help="Override target index; must still end in -<hostname> (default: browsinghistory-<hostname>)")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true", help="Check and show samples; send nothing")
    add_client_arguments(ap)
    # "--tz -05:00" would otherwise be read as an unknown option because of the leading minus
    argv = sys.argv[1:]
    for i, a in enumerate(argv[:-1]):
        if a == "--tz" and argv[i + 1].startswith("-"):
            argv[i:i + 2] = [f"--tz={argv[i + 1]}"]
            break
    args = ap.parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")

    if args.tz.strip().upper() in ("UTC", "GMT", "Z", "+00:00", "0"):
        tz = "Z"
    else:
        m = TZ_RE.match(args.tz.strip())
        if not m or int(m.group(2)) > 14:
            sys.exit(f"--tz must look like +08:00, -0500 or UTC, got '{args.tz}'")
        tz = f"{m.group(1)}{int(m.group(2)):02d}:{m.group(3) or '00'}"

    try:
        host = engine.sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = resolve_index(ARTIFACT_NAME, host, args.index)

    component, index_tpl, body = templates.load(ARTIFACT_NAME)
    types = templates.field_types(body["mappings"])
    problems = check_against_template(types)
    if problems:
        sys.exit(f"Column map and index-{ARTIFACT_NAME}.json disagree:\n  " + "\n  ".join(problems))

    files = []
    for p in map(Path, args.paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() in (".csv", ".txt", ".tsv"))
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    tables = []
    for f in files:
        if f.stat().st_size == 0:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        tables.append(Table(f))
    if not tables:
        sys.exit("No CSV files found.")

    stat, rows_total = new_stat(), 0
    for t in tables:
        rows_total += scan(t, stat)
    order = decide_order(stat, args.date_order)
    plans = {t.path: column_plan(t.raw_header) for t in tables}
    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    print(f"{len(tables)} file(s), {rows_total} rows -> index '{index}', host={host}")
    unknown = sorted({c for _, u in plans.values() for c in u})
    if unknown:
        print(f"Columns not in the {ARTIFACT_NAME} schema (kept as keywords under"
              f" {ARTIFACT_NAME}.unmapped.*): {', '.join(unknown)}")
    safe = timestamp_check(tables, stat, order, tz, rows_total, args.date_order)

    def meta_for(t):
        return {"host": host, "case": args.case, "source_file": t.path.name}

    if args.dry_run:
        print("\nSample documents:")
        shown, issues = 0, {}
        for t in tables:
            for row in t.rows():
                doc = build_doc(row, plans[t.path][0], order, tz, meta_for(t), ingest_time, issues)
                print("  " + json.dumps(doc, ensure_ascii=False)[:700])
                shown += 1
                if shown == 2:
                    break
            if shown == 2:
                break
        print("\nDry run only - nothing sent." + ("" if safe else
              "  Fix the STOP item(s) above before loading."))
        return

    if not safe:
        sys.exit("\nNot loading: fix the STOP item(s) in the timestamp check first"
                 " (usually by adding --date-order).")

    es = engine.ES(args.es, args.user, args.password, args.insecure)
    try:
        status, info = es.call("GET", "/")
    except error.URLError as e:
        sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {e.reason}")
    if status >= 300:
        sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
    print(f"\nConnected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    templates.install(es.call, ARTIFACT_NAME, component, index_tpl)
    print(f"Installed index template 'sofelk-toolkit-{ARTIFACT_NAME}' ({ARTIFACT_NAME}-*)")
    art = engine.Artifact(name=ARTIFACT_NAME, tool="BrowsingHistoryView", columns={},
                          detect_section=lambda p, h: None, dataset_for=lambda s: ARTIFACT_NAME,
                          time_default=[])
    print(f"Index '{index}': {es.prepare_index(art, index, body)}")

    stats_b = {"ok": 0, "errors": 0, "updated": 0}
    lines, seen, issues = [], {}, {}
    for t in tables:
        meta, plan = meta_for(t), plans[t.path][0]
        for row in t.rows():
            # ID = host + row content (+ a counter so identical rows stay separate documents)
            content = dict(sorted(zip(t.raw_header, (c.strip() for c in row))))
            key = json.dumps([host, "BrowsingHistory", content], ensure_ascii=False)
            n = seen.get(key, 0)
            seen[key] = n + 1
            doc_id = hashlib.sha1(f"{key}|{n}".encode()).hexdigest()
            doc = build_doc(row, plan, order, tz, meta, ingest_time, issues)
            lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
            lines.append(json.dumps(doc, ensure_ascii=False))
            if len(lines) >= args.batch_size * 2:
                es.send(lines, stats_b)
    es.send(lines, stats_b)

    if issues:
        print(f"\nValues that did not fit their field type (kept as text in {ARTIFACT_NAME}.malformed):")
        for (col, field), n in sorted(issues.items()):
            print(f"  {col} -> {field}: {n} value(s)")
    new = stats_b["ok"] - stats_b["updated"]
    print(f"\nDone: {rows_total} rows read -> {new} new documents, {stats_b['updated']} already in"
          f" index (re-run), {stats_b['errors']} errors.")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == rows_total else "DOES NOT MATCH"
        print(f"Index check: '{index}' holds {in_index} browsing history documents for host"
              f" '{host}' ({verdict} the {rows_total} rows read).")
    print(f"In Kibana, use the '{ARTIFACT_NAME}-*' data view (time field @timestamp); useful fields:"
          f" user.name, url.domain, url.original, browsinghistory.title, browsinghistory.web_browser.")


if __name__ == "__main__":
    main()

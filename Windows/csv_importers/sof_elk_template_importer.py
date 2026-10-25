"""Shared engine for CSV importers with a fixed, template-defined schema.

An importer describes its artifact with an Artifact object: which CSVs are its own, how each
column maps to a field and conversion, and which fields feed @timestamp. The field types live in
Windows/index_templates/index-<artifact>.json; the engine checks the column map against that
template at startup, installs the templates, creates the index from them and bulk-loads.

Columns the importer does not know go to <artifact>.unmapped.<snake_case> as keyword. Values that
do not fit their field's type are kept as "Column=value" strings in <artifact>.malformed.
"""
import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import re
import ssl
import sys
from pathlib import Path
from urllib import error, request

import sof_elk_index_templates as templates

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:  # Windows: C long is 32-bit
    csv.field_size_limit(2**31 - 1)

# EZ Tools write UTC timestamps like "2026-10-08 09:12:44.1234567" (7 fractional digits)
ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
# Month-day-year dates, e.g. 06-21-2006 (Amcache DevicePnps DriverVerDate)
MDY_RE = re.compile(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$")
INT_RE = re.compile(r"^-?\d{1,19}$")
BOOLS = {"true": True, "false": False}
INT64_MAX = 2**63 - 1
TZ_ARG_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

# Conversions a column map can use, and the template type each must land in:
#   keyword  value as-is (trimmed)
#   date     EZ Tools UTC timestamp -> ISO 8601 (ms)
#   mdy      MM-DD-YYYY date -> ISO 8601 midnight UTC
#   long     integer
#   boolean  True / False
#   path     lower-case, "/" -> "\"
#   name     lower-case
#   ext      lower-case, no leading dot
#   sha1     lower-case, legacy "0000" prefix removed
CONV_TYPE = {"keyword": "keyword", "path": "keyword", "name": "keyword", "ext": "keyword",
             "sha1": "keyword", "date": "date", "mdy": "date", "long": "long", "boolean": "boolean"}


class Artifact:
    """What one importer needs to tell the engine. See amcache2sofelk.py for a full example.

    name             index prefix and field namespace, e.g. "amcache"
    tool             parser name for messages, e.g. "AmcacheParser"
    columns          lower-case column -> [(field, conversion), ...]
    section_columns  section kind -> overrides of `columns` for that kind
    detect_section   (path, header) -> section name, or None if the CSV is not this artifact's
    section_kind     section -> key into section_columns / time_prefs (default: lower-case name)
    dataset_for      section -> event.dataset value
    time_prefs       section kind -> ordered @timestamp candidate fields
    time_default     candidates for kinds not in time_prefs
    time_meaning     lower-case source column -> what it means (kape.timestamp_meaning)
    """

    def __init__(self, name, tool, columns, detect_section, dataset_for, time_default,
                 section_columns=None, section_kind=None, time_prefs=None, time_meaning=None):
        self.name = name
        self.tool = tool
        self.columns = columns
        self.section_columns = section_columns or {}
        self.detect_section = detect_section
        self.section_kind = section_kind or (lambda s: s.lower())
        self.dataset_for = dataset_for
        self.time_prefs = time_prefs or {}
        self.time_default = time_default
        self.time_meaning = {"ingest_time": "No usable time in this row - time the row was loaded",
                             **(time_meaning or {})}


# --------------------------------------------------------------------------- helpers

def parse_ts(value):
    """EZ Tools UTC timestamp -> ISO 8601 with millisecond precision, or None."""
    m = ISO_RE.match(value.strip())
    if not m:
        return None
    date, time, frac, tz = m.groups()
    frac = (frac or "")[:3].ljust(3, "0")
    if not tz:
        tz = "Z"  # EZ Tools output is UTC unless the column says LOCAL
    elif tz != "Z" and ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return f"{date}T{time}.{frac}{tz}"


def parse_mdy(value):
    m = MDY_RE.match(value)
    if not m:
        return parse_ts(value)
    month, day, year = (int(x) for x in m.groups())
    try:
        return dt.date(year, month, day).isoformat() + "T00:00:00.000Z"
    except ValueError:
        return None


def convert(value, conv):
    """Converted value, or None if it does not fit the conversion's type."""
    if conv == "keyword":
        return value
    if conv == "date":
        return parse_ts(value)
    if conv == "mdy":
        return parse_mdy(value)
    if conv == "long":
        return int(value) if INT_RE.match(value) and abs(int(value)) <= INT64_MAX else None
    if conv == "boolean":
        return BOOLS.get(value.lower())
    if conv == "path":
        return value.lower().replace("/", "\\")
    if conv == "name":
        return value.lower()
    if conv == "ext":
        return value.lower().lstrip(".") or None
    if conv == "sha1":
        sha1 = value.lower()
        if len(sha1) == 44 and sha1.startswith("0000"):
            sha1 = sha1[4:]  # older Amcache stores SHA1 with a 0000 prefix
        return sha1
    raise ValueError(conv)


def snake(name):
    """CamelCase / free-form column name -> snake_case field name."""
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", name.strip())
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_") or "field"


def set_field(doc, dotted, value):
    parts = dotted.split(".")
    for p in parts[:-1]:
        doc = doc.setdefault(p, {})
    doc[parts[-1]] = value


def get_field(doc, dotted):
    for p in dotted.split("."):
        if not isinstance(doc, dict) or p not in doc:
            return None
        doc = doc[p]
    return doc


def sanitize_hostname(hostname):
    """Lower-case host name safe for an Elasticsearch index name."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def column_plan(art, section, header):
    """Per-column targets for one file: list of (column, [(field, conv), ...]) in header order,
    plus the columns that are not in the artifact's map."""
    overrides = art.section_columns.get(art.section_kind(section), {})
    plan, unknown, used = [], [], set()
    for col in header:
        key = col.strip().lower()
        targets = overrides.get(key) or art.columns.get(key)
        if targets is None:
            name = snake(col)
            base, i = name, 2
            while name in used:
                name, i = f"{base}_{i}", i + 1
            used.add(name)
            targets = [(f"{art.name}.unmapped.{name}", "keyword")]
            unknown.append(col.strip())
        plan.append((col.strip(), targets))
    return plan, unknown


def check_against_template(art, types):
    """Every field the column map writes must exist in the template with the same type."""
    problems = []
    for table in [art.columns] + list(art.section_columns.values()):
        for col, targets in table.items():
            for field, conv in targets:
                want, have = CONV_TYPE[conv], types.get(field)
                if have != want:
                    problems.append(f"{col} -> {field}: template has {have or 'nothing'}, needs {want}")
    for field in ("@timestamp", "host.name", "case", "event.dataset", "kape.source_file",
                  "kape.timestamp_source", "kape.timestamp_meaning", "file.name",
                  "file.extension", f"{art.name}.malformed"):
        if field not in types:
            problems.append(f"{field}: missing from template")
    return problems


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        yield header
        for row in reader:
            if any(cell.strip() for cell in row):
                yield row


def build_doc(art, row, plan, kind, meta, ingest_time, issues):
    """One CSV row -> document. issues[(column, field)] counts values that did not convert."""
    doc, ts_columns, malformed = {}, {}, []
    for i, (col, targets) in enumerate(plan):
        v = row[i].strip() if i < len(row) else ""
        if not v:
            continue
        for field, conv in targets:
            val = convert(v, conv)
            if val is None:
                malformed.append(f"{col}={v}")
                issues[(col, field)] = issues.get((col, field), 0) + 1
                continue
            if get_field(doc, field) is None:  # first column that fills a field wins
                set_field(doc, field, val)
                if CONV_TYPE[conv] == "date":
                    ts_columns[field] = col

    # ECS file.name / file.extension from the path when the CSV has no name column
    path = get_field(doc, "file.path")
    if path and not get_field(doc, "file.name"):
        set_field(doc, "file.name", re.split(r"[\\/]", path)[-1])
    name = get_field(doc, "file.name")
    if name and "." in name and not get_field(doc, "file.extension"):
        set_field(doc, "file.extension", name.rsplit(".", 1)[1])
    if malformed:
        set_field(doc, f"{art.name}.malformed", malformed)

    ts, src = None, None
    for field in art.time_prefs.get(kind, art.time_default):
        ts = get_field(doc, field)
        if ts:
            src = ts_columns[field]
            break
    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": meta["host"]}
    doc["event"] = {"dataset": meta["dataset"]}
    src = src or "ingest_time"
    doc["kape"] = {
        "source_file": meta["source_file"],
        "timestamp_source": src,
        "timestamp_meaning": art.time_meaning.get(src.lower(), "Timestamp column: " + src),
    }
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc


# --------------------------------------------------------------------------- Elasticsearch

class ES:
    def __init__(self, url, user=None, password=None, insecure=False):
        self.url = url.rstrip("/")
        self.headers = {}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, method, path, body=None, ctype="application/json"):
        data = body.encode("utf-8") if body is not None else None
        req = request.Request(self.url + path, data=data, method=method,
                              headers={**self.headers, "Content-Type": ctype})
        try:
            with request.urlopen(req, timeout=300, context=self.ctx) as r:
                status, raw = r.status, r.read()
        except error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, (json.loads(raw) if raw else {})
        except ValueError:
            return status, {"raw": raw.decode("utf-8", "replace")}

    def index_mapping(self, index):
        """The index's mappings, or None if it doesn't exist."""
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            return None
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        return next(iter(resp.values()), {}).get("mappings", {})

    def prepare_index(self, art, index, body):
        """Create the index with the template body, or bring an existing toolkit index up to date."""
        mapping = self.index_mapping(index)
        if mapping is None:
            status, resp = self.call("PUT", f"/{index}", json.dumps(body))
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
            return "created"
        if mapping.get("_meta", {}).get("toolkit_schema") != art.name:
            sys.exit(
                f"Index '{index}' exists but was created by an older version of this importer"
                f" (raw {art.tool} column names, types inferred per run). Mixing the two"
                f" schemas in one index breaks queries.\n"
                f"Delete it and reload this host:  curl -X DELETE '{self.url}/{index}'\n"
                f"or load into a new index with --index.")
        # Same schema family: add any fields a newer template defines (existing fields unchanged)
        new = {"_meta": body["mappings"]["_meta"],
               "dynamic_templates": body["mappings"].get("dynamic_templates", []),
               "properties": body["mappings"]["properties"]}
        status, resp = self.call("PUT", f"/{index}/_mapping", json.dumps(new))
        if status >= 300:
            sys.exit(f"Index '{index}' mapping does not match the current template ({status}):"
                     f" {json.dumps(resp)[:500]}\nDelete the index and reload this host.")
        return "appending"

    def bulk(self, lines, stats):
        if not lines:
            return
        status, resp = self.call("POST", "/_bulk", "\n".join(lines) + "\n", "application/x-ndjson")
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    reason = res["error"].get("reason", res["error"])
                    print(f"    ! {reason}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def host_count(self, index, host):
        """Refresh, then count the documents this host has in the index."""
        self.call("POST", f"/{index}/_refresh")
        q = {"query": {"term": {"host.name": host}}}
        status, resp = self.call("POST", f"/{index}/_count", json.dumps(q))
        return resp.get("count") if status < 300 else None


# --------------------------------------------------------------------------- main

def run(art, description):
    ap = argparse.ArgumentParser(description=description)
    ap.add_argument("paths", nargs="+", help="CSV files or folders (searched recursively)")
    ap.add_argument("--hostname", required=True, help="Host the KAPE collection came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None,
                    help=f"Override target index (default: {art.name}-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help=f"Accepted for wrapper compatibility; {art.tool} output is UTC, so it is"
                         " not used")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show sections, column -> field mapping and sample docs; send nothing")
    args = ap.parse_args()

    if args.local_tz and not TZ_ARG_RE.match(args.local_tz.strip()):
        sys.exit(f"--local-tz must look like +08:00 or -0500, got '{args.local_tz}'")

    try:
        host = sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = (args.index or f"{art.name}-{host}").lower()
    if args.index and index != args.index:
        print(f"note: Elasticsearch index names must be lower-case, using '{index}'\n")

    component, index_tpl, body = templates.load(art.name)
    problems = check_against_template(art, templates.field_types(body["mappings"]))
    if problems:
        sys.exit(f"Column map and index-{art.name}.json disagree:\n  " + "\n  ".join(problems))

    files = []
    for p in map(Path, args.paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() == ".csv")
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    if not files:
        sys.exit("No CSV files found.")

    # Group files by section; count rows
    sections, skipped = {}, []
    for f in files:
        rows = read_rows(f)
        header = next(rows, None)
        if not header:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        section = art.detect_section(f, header)
        if not section:
            skipped.append(f.name)
            continue
        plan, unknown = column_plan(art, section, header)
        s = sections.setdefault(section.lower(), {"section": section, "files": [], "rows": 0,
                                                  "unknown": set()})
        s["files"].append((f, plan))
        s["unknown"].update(unknown)
        s["rows"] += sum(1 for _ in rows)

    if skipped:
        print(f"Skipped {len(skipped)} CSV(s) outside this importer's supported source type:")
        for n in skipped:
            print(f"  - {n}")
        print()
    if not sections:
        sys.exit("No matching CSV files found for this importer.")

    ordered = sorted(sections.values(), key=lambda x: x["section"].lower())
    loaded = sum(len(s["files"]) for s in ordered)
    total_rows = sum(s["rows"] for s in ordered)
    print(f"{loaded} CSV files, {total_rows} rows -> index '{index}', {len(ordered)} sections\n")
    for s in ordered:
        print(f"  {art.dataset_for(s['section']):<36} {len(s['files']):>3} file(s) {s['rows']:>8} rows")
    unknown_any = [(s["section"], sorted(s["unknown"])) for s in ordered if s["unknown"]]
    if unknown_any:
        print(f"\nColumns not in the {art.name} schema (kept as keywords under"
              f" {art.name}.unmapped.*):")
        for section, cols in unknown_any:
            print(f"  {section}: {', '.join(cols)}")
    if args.local_tz:
        print(f"\nnote: --local-tz ignored; {art.tool} timestamps are UTC.")

    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def file_meta(f, s):
        return {"host": host, "dataset": art.dataset_for(s["section"]), "source_file": f.name,
                "case": args.case}

    if args.dry_run:
        print("\nColumn -> field per section:")
        for s in ordered:
            f, plan = s["files"][0]
            print(f"  {s['section']}:")
            for col, targets in plan:
                dests = ", ".join(f"{fld} ({CONV_TYPE[c]})" for fld, c in targets)
                print(f"    {col:<30} -> {dests}")
        print("\nSample document per section:")
        issues = {}
        for s in ordered:
            f, plan = s["files"][0]
            rows = read_rows(f)
            next(rows)
            sample = next(rows, None)
            if sample:
                doc = build_doc(art, sample, plan, art.section_kind(s["section"]),
                                file_meta(f, s), ingest_time, issues)
                print(f"  {s['section']}: " + json.dumps(doc, ensure_ascii=False)[:900])
        print("\nDry run only - nothing sent.")
        return

    es = ES(args.es, args.user, args.password, args.insecure)
    try:
        status, info = es.call("GET", "/")
    except error.URLError as e:
        sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {e.reason}")
    if status >= 300:
        sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
    print(f"\nConnected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    templates.install(es.call, art.name, component, index_tpl)
    print(f"Installed index template 'sofelk-toolkit-{art.name}' ({art.name}-*)")
    state = es.prepare_index(art, index, body)
    print(f"Index '{index}': {state}")

    total = {"ok": 0, "errors": 0, "updated": 0}
    issues = {}
    for s in ordered:
        stats, lines = {"ok": 0, "errors": 0, "updated": 0}, []
        kind = art.section_kind(s["section"])
        tag = f"{art.name}:{s['section']}"
        for f, plan in s["files"]:
            meta = file_meta(f, s)
            # ID = host + section + file name (minus KAPE's run timestamp) + row position + row.
            # Re-runs overwrite instead of duplicating; identical rows in a file stay separate.
            stable_name = re.sub(r"^\d{8,}_", "", f.name)
            rows = read_rows(f)
            next(rows)
            for n, row in enumerate(rows):
                doc = build_doc(art, row, plan, kind, meta, ingest_time, issues)
                doc_id = hashlib.sha1(json.dumps(
                    [host, tag, stable_name, n, row], ensure_ascii=False).encode()).hexdigest()
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.bulk(lines, stats)
            es.bulk(lines, stats)
        new = stats["ok"] - stats["updated"]
        print(f"  {art.dataset_for(s['section']):<36} {s['rows']:>8} rows: {new} new,"
              f" {stats['updated']} already in index, {stats['errors']} errors")
        for k in total:
            total[k] += stats[k]

    if issues:
        print(f"\nValues that did not fit their field type (kept as text in {art.name}.malformed):")
        for (col, field), n in sorted(issues.items()):
            print(f"  {col} -> {field}: {n} value(s)")

    new = total["ok"] - total["updated"]
    print(f"\nDone: {total_rows} rows read -> {new} new documents, {total['updated']} already in"
          f" index (re-run), {total['errors']} errors.")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == total_rows else "DOES NOT MATCH"
        print(f"Index check: '{index}' now holds {in_index} documents for host '{host}'"
              f" ({verdict} the {total_rows} rows read).")
        if in_index > total_rows:
            print("  More documents than rows: this host was probably loaded earlier with different"
                  " files. Delete its documents and reload to get a clean count.")
    print(f"In Kibana, use the '{art.name}-*' data view (time field @timestamp) and filter on"
          f" event.dataset, file.path.")

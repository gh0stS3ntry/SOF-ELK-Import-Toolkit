#!/usr/bin/env python3
"""Load RECmd batch and plugin-detail CSVs into registry-<hostname>.

The schema is fixed by the explicit index template in Windows/index_templates/index-registry.json
(plus the shared component-toolkit-common.json):

  * The batch CSV (*_RECmd_Batch_*_Output.csv) has a fixed column set, mapped to ECS registry.*
    (registry.key, registry.value, registry.data.type, registry.data.strings) and registry.<snake>.
  * Plugin-detail CSVs (UserAssist, BamDam, Services, ... one schema per plugin) share
    registry.key (from BatchKeyPath) and registry.batch_value_name. Their other columns go to
    registry.plugin.<snake_case> as keyword, except known timestamp columns, which are dates.
    event.dataset names the plugin, e.g. registry.userassist.

The hive owner is added as user.name when the hive is a user's NTUSER.DAT / UsrClass.dat.
The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/registry.md.
"""
import argparse
import csv
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib import error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, log, resolve_index  # noqa: E402

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). Conversions are listed in
# sof_elk_template_importer.CONV_TYPE. Used for the batch CSV.
COLUMNS = {
    "hivepath": [("registry.hive_path", "keyword")],
    "hivetype": [("registry.hive_type", "keyword")],
    "description": [("registry.description", "keyword")],
    "category": [("registry.category", "keyword")],
    "keypath": [("registry.key", "keyword")],
    "valuename": [("registry.value", "keyword")],
    "valuetype": [("registry.data.type", "keyword")],
    "valuedata": [("registry.data.strings", "keyword")],
    "valuedata2": [("registry.value_data2", "keyword")],
    "valuedata3": [("registry.value_data3", "keyword")],
    "comment": [("registry.comment", "keyword")],
    "recursive": [("registry.recursive", "boolean")],
    "deleted": [("registry.deleted", "boolean")],
    "lastwritetimestamp": [("registry.last_write", "date")],
    "plugindetailfile": [("registry.plugin_detail_file", "keyword")],
}

# Plugin timestamp columns (UTC) that are typed as dates; all other plugin columns are keywords.
# Columns ending in LOCAL (KnownNetworks) are host local time and stay keywords.
PLUGIN_DATE_COLUMNS = [
    "Timestamp", "ExecutionTime", "LastExecuted", "ExecutedOn", "OpenedOn", "LastOpened",
    "ModifiedTime", "LastDetectionTime", "LastStart", "CreatedOn", "LastLoginTime",
    "LastLogonTime", "LastConnected", "LastModified", "ParametersKeyLastWrite",
    "NameKeyLastWrite", "ExtensionLastOpened", "LastClosed", "FirstInstalled", "Installed",
    "InitialTimestamp", "LastStop", "LastLogoffTime", "LastPasswordChange",
    "LastIncorrectPassword",
]

SECTION_COLUMNS = {
    "plugin": {
        "batchkeypath": [("registry.key", "keyword")],
        "batchvaluename": [("registry.batch_value_name", "keyword")],
        "valuename": [("registry.value", "keyword")],
        "valuedata": [("registry.data.strings", "keyword")],
        "lastwritetimestamp": [("registry.last_write", "date")],
        **{c.lower(): [(f"registry.plugin.{engine.snake(c)}", "date")] for c in PLUGIN_DATE_COLUMNS},
    },
}

TIME_PREFS = {
    "batch": ["registry.last_write"],
    # first plugin time column with a value; key last write first, then activity times
    "plugin": ["registry.last_write"] + [f"registry.plugin.{engine.snake(c)}" for c in PLUGIN_DATE_COLUMNS],
}

TIME_MEANING = {
    "lastwritetimestamp": "Registry key last write time",
    "timestamp": "Registry key last write time (plugin)",
    "executiontime": "BAM/DAM last execution time",
    "lastexecuted": "UserAssist last execution time",
    "executedon": "Last execution time recorded by the plugin",
    "openedon": "MRU entry last opened time",
    "lastopened": "Office MRU last opened time",
    "modifiedtime": "File last-modified time ($SI) recorded in AppCompatCache - NOT an execution time",
    "laststart": "Scheduled task last start time",
    "createdon": "Creation time recorded by the plugin",
}

class ES:
    def __init__(self, url, user=None, password=None, insecure=False):
        self.client = EsClient(url, user, password, insecure)

    def call(self, method, path, body=None, ctype="application/json"):
        """(status, payload); timeouts, connection errors and HTTP 429/5xx are retried."""
        return self.client.request(method, path, body, ctype)

    def existing_fields(self, index):
        """Top-level field -> mapping type for an existing index, or None if it doesn't exist."""
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            return None
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        props = next(iter(resp.values()), {}).get("mappings", {}).get("properties", {})
        return {f: m.get("type", "object") for f, m in props.items()}

    def create_index(self, index, typed_props):
        body = {
            "settings": {
                "number_of_replicas": 0,
                "index.mapping.total_fields.limit": 5000,
                # safety net: a stray bad value is kept in _source instead of failing the doc
                "index.mapping.ignore_malformed": True,
            },
            "mappings": {
                "date_detection": False,
                "numeric_detection": False,
                "dynamic_templates": [{"strings": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                }}],
                "properties": {**typed_props, **META_PROPS},
            },
        }
        status, resp = self.call("PUT", f"/{index}", json.dumps(body))
        if status >= 300:
            sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")

    def add_fields(self, index, typed_props):
        if not typed_props:
            return
        status, resp = self.call("PUT", f"/{index}/_mapping",
                                 json.dumps({"properties": typed_props}))
        if status >= 300:
            sys.exit(f"Could not update mapping of {index} ({status}): {json.dumps(resp)[:500]}")

    def bulk(self, lines, stats):
        if not lines:
            return
        status, resp = self.client.bulk(lines)  # retries failed requests and rejected items
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
        lines.clear()


def typed_props(write, renames, only_new_from=None):
    """Explicit mappings for non-string fields (strings go through the dynamic template)."""
    props = {}
    for f, t in write.items():
        if t == "string":
            continue
        name = renames.get(f, f)
        if only_new_from is not None and name in only_new_from:
            continue
        props[name] = {"type": t}
    return props


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="Load RECmd registry CSVs into one SOF-ELK index.")
    ap.add_argument("paths", nargs="+", help="CSV files or folders (searched recursively)")
    ap.add_argument("--hostname", required=True, help="Host the KAPE collection came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None, help="Override target index; must still end in -<hostname> (default: registry-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="UTC offset of the host's clock, used to convert *LOCAL* time columns"
                         " (e.g. +08:00). Without it LOCAL columns are kept as text.")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show plugins, inferred types and sample docs; send nothing")
    add_client_arguments(ap)
    args = ap.parse_args()
    apply_client_arguments(args)

    local_tz = None
    if args.local_tz:
        m = TZ_ARG_RE.match(args.local_tz.strip())
        if not m or int(m.group(2)) > 14:
            sys.exit(f"--local-tz must look like +08:00 or -0500, got '{args.local_tz}'")
        local_tz = f"{m.group(1)}{int(m.group(2)):02d}:{m.group(3) or '00'}"

    try:
        host = sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = resolve_index("registry", host, args.index)

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

    # Pass 1: group files by forensic_tag and infer types per tag
    plan = {}
    for f in files:
        header = next(read_rows(f), None)
        if not header:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        fields = clean_fields(header)
        tag, hive = tag_and_hive(f)
        p = plan.setdefault(tag.lower(), {"tag": tag, "files": [], "state": {}, "rows": 0})
        p["files"].append((f, fields, hive))
        p["rows"] += scan(f, fields, p["state"])

    for p in plan.values():
        p["types"] = finalize(p["state"], local_tz)
        p["ts"] = pick_time_field(p["types"])

    # One type per field across every plugin
    types, conflicts = merge_types(plan)

    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    loaded = sum(len(p["files"]) for p in plan.values())
    total_rows = sum(p["rows"] for p in plan.values())
    print(f"{loaded} CSV files, {total_rows} rows -> index '{index}', {len(plan)} source groups\n")
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        print(f"  source={p['tag']:<32} {len(p['files']):>3} file(s) {p['rows']:>8} rows")
    if conflicts:
        print("\nColumns with different types in different plugins (stored as string):")
        for f, v in sorted(conflicts.items()):
            print(f"  {f}: " + "; ".join(f"{t} in {', '.join(tags)}" for t, tags in v.items()))

    timestamp_check(plan, types, local_tz)

    if args.dry_run:
        typed = {f: t for f, t in types.items() if t != "string"}
        print(f"\nTyped fields: {typed or 'none (all strings)'}")
        print("\nSample document per source group:")
        for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
            f, fields, hive = p["files"][0]
            rows = read_rows(f)
            next(rows)
            sample = next(rows, None)
            if sample:
                meta = {"host": host, "tag": p["tag"], "hive": hive,
                        "source_file": f.name, "case": args.case}
                doc = build_doc(sample, fields, types, {}, p["ts"], meta, ingest_time, local_tz)
                print(f"  {p['tag']}: " + json.dumps(doc, ensure_ascii=False)[:700])
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

    existing = es.existing_fields(index)
    if existing is None:
        write, renames = types, {}
        es.create_index(index, typed_props(write, renames))
        print(f"Created index '{index}'")
    else:
        write, renames = resolve_against_existing(types, existing)
        es.add_fields(index, typed_props(write, renames, only_new_from=existing))
        print(f"Index '{index}' exists - appending")
        for f, new in sorted(renames.items()):
            print(f"  note: '{f}' is mapped as {existing[f]} in the index but this data doesn't fit;"
                  f" storing it as '{new}'")

    total = {"ok": 0, "errors": 0}
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        stats, lines = {"ok": 0, "errors": 0}, []
        for f, fields, hive in p["files"]:
            meta = {"host": host, "tag": p["tag"], "hive": hive,
                    "source_file": f.name, "case": args.case}
            # ID = host + tool + file name (minus KAPE's run timestamp) + row position + row.
            # Re-runs overwrite instead of duplicating; identical rows in a file stay separate.
            stable_name = re.sub(r"^\d{8,}_", "", f.name)
            rows = read_rows(f)
            next(rows)
            for n, row in enumerate(rows):
                doc = build_doc(row, fields, write, renames, p["ts"], meta, ingest_time, local_tz)
                doc_id = hashlib.sha1(json.dumps(
                    [host, p["tag"], stable_name, n, row], ensure_ascii=False).encode()).hexdigest()
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.bulk(lines, stats)
            es.bulk(lines, stats)
        print(f"  {p['tag']:<34} {stats['ok']:>8} indexed, {stats['errors']} errors")
        total["ok"] += stats["ok"]
        total["errors"] += stats["errors"]

    log.info("done: index=%s ok=%d errors=%d", index, total["ok"], total["errors"])
    print(f"\nDone: {total['ok']} documents indexed into '{index}', {total['errors']} errors.")
    print(f"In Kibana, create a data view for '{index}' with @timestamp as the time field,"
          f" then filter or break down by host.name.")


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load RECmd batch and plugin CSVs into a host-specific SOF-ELK index with a"
                         " fixed schema.")

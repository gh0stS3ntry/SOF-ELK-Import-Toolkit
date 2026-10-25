#!/usr/bin/env python3
"""Load AmcacheParser CSV sections into amcache-<hostname>.

Every AmcacheParser column is mapped to a fixed field with a fixed type, defined by the explicit
index template in Windows/index_templates/index-amcache.json (plus the shared
component-toolkit-common.json). ECS names are used where they fit (file.*, package.*), and
everything else lives under amcache.* in snake_case. Nothing is inferred per run, so every host's
amcache-<hostname> index has the same schema and ES|QL queries work across amcache-*.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/amcache.md.
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

# --------------------------------------------------------------------------- column map
#
# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions are listed in sof_elk_template_importer.CONV_TYPE.

COLUMNS = {
    # Present in several sections
    "keyname": [("amcache.key_name", "keyword")],
    "keylastwritetimestamp": [("amcache.key_last_write", "date")],
    "programid": [("amcache.program_id", "keyword")],
    "programinstanceid": [("amcache.program_instance_id", "keyword")],
    "language": [("amcache.language", "long")],
    "manufacturer": [("amcache.manufacturer", "keyword")],
    "description": [("amcache.description", "keyword")],
    "name": [("amcache.name", "keyword")],
    "version": [("amcache.version", "keyword")],
    "productversion": [("amcache.product_version", "keyword")],
    "class": [("amcache.class", "keyword")],
    "inf": [("amcache.inf", "keyword")],
    "provider": [("amcache.provider", "keyword")],
    "service": [("amcache.service", "keyword")],
    "driverid": [("amcache.driver_id", "keyword")],
    "drivername": [("amcache.driver_name", "keyword")],
    "driverpackagestrongname": [("amcache.driver_package_strong_name", "keyword")],
    "driverinbox": [("amcache.driver_in_box", "boolean")],

    # AssociatedFileEntries / UnassociatedFileEntries (InventoryApplicationFile)
    "applicationname": [("amcache.application_name", "keyword")],
    "filekeylastwritetimestamp": [("amcache.file_key_last_write", "date")],
    "sha1": [("file.hash.sha1", "sha1")],
    "isoscomponent": [("amcache.is_os_component", "boolean")],
    "fullpath": [("file.path", "path")],
    "fileextension": [("file.extension", "ext")],
    "linkdate": [("amcache.link_date", "date")],
    "productname": [("file.pe.product", "keyword")],
    "size": [("file.size", "long")],
    "longpathhash": [("amcache.long_path_hash", "keyword")],
    "binarytype": [("amcache.binary_type", "keyword")],
    "ispefile": [("amcache.is_pe_file", "boolean")],
    "binfileversion": [("amcache.bin_file_version", "keyword")],
    "binproductversion": [("amcache.bin_product_version", "keyword")],
    "usn": [("amcache.usn", "long")],

    # ProgramEntries (InventoryApplication)
    "publisher": [("amcache.publisher", "keyword")],
    "installdate": [("package.installed", "date")],
    "installdatearplastmodified": [("amcache.install_date_arp_last_modified", "date")],
    "installdatemsi": [("amcache.install_date_msi", "date")],
    "installdatefromlinkfile": [("amcache.install_date_from_link_file", "date")],
    "osversionatinstalltime": [("amcache.os_version_at_install_time", "keyword")],
    "bundlemanifestpath": [("amcache.bundle_manifest_path", "keyword")],
    "hiddenarp": [("amcache.hidden_arp", "boolean")],
    "inboxmodernapp": [("amcache.inbox_modern_app", "boolean")],
    "manifestpath": [("amcache.manifest_path", "keyword")],
    "msipackagecode": [("amcache.msi_package_code", "keyword")],
    "msiproductcode": [("amcache.msi_product_code", "keyword")],
    "packagefullname": [("amcache.package_full_name", "keyword")],
    "registrykeypath": [("amcache.registry_key_path", "keyword")],
    "rootdirpath": [("package.path", "keyword")],
    "type": [("amcache.type", "keyword")],
    "source": [("amcache.source", "keyword")],
    "storeapptype": [("amcache.store_app_type", "keyword")],
    "uninstallstring": [("amcache.uninstall_string", "keyword")],

    # DeviceContainers
    "categories": [("amcache.categories", "keyword")],
    "discoverymethod": [("amcache.discovery_method", "keyword")],
    "friendlyname": [("amcache.friendly_name", "keyword")],
    "icon": [("amcache.icon", "keyword")],
    "isactive": [("amcache.is_active", "boolean")],
    "isconnected": [("amcache.is_connected", "boolean")],
    "ismachinecontainer": [("amcache.is_machine_container", "boolean")],
    "isnetworked": [("amcache.is_networked", "boolean")],
    "ispaired": [("amcache.is_paired", "boolean")],
    "modelid": [("amcache.model_id", "keyword")],
    "modelname": [("amcache.model_name", "keyword")],
    "modelnumber": [("amcache.model_number", "keyword")],
    "primarycategory": [("amcache.primary_category", "keyword")],
    "state": [("amcache.state", "long")],

    # DevicePnps
    "busreporteddescription": [("amcache.bus_reported_description", "keyword")],
    "classguid": [("amcache.class_guid", "keyword")],
    "compid": [("amcache.compid", "keyword")],
    "containerid": [("amcache.container_id", "keyword")],
    "driververdate": [("amcache.driver_ver_date", "mdy")],
    "driververversion": [("amcache.driver_ver_version", "keyword")],
    "enumerator": [("amcache.enumerator", "keyword")],
    "hwid": [("amcache.hwid", "keyword")],
    "installstate": [("amcache.install_state", "long")],
    "matchingid": [("amcache.matching_id", "keyword")],
    "model": [("amcache.model", "keyword")],
    "parentid": [("amcache.parent_id", "keyword")],
    "problemcode": [("amcache.problem_code", "long")],
    "stackid": [("amcache.stack_id", "keyword")],

    # DriveBinaries (InventoryDriverBinary)
    "drivertimestamp": [("amcache.link_date", "date")],  # PE header TimeDateStamp, same as LinkDate
    "driverlastwritetime": [("file.mtime", "date")],
    "driveriskernelmode": [("amcache.driver_is_kernel_mode", "boolean")],
    "driversigned": [("amcache.driver_signed", "boolean")],
    "driverchecksum": [("amcache.driver_checksum", "long")],
    "drivercompany": [("file.pe.company", "keyword")],
    "drivertype": [("amcache.driver_type", "long")],
    "driverversion": [("file.pe.file_version", "keyword")],
    "imagesize": [("amcache.image_size", "long")],
    "product": [("file.pe.product", "keyword")],
    "wdfversion": [("amcache.wdf_version", "keyword")],

    # DriverPackages
    "date": [("amcache.driver_date", "date")],
    "directory": [("amcache.directory", "keyword")],
    "hwids": [("amcache.hwid", "keyword")],
    "submissionid": [("amcache.submission_id", "keyword")],
    "sysfile": [("amcache.sys_file", "keyword")],

    # ShortCuts
    "lnkname": [("file.path", "path")],
}

# Section-specific meanings of columns whose name is reused across sections
SECTION_COLUMNS = {
    "file": {
        "name": [("file.name", "name")],
        "version": [("file.pe.file_version", "keyword")],
        "description": [("file.pe.description", "keyword")],
        # Older (Windows 8 / early 10) Amcache "File" key layout
        "programname": [("amcache.application_name", "keyword")],
        "fileidlastwritetimestamp": [("amcache.file_key_last_write", "date")],
        "volumeid": [("amcache.volume_id", "keyword")],
        "volumeidlastwritetimestamp": [("amcache.volume_id_last_write", "date")],
        "fileid": [("amcache.file_id", "keyword")],
        "mftentrynumber": [("amcache.mft_entry_number", "long")],
        "mftsequencenumber": [("amcache.mft_sequence_number", "long")],
        "filesize": [("file.size", "long")],
        "fileversionstring": [("file.pe.file_version", "keyword")],
        "fileversionnumber": [("amcache.file_version_number", "keyword")],
        "filedescription": [("file.pe.description", "keyword")],
        "sizeofimage": [("amcache.image_size", "long")],
        "peheaderhash": [("amcache.pe_header_hash", "keyword")],
        "peheaderchecksum": [("amcache.pe_header_checksum", "long")],
        "companyname": [("file.pe.company", "keyword")],
        "created": [("file.created", "date")],
        "lastmodified": [("file.mtime", "date")],
        "lastmodified2": [("amcache.last_modified2", "date")],
        "compiletime": [("amcache.compile_time", "date")],
        "languageid": [("amcache.language", "long")],
    },
    "program": {
        "name": [("package.name", "keyword")],
        "version": [("package.version", "keyword")],
    },
    "drivebinaries": {
        # KeyName is the driver's path (c:/windows/system32/drivers/x.sys)
        "keyname": [("amcache.key_name", "keyword"), ("file.path", "path")],
        "drivername": [("amcache.driver_name", "keyword"), ("file.name", "name")],
    },
}

# event.dataset per AmcacheParser section (unknown sections: amcache.<snake_case>)
DATASETS = {
    "associatedfileentries": "amcache.associated_file_entries",
    "unassociatedfileentries": "amcache.unassociated_file_entries",
    "fileentries": "amcache.file_entries",
    "programentries": "amcache.program_entries",
    "devicecontainers": "amcache.device_containers",
    "devicepnps": "amcache.device_pnps",
    "drivebinaries": "amcache.drive_binaries",
    "driverpackages": "amcache.driver_packages",
    "shortcuts": "amcache.shortcuts",
}

# @timestamp candidates per section kind, as template fields (first one with a value wins)
TIME_PREFS = {
    "file": ["amcache.file_key_last_write", "amcache.key_last_write"],
    "program": ["package.installed", "amcache.key_last_write"],
}
TIME_DEFAULT = ["amcache.key_last_write", "amcache.file_key_last_write"]

# What each @timestamp source column means (stored in kape.timestamp_meaning)
TIME_MEANING = {
    "filekeylastwritetimestamp": "Amcache file key last write - often close to first execution, not proof of it",
    "fileidlastwritetimestamp": "Amcache file key last write - often close to first execution, not proof of it",
    "keylastwritetimestamp": "Amcache registry key last write time",
    "installdate": "Program install date recorded in Amcache",
}


# --------------------------------------------------------------------------- sections

def detect_section(path, header):
    """AmcacheParser section name (e.g. 'ProgramEntries') from the file name or columns, or None."""
    h = {c.strip().lower() for c in header}
    stem = re.sub(r"^\d{8,}_", "", path.stem)
    if re.search(r"appcompatcache|shimcache", stem, re.I) or {"cacheentryposition", "lastmodifiedtimeutc"} <= h:
        return None  # ShimCache, handled by shimcache2sofelk.py
    m = re.search(r"amcache[_ -]+(.+)$", stem, re.I)
    if m:
        section = re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).strip("_")[:50]
        return section or "Unknown"
    if "filekeylastwritetimestamp" in h or ("sha1" in h and "programid" in h):
        return "FileEntries"
    return None


def section_kind(section):
    s = section.lower().replace("_", "")
    if s.endswith("fileentries"):
        return "file"
    if s == "programentries":
        return "program"
    return s


def dataset_for(section):
    s = section.lower().replace("_", "")
    return DATASETS.get(s, f"amcache.{engine.snake(section)}")


    ts, ts_col = first_ts(row, fields, ts_field, local_tz)
    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": meta["host"]}
    fobj = {}
    pi = meta.get("path_col")
    if pi is not None and pi < len(row) and row[pi].strip():
        path = row[pi].strip().lower()
        fobj["path"] = path
        fobj["name"] = re.split(r"[\\/]", path)[-1]
    hi = meta.get("sha1_col")
    if hi is not None and hi < len(row) and row[hi].strip():
        sha1 = row[hi].strip().lower()
        if len(sha1) == 44 and sha1.startswith("0000"):
            sha1 = sha1[4:]  # older Amcache stores SHA1 with a 0000 prefix
        fobj["hash"] = {"sha1": sha1}
    if fobj:
        doc["file"] = fobj
    src = ts_col or "ingest_time"
    doc["kape"] = {
        "source_file": meta["source_file"],
        "timestamp_source": src,
        "timestamp_meaning": TIME_MEANING.get(src.lower(), "Timestamp column: " + src),
    }
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc


def timestamp_check(plan, types, local_tz):
    """Print how each tool's @timestamp is set and anything that needs a look. Returns note count."""
    notes_total = 0
    print("\nTimestamp check")
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        st, chain, rows = p["state"], p["ts"], p["rows"]
        notes = []
        if chain:
            used, none = count_ts_coverage(p, local_tz)
            parts = []
            for c in chain:
                zone = f"local {local_tz}" if is_local(c) else "UTC"
                parts.append(f"{c} ({zone}) {used[c]}")
            head = f"OK    @timestamp <- " + ", then ".join(parts) + f"  [of {rows} rows]"
            if none:
                notes.append(f"{none} row(s) have none of {', '.join(chain)} -> those use ingest time")
            for c in chain:
                if types.get(c) != "date":
                    notes.append(f"{c} is text in other tools, so it is a text field in the index"
                                 f" (this tool's @timestamp is still correct)")
        else:
            head = "WARN  @timestamp <- ingest time (no usable UTC date column)"
            if not rows:
                head = "OK    header only, no rows"
            if rows:
                notes.append("these rows will all sit at the load time in Kibana timelines")
        for f, s in st.items():
            if not s["filled"]:
                continue
            all_dates = s["date_hits"] == s["filled"]
            if is_local(f) and all_dates and not local_tz:
                notes.append(f"{f}: host LOCAL time with no offset -> stored as text, not used for"
                             f" @timestamp (add --local-tz +HH:MM to convert it)")
            elif is_local(f) and all_dates:
                notes.append(f"{f}: LOCAL time, converted using offset {local_tz}")
            elif not all_dates and s["date_hits"]:
                notes.append(f"{f}: {s['date_hits']}/{s['filled']} values are timestamps, the rest"
                             f" aren't (e.g. \"{s['bad']}\") -> stored as text")
            elif (s["date_hits"] == 0 and TIME_NAME_RE.search(f) and s["bad"]
                  and OTHER_DATE_RE.search(s["bad"])):
                notes.append(f"{f}: looks like a date in an unrecognised format"
                             f" (e.g. \"{s['bad']}\") -> stored as text")
        print(f"  {p['tag']:<32} {head}")
        if chain:
            meaning = TIME_MEANING.get(chain[0].lower())
            if meaning:
                print(f"  {'':<32}   means: {meaning}")
        for n in notes:
            print(f"  {'':<32}   - {n}")
        notes_total += len(notes)
    if notes_total:
        print(f"\n  {notes_total} note(s). None of these stop ingestion: every row still loads,"
              f" affected values are kept as text.")
    else:
        print("\n  No timestamp issues found.")
    return notes_total


# --------------------------------------------------------------------------- Elasticsearch

META_PROPS = {
    "@timestamp": {"type": "date"},
    "host": {"properties": {"name": {"type": "keyword"}}},
    "file": {"properties": {
        "path": {"type": "keyword", "ignore_above": 4096},
        "name": {"type": "keyword"},
        "hash": {"properties": {"sha1": {"type": "keyword"}}},
    }},
    "kape": {"properties": {
        "source_file": {"type": "keyword"},
        "timestamp_source": {"type": "keyword"},
        "timestamp_meaning": {"type": "keyword"},
    }},
    "case": {"type": "keyword"},
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
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def host_count(self, index, host):
        """Refresh, then count the documents this host has in the index."""
        self.call("POST", f"/{index}/_refresh")
        q = {"query": {"term": {"host.name": host}}}
        status, resp = self.call("POST", f"/{index}/_count", json.dumps(q))
        return resp.get("count") if status < 300 else None


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

def file_meta(f, fields, host, tag, case):
    """Per-file values build_doc needs: where the path and hash columns are, and labels."""
    lower = [x.lower() for x in fields]
    path_col = next((lower.index(c) for c in PATH_COLUMNS if c in lower), None)
    sha1_col = lower.index("sha1") if "sha1" in lower else None
    return {"host": host, "tag": tag, "source_file": f.name, "case": case,
            "path_col": path_col, "sha1_col": sha1_col}


def main():
    ap = argparse.ArgumentParser(
        description="Load AmcacheParser CSVs into a host-specific SOF-ELK index.")
    ap.add_argument("paths", nargs="+", help="CSV files or folders (searched recursively)")
    ap.add_argument("--hostname", required=True, help="Host the KAPE collection came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None,
                    help="Override target index; must still end in -<hostname> (default: amcache-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="UTC offset of the host's clock, used to convert *LOCAL* time columns"
                         " (e.g. +08:00). Without it LOCAL columns are kept as text.")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show tools, inferred types and sample docs; send nothing")
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
    index = resolve_index("amcache", host, args.index)

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
    plan, skipped = {}, []
    for f in files:
        header = next(read_rows(f), None)
        if not header:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        fields = clean_fields(header)
        tag = detect_tag(f, fields)
        if not tag or not tag.startswith("Amcache"):
            skipped.append(f.name)
            continue
        p = plan.setdefault(tag.lower(), {"tag": tag, "files": [], "state": {}, "rows": 0})
        p["files"].append((f, fields))
        p["rows"] += scan(f, fields, p["state"])

    if not plan:
        sys.exit("No matching CSV files found for this importer.")

    for p in plan.values():
        p["types"] = finalize(p["state"], local_tz)
        p["ts"] = pick_time_fields(p["types"], p["tag"])

    # One type per field across every tool
    types, conflicts = merge_types(plan)

    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    if skipped:
        print(f"Skipped {len(skipped)} CSV(s) outside this importer's supported source type"
              f":")
        for n in skipped:
            print(f"  - {n}")
        print()
    if not plan:
        sys.exit("Nothing to load.")
    loaded = sum(len(p["files"]) for p in plan.values())
    total_rows = sum(p["rows"] for p in plan.values())
    print(f"{loaded} CSV files, {total_rows} rows -> index '{index}', {len(plan)} source groups\n")
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        print(f"  source={p['tag']:<32} {len(p['files']):>3} file(s) {p['rows']:>8} rows")
    if conflicts:
        print("\nColumns with different types in different tools (stored as string):")
        for f, v in sorted(conflicts.items()):
            print(f"  {f}: " + "; ".join(f"{t} in {', '.join(tags)}" for t, tags in v.items()))

    timestamp_check(plan, types, local_tz)

    if args.dry_run:
        typed = {f: t for f, t in types.items() if t != "string"}
        print(f"\nTyped fields: {typed or 'none (all strings)'}")
        print("\nSample document per source group:")
        for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
            f, fields = p["files"][0]
            rows = read_rows(f)
            next(rows)
            sample = next(rows, None)
            if sample:
                meta = file_meta(f, fields, host, p["tag"], args.case)
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

    total = {"ok": 0, "errors": 0, "updated": 0}
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        stats, lines = {"ok": 0, "errors": 0, "updated": 0}, []
        for f, fields in p["files"]:
            meta = file_meta(f, fields, host, p["tag"], args.case)
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
        new = stats["ok"] - stats["updated"]
        print(f"  {p['tag']:<34} {p['rows']:>8} rows: {new} new, {stats['updated']} already in index,"
              f" {stats['errors']} errors")
        for k in total:
            total[k] += stats[k]

    rows_total = sum(p["rows"] for p in plan.values())
    new = total["ok"] - total["updated"]
    log.info("done: index=%s ok=%d errors=%d", index, total["ok"], total["errors"])
    print(f"\nDone: {rows_total} rows read -> {new} new documents, {total['updated']} already in"
          f" index (re-run), {total['errors']} errors.")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == rows_total else "DOES NOT MATCH"
        print(f"Index check: '{index}' now holds {in_index} documents for host '{host}'"
              f" ({verdict} the {rows_total} rows read).")
        if in_index > rows_total:
            print("  More documents than rows: this host was probably loaded earlier with different"
                  " files or an older version of the script. Delete its documents and reload"
                  " to get a clean count.")
    print(f"In Kibana, create a data view for '{index}' with @timestamp as the time field,"
          f" then search file.name / file.hash.sha1.")


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load AmcacheParser CSVs into a host-specific SOF-ELK index with a fixed schema.")

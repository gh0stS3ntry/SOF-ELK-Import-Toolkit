#!/usr/bin/env python3
"""Load AmcacheParser CSV sections into amcache-<hostname>.

Every AmcacheParser column is mapped to a fixed field with a fixed type, defined by the explicit
index template in Windows/index_templates/index-amcache.json (plus the shared
component-toolkit-common.json). ECS names are used where they fit (file.*, package.*), and
everything else lives under amcache.* in snake_case. Nothing is inferred per run, so every host's
amcache-<hostname> index has the same schema and ES|QL queries work across amcache-*.

Columns this script does not know (e.g. from a newer AmcacheParser) are kept as keywords under
amcache.unmapped.<column> and listed in the run summary. Values that do not fit their field's
type are kept as "Column=value" strings in amcache.malformed, so nothing is silently dropped.
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

ARTIFACT = "amcache"
SCHEMA_VERSION = 1

# EZ Tools write UTC timestamps like "2026-10-08 09:12:44.1234567" (7 fractional digits)
ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
# DevicePnps DriverVerDate is month-day-year, e.g. 06-21-2006
MDY_RE = re.compile(r"^(\d{1,2})[-/](\d{1,2})[-/](\d{4})$")
INT_RE = re.compile(r"^-?\d{1,19}$")
BOOLS = {"true": True, "false": False}
INT64_MAX = 2**63 - 1
TZ_ARG_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

# --------------------------------------------------------------------------- column map
#
# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions and the template type each must have:
#   keyword  value as-is (trimmed)                         keyword
#   date     EZ Tools UTC timestamp -> ISO 8601 (ms)        date
#   mdy      MM-DD-YYYY date -> ISO 8601 midnight UTC       date
#   long     integer                                        long
#   boolean  True / False                                   boolean
#   path     lower-case, "/" -> "\"                         keyword
#   name     lower-case                                     keyword
#   ext      lower-case, no leading dot                     keyword
#   sha1     lower-case, legacy "0000" prefix removed       keyword

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

# Template type each conversion must land in
CONV_TYPE = {"keyword": "keyword", "path": "keyword", "name": "keyword", "ext": "keyword",
             "sha1": "keyword", "date": "date", "mdy": "date", "long": "long", "boolean": "boolean"}

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
    "ingest_time": "No usable time in this row - time the row was loaded",
}


# --------------------------------------------------------------------------- helpers

def parse_ts(value):
    """EZ Tools UTC timestamp -> ISO 8601 with millisecond precision, or None."""
    m = ISO_RE.match(value.strip())
    if not m:
        return None
    date, time, frac, tz = m.groups()
    frac = (frac or "")[:3].ljust(3, "0")
    if not tz:
        tz = "Z"  # AmcacheParser output is UTC
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
    return DATASETS.get(s, f"amcache.{snake(section)}")


def column_plan(section, header):
    """Per-column targets for one file: list of (column, [(field, conv), ...]) in header order.
    Unknown columns go to amcache.unmapped.<snake_case> as keyword."""
    overrides = SECTION_COLUMNS.get(section_kind(section), {})
    plan, unknown, used = [], [], set()
    for col in header:
        key = col.strip().lower()
        targets = overrides.get(key) or COLUMNS.get(key)
        if targets is None:
            name = snake(col)
            base, i = name, 2
            while name in used:
                name, i = f"{base}_{i}", i + 1
            used.add(name)
            targets = [(f"amcache.unmapped.{name}", "keyword")]
            unknown.append(col.strip())
        plan.append((col.strip(), targets))
    return plan, unknown


def check_against_template(types):
    """Every field the column map writes must exist in the template with the same type."""
    problems = []
    tables = [COLUMNS] + list(SECTION_COLUMNS.values())
    for table in tables:
        for col, targets in table.items():
            for field, conv in targets:
                want = CONV_TYPE[conv]
                have = types.get(field)
                if have != want:
                    problems.append(f"{col} -> {field}: template has {have or 'nothing'}, needs {want}")
    for field in ("@timestamp", "host.name", "case", "event.dataset", "kape.source_file",
                  "kape.timestamp_source", "kape.timestamp_meaning", "file.name",
                  "file.extension", "amcache.malformed"):
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


def build_doc(row, plan, kind, meta, ingest_time, issues):
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

    # ECS file.name / file.extension from the path when the section has no Name column
    path = get_field(doc, "file.path")
    if path and not get_field(doc, "file.name"):
        set_field(doc, "file.name", re.split(r"[\\/]", path)[-1])
    name = get_field(doc, "file.name")
    if name and "." in name and not get_field(doc, "file.extension"):
        set_field(doc, "file.extension", name.rsplit(".", 1)[1])
    if malformed:
        set_field(doc, "amcache.malformed", malformed)

    ts, src = None, None
    for field in TIME_PREFS.get(kind, TIME_DEFAULT):
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
        "timestamp_meaning": TIME_MEANING.get(src.lower(), "Timestamp column: " + src),
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

    def prepare_index(self, index, body):
        """Create the index with the template body, or bring an existing toolkit index up to date."""
        mapping = self.index_mapping(index)
        if mapping is None:
            status, resp = self.call("PUT", f"/{index}", json.dumps(body))
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
            return "created"
        meta = mapping.get("_meta", {})
        if meta.get("toolkit_schema") != ARTIFACT:
            sys.exit(
                f"Index '{index}' exists but was created by an older version of this importer"
                f" (raw AmcacheParser column names, types inferred per run). Mixing the two"
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

def main():
    ap = argparse.ArgumentParser(
        description="Load AmcacheParser CSVs into a host-specific SOF-ELK index with a fixed schema.")
    ap.add_argument("paths", nargs="+", help="CSV files or folders (searched recursively)")
    ap.add_argument("--hostname", required=True, help="Host the KAPE collection came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None,
                    help="Override target index (default: amcache-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="Accepted for wrapper compatibility; AmcacheParser output is UTC, so it is"
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
    index = (args.index or f"amcache-{host}").lower()
    if args.index and index != args.index:
        print(f"note: Elasticsearch index names must be lower-case, using '{index}'\n")

    component, index_tpl, body = templates.load(ARTIFACT)
    types = templates.field_types(body["mappings"])
    problems = check_against_template(types)
    if problems:
        sys.exit("Column map and index-amcache.json disagree:\n  " + "\n  ".join(problems))

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
        section = detect_section(f, header)
        if not section:
            skipped.append(f.name)
            continue
        plan, unknown = column_plan(section, header)
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
        print(f"  {dataset_for(s['section']):<36} {len(s['files']):>3} file(s) {s['rows']:>8} rows")
    unknown_any = [(s["section"], sorted(s["unknown"])) for s in ordered if s["unknown"]]
    if unknown_any:
        print("\nColumns not in the Amcache schema (kept as keywords under amcache.unmapped.*):")
        for section, cols in unknown_any:
            print(f"  {section}: {', '.join(cols)}")
    if args.local_tz:
        print("\nnote: --local-tz ignored; AmcacheParser timestamps are UTC.")

    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def file_meta(f, s):
        return {"host": host, "dataset": dataset_for(s["section"]), "source_file": f.name,
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
                doc = build_doc(sample, plan, section_kind(s["section"]), file_meta(f, s),
                                ingest_time, issues)
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

    templates.install(es.call, ARTIFACT, component, index_tpl)
    print(f"Installed index template 'sofelk-toolkit-{ARTIFACT}' (amcache-*)")
    state = es.prepare_index(index, body)
    print(f"Index '{index}': {state}")

    total = {"ok": 0, "errors": 0, "updated": 0}
    issues = {}
    for s in ordered:
        stats, lines = {"ok": 0, "errors": 0, "updated": 0}, []
        kind = section_kind(s["section"])
        tag = f"Amcache_{s['section']}"
        for f, plan in s["files"]:
            meta = file_meta(f, s)
            # ID = host + section + file name (minus KAPE's run timestamp) + row position + row.
            # Re-runs overwrite instead of duplicating; identical rows in a file stay separate.
            stable_name = re.sub(r"^\d{8,}_", "", f.name)
            rows = read_rows(f)
            next(rows)
            for n, row in enumerate(rows):
                doc = build_doc(row, plan, kind, meta, ingest_time, issues)
                doc_id = hashlib.sha1(json.dumps(
                    [host, tag, stable_name, n, row], ensure_ascii=False).encode()).hexdigest()
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.bulk(lines, stats)
            es.bulk(lines, stats)
        new = stats["ok"] - stats["updated"]
        print(f"  {dataset_for(s['section']):<36} {s['rows']:>8} rows: {new} new,"
              f" {stats['updated']} already in index, {stats['errors']} errors")
        for k in total:
            total[k] += stats[k]

    if issues:
        print("\nValues that did not fit their field type (kept as text in amcache.malformed):")
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
    print(f"In Kibana, use the '{ARTIFACT}-*' data view (time field @timestamp) and filter on"
          f" event.dataset, file.path, file.hash.sha1.")


if __name__ == "__main__":
    main()

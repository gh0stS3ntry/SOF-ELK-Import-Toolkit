#!/usr/bin/env python3
"""Stream PECmd JSON or CSV records into a per-host SOF-ELK-compatible prefetch index."""
import argparse
from sof_elk_json_bulk_common import (DATE_STATS, add_common_arguments, base_event, copy_renames, get_nested,
                                     normalize_date_field, parse_timestamp, remove_nested, run_import, set_nested)

INDEX_PREFIX = "prefetch"
LABEL_TYPE = "kape_prefetch"
PATTERNS = ("*_PECmd_Output.json", "*_PECmd_Output.json.gz", "*_PECmd_Output.csv")
EXCLUDES = ("*_PECmd_Output_Timeline.json", "*_PECmd_Output_Timeline.json.gz")
RENAMES = {
    "SourceFilename": "file.path", "SourceCreated": "file.stdinfo.ctime", "SourceModified": "file.stdinfo.mtime",
    "SourceAccessed": "file.stdinfo.accessed", "ExecutableName": "file.target.path", "Hash": "kape.prefetch.hash",
    "Size": "file.size", "Version": "kape.prefetch.version", "RunCount": "kape.prefetch.run_count",
    "LastRun": "kape.prefetch.last_run", "Volume0Name": "kape.prefetch.volume.name",
    "Volume0Serial": "volume.serial_number", "Volume0Created": "kape.prefetch.volume.created",
    "ParsingError": "kape.prefetch.parsing_error", "Directories": "kape.prefetch.directories",
    "FilesLoaded": "kape.prefetch.files_loaded",
}
DATE_FIELDS = ["file.stdinfo.ctime", "file.stdinfo.mtime", "file.stdinfo.accessed", "kape.prefetch.last_run", "kape.prefetch.volume.created"]
MAPPINGS = {"@timestamp": {"type": "date"}, "labels.type": {"type": "keyword"}, "tags": {"type": "keyword"},
            "log.file.path": {"type": "keyword"}, "sof-elk.path": {"type": "keyword"}, "file.size": {"type": "long"},
            "kape.prefetch.run_count": {"type": "long"}, "kape.prefetch.last_run": {"type": "date"},
            "kape.prefetch.volume.created": {"type": "date"}, "prefetch.previous_runs": {"type": "date"}}
MAPPINGS.update({field: {"type": "date"} for field in DATE_FIELDS})


def to_integer(value):
    if isinstance(value, bool):
        return int(value)
    try:
        text = str(value).strip()
        if text and (text.isdigit() or (text.startswith("-") and text[1:].isdigit())):
            return int(text)
    except (TypeError, ValueError):
        pass
    return value


def split_csv_values(value):
    if isinstance(value, str) and value != "":
        return value.split(", ")
    return value


def transform(raw, source_path, hostname, label_type, ingest_time):
    if not isinstance(raw, dict):
        raise ValueError("PECmd JSON records must be objects")
    doc = base_event(raw, source_path, hostname, label_type, ingest_time)
    copy_renames(raw, doc, RENAMES)
    file_obj = doc.setdefault("file", {})
    kape = doc.setdefault("kape", {}).setdefault("prefetch", {})
    file_obj["extension"] = "pf"

    if kape.get("directories") is not None:
        kape["directories"] = split_csv_values(kape["directories"])
    if kape.get("files_loaded") is not None:
        kape["files_loaded"] = split_csv_values(kape["files_loaded"])

    # The pipeline discards these well-known .NET unset sentinels before date parsing.
    invalid_sentinels = {"", "0001-01-01 00:00:00", "0001-01-01T00:00:00.0000000+00:00"}
    for field in ("kape.prefetch.last_run", "kape.prefetch.volume.created"):
        value = get_nested(doc, field)
        if isinstance(value, str) and value in invalid_sentinels:
            remove_nested(doc, field)

    for field in DATE_FIELDS:
        normalize_date_field(doc, field)

    previous_runs = []
    for n in range(8):
        key = f"PreviousRun{n}"
        value = raw.get(key)
        if value is None or value == "":
            continue
        normalized = parse_timestamp(value)
        if normalized:
            previous_runs.append(normalized)
        else:
            DATE_STATS.add_invalid("prefetch.previous_runs", value)
    if previous_runs:
        set_nested(doc, "prefetch.previous_runs", previous_runs)

    if file_obj.get("size") is not None:
        file_obj["size"] = to_integer(file_obj["size"])
    if kape.get("run_count") is not None:
        kape["run_count"] = to_integer(kape["run_count"])

    # Common postprocessing splits source file.path when directory/name are not already set.
    if file_obj.get("path") and (not file_obj.get("directory") or not file_obj.get("name")):
        path = str(file_obj["path"])
        directory, sep, name = path.rpartition("\\")
        if not sep:
            directory, sep, name = path.rpartition("/")
        if not file_obj.get("directory") and directory:
            file_obj["directory"] = directory
        if not file_obj.get("name") and name:
            file_obj["name"] = name

    # Most recent execution time wins; source mtime is used only when LastRun is absent.
    last_run = get_nested(doc, "kape.prefetch.last_run")
    source_mtime = get_nested(doc, "file.stdinfo.mtime")
    if last_run not in (None, ""):
        doc["@timestamp"] = last_run
    elif source_mtime not in (None, ""):
        doc["@timestamp"] = source_mtime
    else:
        doc["@timestamp"] = ingest_time

    target_path = get_nested(doc, "file.target.path")
    run_count = get_nested(doc, "kape.prefetch.run_count")
    if target_path and run_count:
        doc["message"] = f"Prefetch: {target_path} executed {run_count} time(s)"
    elif target_path:
        doc["message"] = f"Prefetch: {target_path}"
    else:
        doc["message"] = "Prefetch record (no executable name parsed)"
    return doc


def main():
    parser = argparse.ArgumentParser()
    add_common_arguments(parser, "Load PECmd JSON records directly into prefetch-<hostname>.")
    args = parser.parse_args()
    run_import(args, LABEL_TYPE, INDEX_PREFIX, PATTERNS, EXCLUDES, MAPPINGS, transform,
               csv_int_fields={"Size", "RunCount"},
               csv_bool_fields={"ParsingError"})

if __name__ == "__main__":
    main()

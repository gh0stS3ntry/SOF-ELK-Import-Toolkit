#!/usr/bin/env python3
"""Stream MFTECmd JSON or CSV records into a per-host SOF-ELK-compatible filesystem index."""
import argparse
import re
from pathlib import Path
from sof_elk_json_bulk_common import (add_common_arguments, add_tag, base_event, copy_renames, get_nested,
                                     normalize_date_field, parse_timestamp, run_import, set_nested)

INDEX_PREFIX = "filesystem"
LABEL_TYPE = "kape_filesystem"
PATTERNS = ("*_MFTECmd*_Output.json", "*_MFTECmd*_Output.json.gz", "*_MFTECmd*_Output.csv")
EXCLUDES = ()

RENAMES = {
    "LastRecordChange0x10": "file.stdinfo.ctime", "LastModified0x10": "file.stdinfo.mtime",
    "LastAccess0x10": "file.stdinfo.accessed", "Created0x10": "file.stdinfo.created",
    "LastRecordChange0x30": "file.filename.ctime", "LastModified0x30": "file.filename.mtime",
    "LastAccess0x30": "file.filename.accessed", "Created0x30": "file.filename.created",
    "InUse": "kape.mft.inuse", "HasAds": "kape.mft.hasads", "IsAds": "kape.mft.isads",
    "Timestomped": "kape.mft.timestomped", "Copied": "kape.mft.copied", "NameType": "kape.mft.name_type",
    "EntryNumber": "file.inode", "SequenceNumber": "file.sequence_number",
    "ParentEntryNumber": "file.parent.inode", "ParentSequenceNumber": "file.parent.sequence_number",
    "ParentPath": "file.directory", "Extension": "file.extension", "FileSize": "file.size",
    "ReferenceCount": "file.reference_count", "ReparseTarget": "file.reparse.target",
    "UpdateReasons": "file.update_reasons", "UpdateSequenceNumber": "file.update_sequence_number",
    "UpdateTimestamp": "file.update_timestamp", "LogfileSequenceNumber": "file.logfile.sequence_number",
    "SecurityId": "file.uid", "ObjectIdFileDroid": "file.object_id", "LoggedUtilStream": "file.stream_name",
    "ZoneIdContents": "file.fork_contents", "OffsetToData": "file.offset_to_data", "SourceFile": "file.source_file",
}
NTFS_FLAGS = {
    "readonly": 0x0001, "hidden": 0x0002, "system": 0x0004, "archive": 0x0020,
    "device": 0x0040, "normal": 0x0080, "temporary": 0x0100, "sparsefile": 0x0200,
    "reparsepoint": 0x0400, "compressed": 0x0800, "offline": 0x1000,
    "notcontentindexed": 0x2000, "encrypted": 0x4000, "integritystream": 0x8000,
    "virtual": 0x010000, "noscrubdata": 0x020000, "hasea": 0x040000,
    "directory": 0x10000000, "indexview": 0x20000000,
}
DATE_FIELDS = [
    "file.stdinfo.ctime", "file.stdinfo.mtime", "file.stdinfo.accessed", "file.stdinfo.created",
    "file.filename.ctime", "file.filename.mtime", "file.filename.accessed", "file.filename.created",
]
MAPPINGS = {"@timestamp": {"type": "date"}, "labels.type": {"type": "keyword"}, "tags": {"type": "keyword"},
            "log.file.path": {"type": "keyword"}, "sof-elk.path": {"type": "keyword"}, "file.size": {"type": "long"}}
MAPPINGS.update({field: {"type": "date"} for field in DATE_FIELDS})
MAPPINGS.update({f"file.attributes.{flag}": {"type": "boolean"} for flag in NTFS_FLAGS})


def truthy(value):
    return value is True or (isinstance(value, (int, float)) and value == 1) or str(value).strip().lower() in ("true", "1", "yes")


def make_attributes(value, source_type):
    names = list(NTFS_FLAGS)
    output = {name: False for name in names}
    if source_type == "int":
        try:
            mask = int(value)
        except (TypeError, ValueError):
            mask = 0
        for name, bit in NTFS_FLAGS.items():
            output[name] = bool(mask & bit)
    else:
        text = str(value or "").lower()
        # Match SOF-ELK's supporting ntfs_flags_to_array.rb substring handling.
        for name in names:
            output[name] = name in text
    return output


def transform(raw, source_path, hostname, label_type, ingest_time):
    if not isinstance(raw, dict):
        raise ValueError("MFTECmd JSON records must be objects")
    doc = base_event(raw, source_path, hostname, label_type, ingest_time)
    copy_renames(raw, doc, RENAMES)
    if raw.get("FileName") not in (None, ""):
        set_nested(doc, "file.name", raw["FileName"])
        add_tag(doc, "filesystem_mft")
    elif raw.get("Name") not in (None, ""):
        set_nested(doc, "file.name", raw["Name"])
        add_tag(doc, "filesystem_j")

    # Logstash removes empty directory/extension strings.
    file_obj = doc.get("file", {})
    if file_obj.get("directory") == "":
        file_obj.pop("directory", None)
    if file_obj.get("extension") == "":
        file_obj.pop("extension", None)
    if "size" not in file_obj or file_obj.get("size") == "":
        file_obj["size"] = 0
    else:
        try:
            file_obj["size"] = int(file_obj["size"])
        except (TypeError, ValueError):
            pass

    is_ads = truthy(doc.get("kape", {}).get("mft", {}).get("isads"))
    name = file_obj.get("name")
    if is_ads:
        file_obj.pop("extension", None)
        file_obj.pop("fork_name", None)
        if isinstance(name, str):
            match = re.match(r"^.*\.([^:]*):([^:]*)$", name)
            if match:
                file_obj["extension"] = match.group(1)
                file_obj["fork_name"] = match.group(2)
    elif file_obj.get("extension"):
        ext = str(file_obj["extension"])
        file_obj["extension"] = ext[1:] if ext else ext

    # Logstash converts all eight MACB timestamps to date values in _source.
    for field in DATE_FIELDS:
        normalize_date_field(doc, field)

    # The source filter has two mutually exclusive attribute formats.
    # JSON gives SiFlags as an integer; CSV gives the names joined by | (Hidden|System).
    if "SiFlags" in raw and raw["SiFlags"] is not None:
        si_flags = raw["SiFlags"]
        if isinstance(si_flags, int) or str(si_flags).strip().isdigit():
            doc["file"]["attributes"] = make_attributes(si_flags, "int")
        else:
            doc["file"]["attributes"] = make_attributes(str(si_flags).replace("|", ",").lower(), "str")
    elif "FileAttributes" in raw and raw["FileAttributes"] is not None:
        if raw["FileAttributes"] == "":
            doc["file"]["attributes"] = ""
        else:
            doc["file"]["attributes"] = make_attributes(str(raw["FileAttributes"]).replace("|", ",").lower(), "str")

    # JSON spells the column isDirectory, CSV IsDirectory.
    is_directory = raw.get("isDirectory", raw.get("IsDirectory"))
    if is_directory is not None and is_directory != "":
        is_dir = truthy(is_directory)
        doc["file"]["type"] = "dir" if is_dir else "file"
        if is_dir:
            doc["file"].setdefault("attributes", {})["directory"] = True
    else:
        # The original postprocessor determines the type from @metadata populated from isDirectory.
        doc["file"]["type"] = "file"

    if doc.get("file", {}).get("update_reasons"):
        reasons = doc["file"]["update_reasons"]
        if isinstance(reasons, str):
            doc["file"]["update_reasons"] = [x.lower() for x in reasons.split("|")]

    # SOF-ELK postprocessing constructs/splits file.path after the source renames.
    f = doc.setdefault("file", {})
    if f.get("directory") and f.get("name") and not f.get("path"):
        f["path"] = str(f["directory"]).rstrip("\\/") + "\\" + str(f["name"])
    if f.get("path") and (not f.get("directory") or not f.get("name")):
        path = str(f["path"])
        if "\\" in path:
            directory, _, name_part = path.rpartition("\\")
        elif "/" in path:
            directory, _, name_part = path.rpartition("/")
        else:
            directory, name_part = "", path
        if not f.get("directory") and directory:
            f["directory"] = directory
        if not f.get("name") and name_part:
            f["name"] = name_part

    # @timestamp: stdinfo mtime, else stdinfo created, else USN/update time, else ingest time.
    if get_nested(doc, "file.stdinfo.mtime") not in (None, ""):
        timestamp = get_nested(doc, "file.stdinfo.mtime")
    elif get_nested(doc, "file.stdinfo.created") not in (None, ""):
        timestamp = get_nested(doc, "file.stdinfo.created")
    else:
        timestamp = get_nested(doc, "file.update_timestamp")
    doc["@timestamp"] = parse_timestamp(timestamp) or ingest_time
    return doc


def main():
    parser = argparse.ArgumentParser()
    add_common_arguments(parser, "Load MFTECmd JSON records directly into filesystem-<hostname>.")
    args = parser.parse_args()
    run_import(args, LABEL_TYPE, INDEX_PREFIX, PATTERNS, EXCLUDES, MAPPINGS, transform,
               csv_int_fields={"EntryNumber", "SequenceNumber", "ParentEntryNumber", "ParentSequenceNumber", "FileSize", "ReferenceCount", "UpdateSequenceNumber", "LogfileSequenceNumber", "SecurityId", "OffsetToData", "NameType", "SiFlags"},
               csv_bool_fields={"InUse", "HasAds", "IsAds", "Timestomped", "Copied", "isDirectory", "IsDirectory"})

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Stream LECmd JSON or CSV records into a per-host SOF-ELK-compatible lnkfiles index."""
import argparse
import json
import re
from sof_elk_json_bulk_common import add_common_arguments, base_event, copy_renames, normalize_date_field, run_import

INDEX_PREFIX = "lnkfiles"
LABEL_TYPE = "kape_lnkfiles"
PATTERNS = ("*_LECmd_Output.json", "*_LECmd_Output.json.gz", "*_LECmd_Output.csv")
EXCLUDES = ()
RENAMES = {
    "SourceCreated": "file.created", "SourceModified": "file.mtime", "SourceAccessed": "file.accessed",
    "TargetCreated": "file.target.created", "TargetModified": "file.target.mtime", "TargetAccessed": "file.target.accessed",
    "MachineMACAddress": "file.tracker.mac", "MACVendor": "file.tracker.mac_vendor",
    "TrackerCreatedOn": "file.tracker.creation", "MachineID": "file.tracker.machine_id",
    "FileSize": "file.size", "Arguments": "file.target.path.arguments", "DriveType": "file.target.drivetype",
    "VolumeSerialNumber": "volume.serial_number", "VolumeLabel": "file.target.volume.label",
    "SourceFile": "file.path", "LocalPath": "file.target.local_path", "NetworkPath": "file.target.network_path",
    "CommonPath": "file.target.common_path", "TargetIDAbsolutePath": "file.target.absolute_path",
    "RelativePath": "file.target.relative_path", "WorkingDirectory": "file.target.working_directory",
    "TargetMFTEntryNumber": "file.target.inode_string", "TargetMFTSequenceNumber": "file.target.sequence_number_string",
    "HeaderFlags": "file.header_flags", "FileAttributes": "file.attributes", "ExtraBlocks_Present": "file.extra_blocks",
    "ExtraBlocksPresent": "file.extra_blocks",  # CSV spelling of ExtraBlocks_Present
}
HEADER_FLAGS = [
    "hastargetidlist", "haslinkinfo", "hasname", "hasrelativepath", "hasworkingdir", "hasarguments",
    "hasiconlocation", "isunicode", "forcenolinkinfo", "hasexpstring", "runinseparateprocess", "reserved0",
    "hasdarwinid", "runasuser", "hasexpicon", "nopidlalias", "reserved1", "runwithshimlayer", "forcenolinktrack",
    "enabletargetmetadata", "disablelinkpathtracking", "disableknownfoldertracking", "disableknownfolderalias",
    "allowlinktolink", "unaliasonsave", "preferenvironmentpath", "keeplocalidlistforunctarget",
]
HEADER_BITS = dict(zip(HEADER_FLAGS, [0x0001, 0x0002, 0x0004, 0x0008, 0x0010, 0x0020, 0x0040, 0x0080, 0x0100,
    0x0200, 0x0400, 0x0800, 0x1000, 0x2000, 0x4000, 0x8000, 0x010000, 0x020000, 0x040000, 0x080000,
    0x100000, 0x200000, 0x400000, 0x800000, 0x10000000, 0x20000000, 0x40000000]))
ATTR_FLAGS = [
    "readonly", "hidden", "system", "archive", "device", "normal", "temporary", "sparsefile", "reparsepoint",
    "compressed", "offline", "notcontentindexed", "encrypted", "integritystream", "virtual", "noscrubdata",
    "hasea", "directory", "indexview",
]
DATE_FIELDS = ["file.created", "file.mtime", "file.accessed", "file.target.created", "file.target.mtime", "file.target.accessed"]
MAPPINGS = {"@timestamp": {"type": "date"}, "labels.type": {"type": "keyword"}, "tags": {"type": "keyword"},
            "log.file.path": {"type": "keyword"}, "sof-elk.path": {"type": "keyword"}, "file.size": {"type": "long"},
            "file.target.path": {"type": "text"},
            "file.target.inode": {"type": "long"}, "file.target.sequence_number": {"type": "long"}}
MAPPINGS.update({field: {"type": "date"} for field in DATE_FIELDS})
MAPPINGS.update({f"file.header_flags.{flag}": {"type": "boolean"} for flag in HEADER_FLAGS})
MAPPINGS.update({f"file.attributes.{flag}": {"type": "boolean"} for flag in ATTR_FLAGS})


def flags_object(value, names, bits=None):
    result = {name: False for name in names}
    text = str(value or "").replace(" ", "").lower()
    if bits is not None and isinstance(value, (int, float)):
        mask = int(value)
        return {name: bool(mask & bit) for name, bit in bits.items()}
    for name in names:
        result[name] = name in text
    return result


def transform(raw, source_path, hostname, label_type, ingest_time):
    if not isinstance(raw, dict):
        raise ValueError("LECmd JSON records must be objects")
    doc = base_event(raw, source_path, hostname, label_type, ingest_time)
    copy_renames(raw, doc, RENAMES)
    doc.setdefault("file", {})["extension"] = "lnk"
    f = doc["file"]
    target = f.setdefault("target", {})
    def scalar_path(value):
        if isinstance(value, (dict, list)):
            return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        return value

    if target.get("local_path"):
        target["path"] = scalar_path(target["local_path"])
    elif target.get("absolute_path"):
        target["path"] = scalar_path(target["absolute_path"])
    elif isinstance(target.get("path"), (dict, list)):
        target["path"] = json.dumps(
            target["path"],
            ensure_ascii=False,
            separators=(",", ":"),
        )

    if f.get("extra_blocks") not in (None, ""):
        if isinstance(f["extra_blocks"], str):
            f["extra_blocks"] = f["extra_blocks"].replace(" ", "").replace("Block", "").lower().split(",")
    if f.get("header_flags") not in (None, ""):
        f["header_flags"] = flags_object(f["header_flags"], HEADER_FLAGS, HEADER_BITS if isinstance(f["header_flags"], (int, float)) else None)
    if f.get("attributes") not in (None, ""):
        text = str(f["attributes"]).replace(" ", "").replace("FileAttribute", "").lower()
        f["attributes"] = flags_object(text, ATTR_FLAGS)

    # These three sentinel conditions match the Logstash filters exactly.
    for key in ("created", "mtime", "accessed"):
        if target.get(key) == "":
            target.pop(key, None)
    if target.get("drivetype") == "(None)":
        target.pop("drivetype", None)

    for field in DATE_FIELDS:
        normalize_date_field(doc, field)

    # JSON gives the target MFT entry/sequence as integers, CSV as hex (0x167E4); native Ruby Integer() takes both.
    for source, dest in (("inode_string", "inode"), ("sequence_number_string", "sequence_number")):
        value = target.pop(source, None)
        if value in (None, ""):
            continue
        try:
            target[dest] = value if isinstance(value, int) else int(str(value).strip(), 0)
        except ValueError:
            target[source] = value

    # Postprocessor's path split uses Windows separators; only fill missing values.
    if f.get("path") and (not f.get("directory") or not f.get("name")):
        path = str(f["path"])
        directory, sep, name = path.rpartition("\\")
        if not sep:
            directory, sep, name = path.rpartition("/")
        if not f.get("directory") and directory:
            f["directory"] = directory
        if not f.get("name") and name:
            f["name"] = name
    doc["@timestamp"] = f.get("mtime") or ingest_time
    return doc


def main():
    parser = argparse.ArgumentParser()
    add_common_arguments(parser, "Load LECmd JSON records directly into lnkfiles-<hostname>.")
    args = parser.parse_args()
    run_import(args, LABEL_TYPE, INDEX_PREFIX, PATTERNS, EXCLUDES, MAPPINGS, transform,
               csv_int_fields={"FileSize", "TargetMFTEntryNumber", "TargetMFTSequenceNumber"},
               csv_bool_fields=set())

if __name__ == "__main__":
    main()

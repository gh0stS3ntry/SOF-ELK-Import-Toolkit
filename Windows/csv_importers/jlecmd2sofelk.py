#!/usr/bin/env python3
"""Load JLECmd AutomaticDestinations and CustomDestinations CSVs into jumplist-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-jumplist.json (plus the shared component-toolkit-common.json).
The target's local path is in ECS file.path (lower-cased) with its MAC times in file.created /
file.mtime / file.accessed; everything else is under jumplist.*. event.dataset is
jumplist.automatic or jumplist.custom. user.name is the profile the jump list file came from.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/jumplist.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions are listed in sof_elk_template_importer.CONV_TYPE.
COLUMNS = {
    # The .automaticDestinations-ms / .customDestinations-ms file and its own times
    "sourcefile": [("jumplist.source.path", "keyword")],
    "sourcecreated": [("jumplist.source.created", "date")],
    "sourcemodified": [("jumplist.source.modified", "date")],
    "sourceaccessed": [("jumplist.source.accessed", "date")],
    "appid": [("jumplist.app_id", "keyword")],
    "appiddescription": [("jumplist.app_id_description", "keyword")],
    # DestList entry (AutomaticDestinations only)
    "destlistversion": [("jumplist.dest_list_version", "long")],
    # JLECmd writes entry numbers in hex without a prefix (e.g. "1A"), so they stay keywords
    "lastusedentrynumber": [("jumplist.last_used_entry_number", "keyword")],
    "mru": [("jumplist.mru", "long")],
    "entrynumber": [("jumplist.entry_number", "keyword")],
    "creationtime": [("jumplist.entry_created", "date")],
    "lastmodified": [("jumplist.entry_last_modified", "date")],
    "hostname": [("jumplist.hostname", "keyword")],
    "macaddress": [("jumplist.mac_address", "keyword")],
    "path": [("jumplist.path", "keyword")],
    "interactioncount": [("jumplist.interaction_count", "long")],
    "pinstatus": [("jumplist.pinned", "boolean")],
    "filebirthdroid": [("jumplist.tracker.file_birth_droid", "keyword")],
    "filedroid": [("jumplist.tracker.file_droid", "keyword")],
    "volumebirthdroid": [("jumplist.tracker.volume_birth_droid", "keyword")],
    "volumedroid": [("jumplist.tracker.volume_droid", "keyword")],
    # Category name (CustomDestinations only)
    "entryname": [("jumplist.entry_name", "keyword")],
    # Embedded LNK target
    "targetcreated": [("file.created", "date")],
    "targetmodified": [("file.mtime", "date")],
    "targetaccessed": [("file.accessed", "date")],
    "filesize": [("file.size", "long")],
    "relativepath": [("jumplist.relative_path", "keyword")],
    "workingdirectory": [("jumplist.working_directory", "keyword")],
    "fileattributes": [("jumplist.file_attributes", "keyword")],
    "headerflags": [("jumplist.header_flags", "keyword")],
    "drivetype": [("jumplist.drive_type", "keyword")],
    "volumeserialnumber": [("jumplist.volume_serial_number", "keyword")],
    "volumelabel": [("jumplist.volume_label", "keyword")],
    # Target path as recorded (original case) and the normalized form
    "localpath": [("file.path", "path"), ("jumplist.local_path", "keyword")],
    "commonpath": [("jumplist.common_path", "keyword")],
    "targetidabsolutepath": [("jumplist.target_id_absolute_path", "keyword")],
    "targetmftentrynumber": [("jumplist.target_mft_entry_number", "keyword")],  # hex, e.g. 0x1B871
    "targetmftsequencenumber": [("jumplist.target_mft_sequence_number", "keyword")],
    "machineid": [("jumplist.tracker.machine_id", "keyword")],
    "machinemacaddress": [("jumplist.tracker.machine_mac_address", "keyword")],
    "trackercreatedon": [("jumplist.tracker.created", "date")],
    "extrablockspresent": [("jumplist.extra_blocks_present", "keyword")],
    "arguments": [("jumplist.arguments", "keyword")],
    "notes": [("jumplist.notes", "keyword")],
}

# Same @timestamp choice as the earlier importer: DestList entry time, else the jump list file's
TIME_PREFS = {
    "automatic": ["jumplist.entry_last_modified", "jumplist.source.modified"],
    "custom": ["jumplist.source.modified"],
}

TIME_MEANING = {
    "lastmodified": "DestList entry last modified - when the item was last opened through this app",
    "sourcemodified": "Jump list file last modified - the app's most recent jump list update",
}

# Users\<name>\ in the jump list file's path
USER_PATH_RE = re.compile(r"[\\/]Users[\\/]([^\\/]+)[\\/]", re.I)


def detect_section(path, header):
    """'Automatic' / 'Custom' for JLECmd CSVs (file name first, then columns), otherwise None."""
    h = {c.strip().lower() for c in header}
    name = path.name.lower()
    if "automaticdestinations" in name:
        return "Automatic"
    if "customdestinations" in name:
        return "Custom"
    if "appid" in h and "sourcefile" in h:
        return "Automatic" if {"destlistversion", "entrynumber", "mru"} & h else "Custom"
    return None


def enrich(doc, meta):
    m = USER_PATH_RE.search(engine.get_field(doc, "jumplist.source.path") or "")
    if m:
        doc["user"] = {"name": m.group(1).lower()}


ARTIFACT = engine.Artifact(
    name="jumplist",
    tool="JLECmd",
    columns=COLUMNS,
    detect_section=detect_section,
    dataset_for=lambda section: f"jumplist.{section.lower()}",
    time_prefs=TIME_PREFS,
    time_default=["jumplist.source.modified"],
    time_meaning=TIME_MEANING,
    enrich=enrich,
)

if __name__ == "__main__":
    engine.run(ARTIFACT, "Load JLECmd AutomaticDestinations and CustomDestinations CSVs into a"
                         " host-specific SOF-ELK index with a fixed schema.")

#!/usr/bin/env python3
"""Load SBECmd ShellBags CSVs into shellbag-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-shellbag.json (plus the shared component-toolkit-common.json).
The folder's MAC times from the shell item go to ECS file.created / file.mtime / file.accessed;
everything else is under shellbag.*. event.dataset is always shellbag. SBECmd names its CSVs
<user>_NTUSER.csv / <user>_UsrClass.csv, which gives user.name and shellbag.hive.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/shellbag.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions are listed in sof_elk_template_importer.CONV_TYPE.
COLUMNS = {
    "bagpath": [("shellbag.bag_path", "keyword")],
    "slot": [("shellbag.slot", "long")],
    "nodeslot": [("shellbag.node_slot", "long")],
    "mruposition": [("shellbag.mru_position", "long")],
    "absolutepath": [("shellbag.absolute_path", "keyword")],
    "shelltype": [("shellbag.shell_type", "keyword")],
    "value": [("shellbag.value", "keyword")],
    "childbags": [("shellbag.child_bags", "long")],
    # Folder MAC times stored in the shell item (when the item has them)
    "createdon": [("file.created", "date")],
    "modifiedon": [("file.mtime", "date")],
    "accessedon": [("file.accessed", "date")],
    "lastwritetime": [("shellbag.last_write", "date")],
    "mftentry": [("shellbag.mft_entry", "long")],
    "mftsequencenumber": [("shellbag.mft_sequence_number", "long")],
    "extensionblockcount": [("shellbag.extension_block_count", "long")],
    "firstinteracted": [("shellbag.first_interacted", "date")],
    "lastinteracted": [("shellbag.last_interacted", "date")],
    "hasexplored": [("shellbag.has_explored", "boolean")],
    "miscellaneous": [("shellbag.miscellaneous", "keyword")],
}

# Same @timestamp choice as the earlier importer: last interaction, else the bag key's last write
TIME_DEFAULT = ["shellbag.last_interacted", "shellbag.last_write"]

TIME_MEANING = {
    "lastinteracted": "Last time the user interacted with this folder (from the bag's MRU data)",
    "lastwritetime": "Bag registry key last write time - may reflect a later sibling folder",
}

# <user>_NTUSER.csv / <user>_UsrClass.csv, optionally with a KAPE run-time prefix
HIVE_NAME_RE = re.compile(r"^(?:\d{8,}_)?(.+)_(ntuser|usrclass)$", re.I)


def detect_section(path, header):
    """'ShellBags' for SBECmd CSVs (columns or file name), otherwise None."""
    h = {c.strip().lower() for c in header}
    if "bagpath" in h or {"absolutepath", "shelltype"} <= h or "sbecmd" in path.name.lower():
        return "ShellBags"
    return None


def enrich(doc, meta):
    m = HIVE_NAME_RE.match(meta["path"].stem)
    if m:
        doc["user"] = {"name": m.group(1).lower()}
        doc.setdefault("shellbag", {})["hive"] = "NTUSER" if m.group(2).lower() == "ntuser" else "UsrClass"


ARTIFACT = engine.Artifact(
    name="shellbag",
    tool="SBECmd",
    columns=COLUMNS,
    detect_section=detect_section,
    dataset_for=lambda section: "shellbag",
    time_default=TIME_DEFAULT,
    time_meaning=TIME_MEANING,
    enrich=enrich,
)

if __name__ == "__main__":
    engine.run(ARTIFACT, "Load SBECmd ShellBags CSVs into a host-specific SOF-ELK index with a"
                         " fixed schema.")

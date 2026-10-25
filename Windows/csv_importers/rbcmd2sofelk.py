#!/usr/bin/env python3
"""Load RBCmd (Recycle Bin $I / INFO2) CSVs into recyclebin-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-recyclebin.json (plus the shared component-toolkit-common.json).
The deleted file's original path is in ECS file.path (lower-cased; original case kept in
recyclebin.original_path), DeletedOn feeds @timestamp, and the owner's SID from the
$Recycle.Bin\\<SID> folder is added as user.id.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/recyclebin.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). Conversions are listed in
# sof_elk_template_importer.CONV_TYPE.
COLUMNS = {
    "sourcename": [("recyclebin.source_name", "keyword")],  # $I / INFO2 file on the analysis machine
    "filetype": [("recyclebin.file_type", "keyword")],      # $I or INFO2
    "filename": [("file.path", "path"), ("recyclebin.original_path", "keyword")],
    "filesize": [("file.size", "long")],
    "deletedon": [("recyclebin.deleted_on", "date")],
}

TIME_MEANING = {"deletedon": "Time the file was moved to the Recycle Bin"}

SID_RE = re.compile(r"\$Recycle\.Bin[\\/](S-\d-[\d-]+)", re.I)


def detect_section(path, header):
    """'RBCmd' for RBCmd CSVs (file name or columns), otherwise None."""
    h = {c.strip().lower() for c in header}
    if re.search(r"rbcmd|recyclebin", path.stem, re.I) or {"sourcename", "filename", "deletedon"} <= h:
        return "RBCmd"
    return None


def enrich(doc, meta):
    """user.id: the SID whose $Recycle.Bin folder held the $I file."""
    m = SID_RE.search(engine.get_field(doc, "recyclebin.source_name") or "")
    if m:
        doc["user"] = {"id": m.group(1)}


ARTIFACT = engine.Artifact(
    name="recyclebin",
    tool="RBCmd",
    columns=COLUMNS,
    detect_section=detect_section,
    dataset_for=lambda section: "recyclebin",
    time_default=["recyclebin.deleted_on"],
    time_meaning=TIME_MEANING,
    enrich=enrich,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load RBCmd CSVs into a host-specific SOF-ELK index with a fixed schema.")

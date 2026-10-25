#!/usr/bin/env python3
"""Load AppCompatCacheParser (ShimCache) CSVs into shimcache-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-shimcache.json (plus the shared component-toolkit-common.json).
The entry's path is in ECS file.path (lower-cased) and its $SI last-modified time in file.mtime,
which also feeds @timestamp. That time is file metadata, not proof of execution.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/shimcache.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). A column can feed more than one field.
# Conversions are listed in sof_elk_template_importer.CONV_TYPE.
COLUMNS = {
    "controlset": [("shimcache.control_set", "long")],
    "cacheentryposition": [("shimcache.cache_entry_position", "long")],
    # Path as recorded (original case, may be \??\ or SYSVOL-prefixed) and the normalized form
    "path": [("file.path", "path"), ("shimcache.path", "keyword")],
    "lastmodifiedtimeutc": [("file.mtime", "date")],
    "executed": [("shimcache.executed", "keyword")],  # Yes / No / NA
    "duplicate": [("shimcache.duplicate", "boolean")],
    "sourcefile": [("shimcache.source_hive", "keyword")],  # SYSTEM hive the entry came from
}

TIME_MEANING = {
    "lastmodifiedtimeutc": "File last-modified time ($SI) recorded in ShimCache - NOT an execution time",
}


def detect_section(path, header):
    """'AppCompatCache' for ShimCache CSVs (file name or columns), otherwise None."""
    h = {c.strip().lower() for c in header}
    stem = re.sub(r"^\d{8,}_", "", path.stem)
    if re.search(r"appcompatcache|shimcache", stem, re.I) or {"cacheentryposition", "lastmodifiedtimeutc"} <= h:
        return "AppCompatCache"
    return None


ARTIFACT = engine.Artifact(
    name="shimcache",
    tool="AppCompatCacheParser",
    columns=COLUMNS,
    detect_section=detect_section,
    dataset_for=lambda section: "shimcache",
    time_default=["file.mtime"],
    time_meaning=TIME_MEANING,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load AppCompatCacheParser CSVs into a host-specific SOF-ELK index with a"
                         " fixed schema.")

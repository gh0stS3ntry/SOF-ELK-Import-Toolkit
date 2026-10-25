#!/usr/bin/env python3
"""Load WxTCmd (Windows Timeline, ActivitiesCache.db) CSVs into activitiescache-<hostname>.

Every column is mapped to a fixed field with a fixed type, defined by the explicit index template
in Windows/index_templates/index-activitiescache.json (plus the shared component-toolkit-common.json).
WxTCmd writes one set of CSVs per user (<user>_Activity.csv, <user>_Activity_PackageIDs.csv and,
when present, <user>_ActivityOperations.csv); the user from the file name is added as user.name.

The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/activitiescache.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). Conversions are listed in
# sof_elk_template_importer.CONV_TYPE. Shared by the Activity and ActivityOperations CSVs.
COLUMNS = {
    "id": [("activitiescache.id", "keyword")],
    "activitytypeorg": [("activitiescache.activity_type_org", "long")],
    "activitytype": [("activitiescache.activity_type", "keyword")],  # number or name (ExecuteOpen)
    "executable": [("activitiescache.executable", "keyword")],
    "displaytext": [("activitiescache.display_text", "keyword")],
    "contentinfo": [("activitiescache.content_info", "keyword")],
    "payload": [("activitiescache.payload", "keyword")],
    "clipboardpayload": [("activitiescache.clipboard_payload", "keyword")],
    "starttime": [("activitiescache.start_time", "date")],
    "endtime": [("activitiescache.end_time", "date")],
    "duration": [("activitiescache.duration", "keyword")],  # hh:mm:ss
    "lastmodifiedtime": [("activitiescache.last_modified_time", "date")],
    "lastmodifiedonclient": [("activitiescache.last_modified_on_client", "date")],
    "originallastmodifiedonclient": [("activitiescache.original_last_modified_on_client", "date")],
    "expirationtime": [("activitiescache.expiration_time", "date")],
    "createdincloud": [("activitiescache.created_in_cloud", "date")],
    "islocalonly": [("activitiescache.is_local_only", "boolean")],
    "etag": [("activitiescache.etag", "long")],
    "packageidhash": [("activitiescache.package_id_hash", "keyword")],
    "platformdeviceid": [("activitiescache.platform_device_id", "keyword")],
    "deviceplatform": [("activitiescache.device_platform", "keyword")],
    "timezone": [("activitiescache.time_zone", "keyword")],
    "operationtype": [("activitiescache.operation_type", "keyword")],
}

# Activity_PackageIDs.csv: Id links back to the Activity row
SECTION_COLUMNS = {
    "packageids": {
        "id": [("activitiescache.id", "keyword")],
        "platform": [("activitiescache.platform", "keyword")],
        "name": [("activitiescache.package_name", "keyword")],
        "additionalinformation": [("activitiescache.additional_information", "keyword")],
        "expires": [("activitiescache.expiration_time", "date")],
    },
}

TIME_PREFS = {
    # PackageIDs rows only carry an expiry date, which is not an activity time
    "packageids": [],
}
TIME_DEFAULT = ["activitiescache.start_time", "activitiescache.last_modified_time"]

TIME_MEANING = {
    "starttime": "Activity start time recorded in the Windows Timeline",
    "lastmodifiedtime": "Activity last-modified time recorded in the Windows Timeline",
}

# 20261025081930_tdungan_Activity.csv -> ("tdungan", "Activity")
NAME_RE = re.compile(r"^(?:\d{8,}_)?(.+?)_(Activity(?:Operations)?(?:_PackageIDs)?)$", re.I)


def detect_section(path, header):
    """'Activity', 'ActivityOperations' or 'PackageIDs' for WxTCmd CSVs, otherwise None."""
    h = {c.strip().lower() for c in header}
    stem = path.stem
    if {"id", "platform", "name", "expires"} <= h and re.search(r"packageid", stem, re.I):
        return "PackageIDs"
    if {"id", "activitytype", "executable"} <= h:
        return "ActivityOperations" if "operationtype" in h or re.search(r"operations", stem, re.I) else "Activity"
    return None


def section_kind(section):
    return section.lower()


def dataset_for(section):
    return {"Activity": "activitiescache.activity", "ActivityOperations": "activitiescache.operations",
            "PackageIDs": "activitiescache.package_ids"}.get(section, f"activitiescache.{engine.snake(section)}")


def enrich(doc, meta):
    """user.name from the per-user file name."""
    m = NAME_RE.match(meta["path"].stem)
    if m:
        doc["user"] = {"name": m.group(1)}


ARTIFACT = engine.Artifact(
    name="activitiescache",
    tool="WxTCmd",
    columns=COLUMNS,
    section_columns=SECTION_COLUMNS,
    detect_section=detect_section,
    section_kind=section_kind,
    dataset_for=dataset_for,
    time_prefs=TIME_PREFS,
    time_default=TIME_DEFAULT,
    time_meaning=TIME_MEANING,
    isolated_kinds={"packageids"},
    enrich=enrich,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load WxTCmd CSVs into a host-specific SOF-ELK index with a fixed schema.")

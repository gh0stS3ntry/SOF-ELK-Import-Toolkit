#!/usr/bin/env python3
"""Load RECmd batch and plugin-detail CSVs into registry-<hostname>.

The schema is fixed by the explicit index template in Windows/index_templates/index-registry.json
(plus the shared component-toolkit-common.json):

  * The batch CSV (*_RECmd_Batch_*_Output.csv) has a fixed column set, mapped to ECS registry.*
    (registry.key, registry.value, registry.data.type, registry.data.strings) and registry.<snake>.
  * Plugin-detail CSVs (UserAssist, BamDam, Services, ... one schema per plugin) share
    registry.key (from BatchKeyPath) and registry.batch_value_name. Their other columns go to
    registry.plugin.<snake_case> as keyword, except known timestamp columns, which are dates.
    event.dataset names the plugin, e.g. registry.userassist.

The hive owner is added as user.name when the hive is a user's NTUSER.DAT / UsrClass.dat.
The loading itself (template install, index creation, bulk) is in sof_elk_template_importer.py.
Full field reference: docs/schemas/registry.md.
"""
import re

import sof_elk_template_importer as engine

# Lower-case CSV column -> list of (field, conversion). Conversions are listed in
# sof_elk_template_importer.CONV_TYPE. Used for the batch CSV.
COLUMNS = {
    "hivepath": [("registry.hive_path", "keyword")],
    "hivetype": [("registry.hive_type", "keyword")],
    "description": [("registry.description", "keyword")],
    "category": [("registry.category", "keyword")],
    "keypath": [("registry.key", "keyword")],
    "valuename": [("registry.value", "keyword")],
    "valuetype": [("registry.data.type", "keyword")],
    "valuedata": [("registry.data.strings", "keyword")],
    "valuedata2": [("registry.value_data2", "keyword")],
    "valuedata3": [("registry.value_data3", "keyword")],
    "comment": [("registry.comment", "keyword")],
    "recursive": [("registry.recursive", "boolean")],
    "deleted": [("registry.deleted", "boolean")],
    "lastwritetimestamp": [("registry.last_write", "date")],
    "plugindetailfile": [("registry.plugin_detail_file", "keyword")],
}

# Plugin timestamp columns (UTC) that are typed as dates; all other plugin columns are keywords.
# Columns ending in LOCAL (KnownNetworks) are host local time and stay keywords.
PLUGIN_DATE_COLUMNS = [
    "Timestamp", "ExecutionTime", "LastExecuted", "ExecutedOn", "OpenedOn", "LastOpened",
    "ModifiedTime", "LastDetectionTime", "LastStart", "CreatedOn", "LastLoginTime",
    "LastLogonTime", "LastConnected", "LastModified", "ParametersKeyLastWrite",
    "NameKeyLastWrite", "ExtensionLastOpened", "LastClosed", "FirstInstalled", "Installed",
    "InitialTimestamp", "LastStop", "LastLogoffTime", "LastPasswordChange",
    "LastIncorrectPassword",
]

SECTION_COLUMNS = {
    "plugin": {
        "batchkeypath": [("registry.key", "keyword")],
        "batchvaluename": [("registry.batch_value_name", "keyword")],
        "valuename": [("registry.value", "keyword")],
        "valuedata": [("registry.data.strings", "keyword")],
        "lastwritetimestamp": [("registry.last_write", "date")],
        **{c.lower(): [(f"registry.plugin.{engine.snake(c)}", "date")] for c in PLUGIN_DATE_COLUMNS},
    },
}

TIME_PREFS = {
    "batch": ["registry.last_write"],
    # first plugin time column with a value; key last write first, then activity times
    "plugin": ["registry.last_write"] + [f"registry.plugin.{engine.snake(c)}" for c in PLUGIN_DATE_COLUMNS],
}

TIME_MEANING = {
    "lastwritetimestamp": "Registry key last write time",
    "timestamp": "Registry key last write time (plugin)",
    "executiontime": "BAM/DAM last execution time",
    "lastexecuted": "UserAssist last execution time",
    "executedon": "Last execution time recorded by the plugin",
    "openedon": "MRU entry last opened time",
    "lastopened": "Office MRU last opened time",
    "modifiedtime": "File last-modified time ($SI) recorded in AppCompatCache - NOT an execution time",
    "laststart": "Scheduled task last start time",
    "createdon": "Creation time recorded by the plugin",
}

BATCH_NAME_RE = re.compile(r"recmd_batch", re.I)
# Hive part of a plugin file name: 20261025082257_UserAssist__Users_tdungan_NTUSER.DAT.csv
PLUGIN_NAME_RE = re.compile(r"^(?:\d{8,}_)?([A-Za-z0-9]+)__(.+)$")
# Profile owner from a hive path or plugin file-name hive part
USER_RE = re.compile(r"(?:^|[\\/_])(?:Users|ServiceProfiles)[\\/_](.+?)[\\/_](?:NTUSER\.DAT|AppData)",
                     re.I)


def detect_section(path, header):
    """'Batch' for the RECmd batch CSV, the plugin name for plugin-detail CSVs, otherwise None."""
    h = {c.strip().lower() for c in header}
    if "batchkeypath" in h:
        m = PLUGIN_NAME_RE.match(path.stem)
        return m.group(1) if m else re.sub(r"^\d{8,}_", "", path.stem).split("_")[0] or "Plugin"
    if BATCH_NAME_RE.search(path.stem) or {"hivepath", "keypath", "valuename"} <= h:
        return "Batch"
    return None


def section_kind(section):
    return "batch" if section == "Batch" else "plugin"


def dataset_for(section):
    # plugin name as RECmd spells it, lower-cased: registry.userassist, registry.bamdam
    return "registry.batch" if section == "Batch" else f"registry.{section.lower()}"


def open_field(kind, name):
    """Plugin columns are open-ended by design: registry.plugin.<snake_case>."""
    return f"registry.plugin.{name}" if kind == "plugin" else None


def enrich(doc, meta):
    """kape.source_hive (plugin files) and user.name for per-user hives."""
    hive = engine.get_field(doc, "registry.hive_path")
    if not hive:
        m = PLUGIN_NAME_RE.match(meta["path"].stem)
        if m:
            hive = m.group(2)
            doc["kape"]["source_hive"] = hive
    if hive:
        m = USER_RE.search(hive)
        if m:
            doc["user"] = {"name": m.group(1)}


ARTIFACT = engine.Artifact(
    name="registry",
    tool="RECmd",
    columns=COLUMNS,
    section_columns=SECTION_COLUMNS,
    detect_section=detect_section,
    section_kind=section_kind,
    dataset_for=dataset_for,
    time_prefs=TIME_PREFS,
    time_default=["registry.last_write"],
    time_meaning=TIME_MEANING,
    isolated_kinds={"plugin"},
    open_field=open_field,
    enrich=enrich,
)


if __name__ == "__main__":
    engine.run(ARTIFACT, "Load RECmd batch and plugin CSVs into a host-specific SOF-ELK index with a"
                         " fixed schema.")

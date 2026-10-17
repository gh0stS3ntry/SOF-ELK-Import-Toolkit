#!/usr/bin/env python3
"""Discover forensic exports recursively and run the matching SOF-ELK importer.

Expected layout (as in sof_elk_all_importers.zip):
  SOF-ELK_ImportWrapper.py
  csv_importers/<six CSV importers>
  json_importers/<four JSON importers and sof_elk_json_bulk_common.py>

The wrapper only selects files and orchestrates the existing importers. It does not
parse or index evidence itself.
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable

JSON_IMPORTERS = {
    "MFTECmd": ("mftecmd2sofelk.py", ("*_mftecmd*_output.json", "*_mftecmd*_output.json.gz"), ()),
    "EvtxECmd": ("evtxecmd2sofelk.py", ("*_evtxecmd_output.json", "*_evtxecmd_output.json.gz"), ()),
    "LECmd": ("lecmd2sofelk.py", ("*_lecmd_output.json", "*_lecmd_output.json.gz"), ()),
    "PECmd": ("pecmd2sofelk.py", ("*_pecmd_output.json", "*_pecmd_output.json.gz"), ("*_pecmd_output_timeline.json", "*_pecmd_output_timeline.json.gz")),
}

CSV_IMPORTERS = {
    "RBCmd": ("rbcmd2sofelk.py", "recyclebin"),
    "RecentFileCacheParser": ("recentfilecache2sofelk.py", "recentfilecache"),
    "SQLECmd": ("sqlecmd2sofelk.py", "sqlitedb"),
    "SrumECmd": ("srumecmd2sofelk.py", "srum"),
    "SumECmd": ("sumecmd2sofelk.py", "sum"),
    "WxTCmd": ("wxtcmd2sofelk.py", "activitiescache"),
    "ConvertUsageLogsTo-CSV": ("clrusagelogs2sofelk.py", "clrusagelogs"),
    "NirSoft BrowsingHistoryView": ("nirsoft_bhv2sofelk.py", "browsinghistory"),
    "JLECmd": ("jlecmd2sofelk.py", "jumplist"),
    "SBECmd": ("sbecmd2sofelk.py", "shellbag"),
    "AmcacheParser": ("amcache2sofelk.py", "amcache"),
    "AppCompatCacheParser": ("shimcache2sofelk.py", "shimcache"),
    "RECmd": ("recmd2sofelk.py", "registry"),
}

BHV_HEADERS = {"url", "title", "visit time", "visit count", "visited from", "visit type",
               "visit duration", "web browser", "user profile", "browser profile", "url length",
               "typed count", "history file", "record id"}


def norm_header(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lstrip("\ufeff")).lower()


def read_csv_header(path: Path) -> list[str]:
    """Read a small header only, supporting common encodings and delimiters."""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as stream:
                first = stream.readline()
            if not first:
                return []
            delimiter = max((",", "\t", ";"), key=first.count)
            return next(csv.reader([first], delimiter=delimiter), [])
        except (UnicodeError, OSError, csv.Error):
            continue
    return []


def has_json_pattern(path: Path, patterns: Iterable[str], excludes: Iterable[str] = ()) -> bool:
    name = path.name.lower()
    return any(fnmatch.fnmatchcase(name, p) for p in patterns) and not any(
        fnmatch.fnmatchcase(name, p) for p in excludes
    )


def classify_csv(path: Path, headers: list[str]) -> set[str]:
    """Return importer keys matching this CSV's filename and/or header signature."""
    name = path.name.lower()
    stem = path.stem.lower()
    fields = {norm_header(h) for h in headers}
    # BrowsingHistoryView: the familiar export name or its characteristic columns.
    found: set[str] = set()
    if path.suffix.lower() in {".csv", ".txt", ".tsv"} and (
        "browsinghistory" in name
        or len(fields & BHV_HEADERS) >= 3
        or {"url", "title", "visit_time", "visit_count", "user_profile"}.issubset(fields)
    ):
        found.add("NirSoft BrowsingHistoryView")

    # JLECmd: Automatic/Custom Destinations exports. Avoid classifying arbitrary AppId CSVs.
    if path.suffix.lower() == ".csv" and (
        "automaticdestinations" in name or "customdestinations" in name
    ):
        found.add("JLECmd")

    # SBECmd ShellBags, identified by its characteristic fields or explicit name.
    if path.suffix.lower() == ".csv" and (
        "sbecmd" in name or "bagpath" in fields or ("absolutepath" in fields and "shelltype" in fields)
    ):
        found.add("SBECmd")

    # AmcacheParser sections. These signatures intentionally do not match ShimCache.
    if path.suffix.lower() == ".csv" and (
        "amcache" in name or "filekeylastwritetimestamp" in fields or ("sha1" in fields and "programid" in fields)
    ):
        found.add("AmcacheParser")

    # AppCompatCache/ShimCache.
    if path.suffix.lower() == ".csv" and (
        "appcompatcache" in name or "shimcache" in name
        or {"cacheentryposition", "lastmodifiedtimeutc"}.issubset(fields)
    ):
        found.add("AppCompatCacheParser")

    if path.suffix.lower() == ".csv":
        if "rbcmd" in name or {"deletiontime", "originalfilename", "originalpath"}.intersection(fields) >= {"deletiontime"} :
            found.add("RBCmd")
        if "recentfilecacheparser" in name or {"sourcecreated", "sourcemodified", "filenames"}.issubset(fields):
            found.add("RecentFileCacheParser")
        if "sqlecmd" in name or {"database", "table", "url"}.issubset(fields):
            found.add("SQLECmd")
        if "srumecmd" in name or "srumecmd" in stem or {"timestamp", "appid", "exetimestamp"}.intersection(fields) and ("foregroundbytesread" in fields or "foregroundbyteswritten" in fields):
            found.add("SrumECmd")
        if "sumecmd" in name or {"servername", "username", "applicationname"}.issubset(fields):
            found.add("SumECmd")
        if "wxtcmd" in name or {"activitytype", "starttime", "endtime", "operationtype"}.intersection(fields) >= {"starttime"} and ("activitytype" in fields or "operationtype" in fields):
            found.add("WxTCmd")
        # ConvertUsageLogsTo-CSV.ps1: exact five-column schema. Filename is a strong cue,
        # but the header check prevents arbitrary CSVs from being classified as CLR usage logs.
        clr_headers = {"user", "assemblyname", "firstexecutiontimestamp", "lastexecutiontimestamp", "file"}
        if "convertusagelogs" in name or "usage logs" in name or clr_headers.issubset({re.sub(r"\s+", "", f) for f in fields}):
            found.add("ConvertUsageLogsTo-CSV")

    # RECmd batch and plugin outputs. KAPE plugin filenames commonly have a timestamp
    # prefix and a double underscore before the hive path (e.g. UserAssist__C_Users_...).
    is_recmd_batch = "recmd_batch" in name or ("recmd" in name and "batch" in name)
    is_plugin_export = bool(re.match(r"^\d{8,}_", path.name)) and "__" in path.stem
    if path.suffix.lower() == ".csv" and (is_recmd_batch or is_plugin_export):
        found.add("RECmd")

    return found


def discover(root: Path) -> tuple[dict[str, list[Path]], dict[str, list[Path]]]:
    """Walk the tree once; return selected files for the four JSON and six CSV importers."""
    json_files = {name: [] for name in JSON_IMPORTERS}
    csv_files = {name: [] for name in CSV_IMPORTERS}
    # os.walk avoids materializing a list of every descendant path at once.
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in {".git", "__pycache__"} and not d.startswith("sof-elk-import-"))
        directory = Path(dirpath)
        for filename in filenames:
            path = directory / filename
            lower = filename.lower()
            for importer, (_script, patterns, excludes) in JSON_IMPORTERS.items():
                if has_json_pattern(path, patterns, excludes):
                    json_files[importer].append(path)
            suffix = path.suffix.lower()
            if suffix in {".csv", ".txt", ".tsv"}:
                header = read_csv_header(path)
                for importer in classify_csv(path, header):
                    csv_files[importer].append(path)
    for collection in (json_files, csv_files):
        for key in collection:
            collection[key] = sorted(set(p.resolve() for p in collection[key]), key=lambda p: str(p).lower())
    return json_files, csv_files


def locate_script(wrapper_dir: Path, subdir: str, script: str) -> Path | None:
    candidate = wrapper_dir / subdir / script
    if candidate.is_file():
        return candidate
    # Also support a flat deployment where the scripts are beside the wrapper.
    candidate = wrapper_dir / script
    if candidate.is_file():
        return candidate
    # Last-resort search within the wrapper's directory, excluding temp/cache folders.
    for path in wrapper_dir.rglob(script):
        if path.is_file() and "__pycache__" not in path.parts:
            return path
    return None


class StagingArea:
    """Build per-importer directories containing hardlinks to selected files.

    This keeps source filenames intact for tool detection, avoids excessive argv length,
    and normally adds no evidence-data copy. A copy is a fallback for filesystems that
    do not support hardlinks.
    """
    def __init__(self, root: Path):
        self.root = root
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.base: Path | None = None

    def __enter__(self) -> "StagingArea":
        try:
            self.temp = tempfile.TemporaryDirectory(prefix="sof-elk-import-", dir=str(self.root))
        except OSError:
            self.temp = tempfile.TemporaryDirectory(prefix="sof-elk-import-")
        self.base = Path(self.temp.name)
        return self

    def add(self, importer_key: str, files: list[Path]) -> Path:
        assert self.base is not None
        dest = self.base / re.sub(r"[^A-Za-z0-9_-]+", "_", importer_key)
        dest.mkdir(parents=True, exist_ok=True)
        for i, source in enumerate(files):
            # Preserve the original basename and avoid clashes by placing files in unique subdirs.
            item_dir = dest / f"{i:08d}"
            item_dir.mkdir(exist_ok=True)
            target = item_dir / source.name
            try:
                os.link(source, target)
            except OSError:
                try:
                    target.symlink_to(source)
                except OSError:
                    shutil.copy2(source, target)
        return dest

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.temp is not None:
            self.temp.cleanup()


def add_common_cli_args(command: list[str], args: argparse.Namespace, *, is_json: bool, label: str) -> None:
    command.extend(["--hostname", args.hostname, "--es", args.es])
    if args.user:
        command.extend(["--user", args.user])
    if args.password is not None:
        command.extend(["--password", args.password])
    if args.insecure:
        command.append("--insecure")
    command.extend(["--batch-size", str(args.batch_size)])
    if not is_json:
        if args.case:
            command.extend(["--case", args.case])
        if args.local_tz and label != "NirSoft BrowsingHistoryView":
            command.extend(["--local-tz", args.local_tz])
    if args.dry_run:
        command.append("--dry-run")


def run_one(label: str, script_path: Path, input_dir: Path, args: argparse.Namespace,
            staging: StagingArea, extra: list[str] | None = None, is_json: bool = False) -> int:
    print("\n" + "=" * 76, flush=True)
    print(f"[{label}] Starting import", flush=True)
    print(f"[{label}] Script: {script_path}", flush=True)
    staged_count = sum(1 for p in input_dir.rglob("*") if p.is_file())
    print(f"[{label}] Selected input files: {staged_count}", flush=True)
    command = [sys.executable, str(script_path), str(input_dir)]
    add_common_cli_args(command, args, is_json=is_json, label=label)
    if is_json:
        command.extend(["--workers", str(args.workers), "--sample-docs", str(args.sample_docs)])
    if extra:
        command.extend(extra)
    print(f"[{label}] Command: {command[0]} {Path(command[1]).name} <staged-input> --hostname {args.hostname}", flush=True)
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    try:
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, encoding="utf-8", errors="replace", bufsize=1, env=env)
        assert proc.stdout is not None
        for line in proc.stdout:
            print(line, end="" if line.endswith("\n") else "\n", flush=True)
        result = proc.wait()
    except OSError as exc:
        print(f"[{label}] ERROR: could not start importer: {exc}", flush=True)
        return 127
    if result == 0:
        print(f"[{label}] Completed successfully", flush=True)
    else:
        print(f"[{label}] ERROR: importer exited with status {result}", flush=True)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Recursively discover SOF-ELK forensic exports and invoke the matching CSV/JSON importers.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("directory", help="Root directory to search recursively")
    parser.add_argument("hostname", help="Evidence host name for per-host Elasticsearch indexes")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    parser.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    parser.add_argument("--workers", type=int, default=2, help="Concurrent bulk workers for JSON importers")
    parser.add_argument("--case", help="Optional case/incident ID for importers that support it")
    parser.add_argument("--local-tz", help="UTC offset for *LOCAL timestamp fields in KAPE CSVs, e.g. +08:00")
    parser.add_argument("--bhv-tz", help="Timezone offset for NirSoft BrowsingHistoryView, e.g. +08:00 or UTC")
    parser.add_argument("--date-order", choices=("dmy", "mdy", "ymd"), help="Force BrowsingHistoryView regional date order")
    parser.add_argument("--dry-run", action="store_true", help="Pass dry-run mode to every importer")
    parser.add_argument("--sample-docs", type=int, default=2, help="Sample documents per JSON importer in dry-run mode")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.directory).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        print(f"ERROR: directory does not exist or is not a directory: {root}")
        return 2
    if args.batch_size < 1 or args.workers < 1:
        print("ERROR: --batch-size and --workers must be positive integers.")
        return 2

    wrapper_dir = Path(__file__).resolve().parent
    print(f"SOF-ELK Import Wrapper\nInput directory: {root}\nHostname: {args.hostname}\nElasticsearch: {args.es}", flush=True)
    print("Scanning directory tree and checking file signatures...", flush=True)
    json_files, csv_files = discover(root)

    todo: list[tuple[str, str, str, list[Path], list[str] | None, bool]] = []
    failed: list[tuple[str, int]] = []
    for label, (script, _patterns, _excludes) in JSON_IMPORTERS.items():
        files = json_files[label]
        if files:
            todo.append((label, "json_importers", script, files, None, True))
    for label, (script, _prefix) in CSV_IMPORTERS.items():
        files = csv_files[label]
        if files:
            extra: list[str] = []
            if label == "NirSoft BrowsingHistoryView":
                if not args.bhv_tz:
                    print(f"[{label}] ERROR: found {len(files)} candidate file(s), but --bhv-tz is required; skipping to avoid guessing the source machine's timezone.", flush=True)
                    failed.append((label, 2))
                    continue
                extra.extend(["--tz", args.bhv_tz])
                if args.date_order:
                    extra.extend(["--date-order", args.date_order])
            todo.append((label, "csv_importers", script, files, extra, False))

    print("\nDiscovery summary:", flush=True)
    total_files = 0
    for label, files in [(x, json_files[x]) for x in JSON_IMPORTERS] + [(x, csv_files[x]) for x in CSV_IMPORTERS]:
        print(f"  {label}: {len(files)} file(s)", flush=True)
        total_files += len(files)
    if not todo:
        print("No eligible input files found (or all candidates were skipped).", flush=True)
        if not total_files:
            return 1
        print(f"Importers failed/skipped: {len(failed)}", flush=True)
        for label, code in failed:
            print(f"  ERROR: {label} (exit status {code})", flush=True)
        return 1

    success = 0
    with StagingArea(root) as staging:
        for label, subdir, script, files, extra, is_json in todo:
            script_path = locate_script(wrapper_dir, subdir, script)
            if script_path is None:
                print(f"[{label}] ERROR: could not locate importer {script} under {wrapper_dir}", flush=True)
                failed.append((label, 127))
                continue
            staged_dir = staging.add(label, files)
            code = run_one(label, script_path, staged_dir, args, staging, extra=extra, is_json=is_json)
            if code == 0:
                success += 1
            else:
                failed.append((label, code))

    print("\n" + "=" * 76, flush=True)
    print("Import wrapper summary", flush=True)
    print(f"Importers succeeded: {success}", flush=True)
    print(f"Importers failed/skipped: {len(failed)}", flush=True)
    for label, code in failed:
        print(f"  ERROR: {label} (exit status {code})", flush=True)
    if failed:
        print("One or more importers failed or were skipped. See messages above.", flush=True)
        return 1
    print("All scheduled importers completed successfully.", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

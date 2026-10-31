#!/usr/bin/env python3
"""
SOF-ELK_CreateDataViews.py

Create the Kibana Data Views used with the SOF-ELK direct-import toolkit.

1. SOF-ELK's own out-of-box Data Views (unless --toolkit-only), loaded from the
   unmodified copies in sof-elk-kibana/data_views/: all-records, appleul, aws,
   azure, evtxlogs, filesystem, gcp, gws, httpdlog, icsnpp, kape, kubernetes,
   lnkfiles, logstash, microsoft365, netflow, plaso, prefetch, volatility, zeek.
   A plain Elasticsearch/Kibana (such as the one Install-ForensicELK.ps1 builds)
   has none of these; on a SOF-ELK VM they already exist and are skipped.
   SOF-ELK's Kibana defaults from sof-elk-kibana/sof-elk_config.json are applied
   too (UTC display time zone, date formats, default Data View, Discover sample
   size), because the Data Views' "...SSS Z" date format assumes UTC display.

2. The toolkit's Data Views, which stock SOF-ELK does not have:
  activitiescache-*   WxTCmd
  sum-*               SumECmd
  srum-*              SrumECmd
  sqlitedb-*          SQLECmd
  recentfilecache-*   RecentFileCacheParser
  recyclebin-*        RBCmd
  clrusagelogs-*      ConvertUsageLogsTo-CSV.ps1 CLR Usage Logs
  browsinghistory-*   NirSoft BrowsingHistoryView
  jumplist-*          JLECmd
  shellbag-*          SBECmd
  amcache-*           AmcacheParser
  shimcache-*         AppCompatCacheParser / ShimCache
  registry-*          RECmd
  aws-cloudtrail-*    AWS/cloudtrail2sofelk.py (CloudTrail)
  aws-vpcflow-*       AWS/vpcflow2sofelk.py (VPC Flow Logs)
  aws-waf-*           AWS/waf2sofelk.py (AWS WAF)
  genericcsv-*        Generic-CSV/genericcsv2sofelk.py (any CSV, fields from its header)
  auditd-*            Linux/auditd2sofelk.py (Linux audit log, one document per event)
  bodyfile-*          Linux/bodyfile2sofelk.py (Linux bodyfile file system timeline)
  wtmp-*              Linux/wtmp2sofelk.py (wtmp, btmp and wtmpdb login records)
  packages-*          Linux/packages2sofelk.py (package history and installed packages)
  linuxconfig-*       Linux/linuxconfig2sofelk.py (accounts and persistence snapshot)

filesystem-*, evtxlogs-*, lnkfiles-* and prefetch-* come from SOF-ELK's set in
step 1. The toolkit's AWS indexes get their own, narrower patterns so they do not
mix with SOF-ELK's aws-* (Logstash CloudTrail output, aws-YYYY.MM). ALB/ELB access
logs from AWS/alb2sofelk.py go to httpdlog-<source>, which SOF-ELK's httpdlog-*
Data View covers. The Linux journal and text syslog go to logstash-<hostname>, which
SOF-ELK's logstash-* Data View covers.

Standard library only.
"""

import argparse
import base64
import json
import ssl
import sys
from pathlib import Path
from urllib import error, request

SOFELK_KIBANA_DIR = Path(__file__).resolve().parent / "sof-elk-kibana"
SOFELK_DATA_VIEW_DIR = SOFELK_KIBANA_DIR / "data_views"
SOFELK_SETTINGS_FILE = SOFELK_KIBANA_DIR / "sof-elk_config.json"
# defaultRoute opens a SOF-ELK dashboard, which this script does not install.
SKIPPED_SETTINGS = {"defaultRoute"}

DATA_VIEWS = [
    ("activitiescache", "activitiescache-*"),
    ("sum", "sum-*"),
    ("srum", "srum-*"),
    ("sqlitedb", "sqlitedb-*"),
    ("recentfilecache", "recentfilecache-*"),
    ("recyclebin", "recyclebin-*"),
    ("clrusagelogs", "clrusagelogs-*"),
    ("browsinghistory", "browsinghistory-*"),
    ("jumplist", "jumplist-*"),
    ("shellbag", "shellbag-*"),
    ("amcache", "amcache-*"),
    ("shimcache", "shimcache-*"),
    ("registry", "registry-*"),
    ("aws-cloudtrail", "aws-cloudtrail-*"),
    ("aws-vpcflow", "aws-vpcflow-*"),
    ("aws-waf", "aws-waf-*"),
    ("genericcsv", "genericcsv-*"),
    ("auditd", "auditd-*"),
    ("bodyfile", "bodyfile-*"),
    ("wtmp", "wtmp-*"),
    ("packages", "packages-*"),
    ("linuxconfig", "linuxconfig-*"),
]

DATE_FORMAT = "YYYY-MM-DD HH:mm:ss.SSS\\Z"


def auth_header(user, password):
    if not user:
        return {}
    token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def call(base_url, method, path, body=None, headers=None, ctx=None):
    payload = None if body is None else json.dumps(body, ensure_ascii=False).encode("utf-8")
    merged = {
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
        **(headers or {}),
    }
    req = request.Request(base_url.rstrip("/") + path, data=payload, method=method, headers=merged)
    try:
        with request.urlopen(req, timeout=60, context=ctx) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        raw = exc.read()
        try:
            body_obj = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body_obj = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, body_obj
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def data_view_body(view_id, title):
    return {
        "data_view": {
            "allowHidden": False,
            "allowNoIndex": True,
            "fieldFormats": {
                "@timestamp": {
                    "id": "date",
                    "params": {"pattern": DATE_FORMAT},
                }
            },
            "id": view_id,
            "name": title,
            "timeFieldName": "@timestamp",
            "title": title,
        }
    }


def load_sofelk_data_views():
    """[(id, body)] from sof-elk-kibana/data_views/<id>.json, as SOF-ELK's
    load_all_dashboards.sh names them (the file name is the Data View id)."""
    views = []
    for path in sorted(SOFELK_DATA_VIEW_DIR.glob("*.json")):
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
            view_id = body["data_view"]["id"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise SystemExit(f"Cannot read SOF-ELK Data View {path}: {exc}")
        if view_id != path.stem:
            raise SystemExit(f"{path}: Data View id {view_id!r} does not match the file name")
        views.append((view_id, body))
    if not views:
        raise SystemExit(f"No SOF-ELK Data Views found in {SOFELK_DATA_VIEW_DIR}")
    return views


def load_sofelk_settings():
    try:
        attributes = json.loads(SOFELK_SETTINGS_FILE.read_text(encoding="utf-8"))["attributes"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise SystemExit(f"Cannot read SOF-ELK Kibana settings {SOFELK_SETTINGS_FILE}: {exc}")
    return {k: v for k, v in attributes.items() if k not in SKIPPED_SETTINGS}


def ensure_data_view(args, view_id, body, headers, ctx):
    """Create one Data View. Returns 'created', 'replaced', 'skipped' or 'failed'."""
    title = body["data_view"]["title"]
    print(f"\n[{view_id}] Checking existing Data View...")
    try:
        get_status, get_body = call(
            args.kibana,
            "GET",
            f"/api/data_views/data_view/{view_id}",
            headers=headers,
            ctx=ctx,
        )
    except RuntimeError as exc:
        print(f"[{view_id}] ERROR: {exc}", file=sys.stdout)
        return "failed"

    outcome = "created"
    if get_status == 200 and not args.overwrite:
        existing = get_body.get("data_view", {})
        print(
            f"[{view_id}] Already exists (title={existing.get('title', '?')}); skipping."
        )
        return "skipped"

    if get_status == 200 and args.overwrite:
        print(f"[{view_id}] Exists; deleting before recreation...")
        try:
            del_status, del_body = call(
                args.kibana,
                "DELETE",
                f"/api/data_views/data_view/{view_id}",
                headers=headers,
                ctx=ctx,
            )
        except RuntimeError as exc:
            print(f"[{view_id}] ERROR deleting: {exc}", file=sys.stdout)
            return "failed"
        if del_status >= 300:
            print(
                f"[{view_id}] ERROR deleting: HTTP {del_status}: "
                f"{json.dumps(del_body, ensure_ascii=False)[:500]}",
                file=sys.stdout,
            )
            return "failed"
        outcome = "replaced"
    elif get_status not in (404,):
        print(
            f"[{view_id}] ERROR checking: HTTP {get_status}: "
            f"{json.dumps(get_body, ensure_ascii=False)[:500]}",
            file=sys.stdout,
        )
        return "failed"

    print(f"[{view_id}] Creating Data View '{title}'...")
    try:
        post_status, post_body = call(
            args.kibana,
            "POST",
            "/api/data_views/data_view",
            body=body,
            headers=headers,
            ctx=ctx,
        )
    except RuntimeError as exc:
        print(f"[{view_id}] ERROR creating: {exc}", file=sys.stdout)
        return "failed"

    if post_status >= 300:
        print(
            f"[{view_id}] ERROR creating: HTTP {post_status}: "
            f"{json.dumps(post_body, ensure_ascii=False)[:500]}",
            file=sys.stdout,
        )
        return "failed"

    print(f"[{view_id}] Created successfully.")
    return outcome


def post_settings(args, changes, headers, ctx):
    """POST /api/kibana/settings. Returns None on success, else an error string.
    It is an internal Kibana API: Kibana 9 (server.restrictInternalApis) answers
    "exists but is not available with the current configuration" unless the
    request carries x-elastic-internal-origin, as Kibana's own UI does."""
    try:
        status, body = call(
            args.kibana,
            "POST",
            "/api/kibana/settings",
            body={"changes": changes},
            headers={**headers, "x-elastic-internal-origin": "Kibana"},
            ctx=ctx,
        )
    except RuntimeError as exc:
        return str(exc)
    if status >= 300:
        return f"HTTP {status}: {json.dumps(body, ensure_ascii=False)[:500]}"
    return None


def apply_settings(args, settings, headers, ctx):
    """Apply SOF-ELK's Kibana advanced settings. Returns True on success.
    Kibana validates the whole request, so if one setting is refused (for
    example a plugin that is not present), retry one by one so the rest apply."""
    print("\n[settings] Applying SOF-ELK Kibana defaults: " + ", ".join(sorted(settings)))
    err = post_settings(args, settings, headers, ctx)
    if err is None:
        print("[settings] Applied.")
        return True
    print(f"[settings] Batch refused ({err}); retrying one setting at a time...")
    ok = True
    for key in sorted(settings):
        err = post_settings(args, {key: settings[key]}, headers, ctx)
        if err is None:
            print(f"[settings] {key}: applied")
        else:
            print(f"[settings] {key}: ERROR {err}", file=sys.stdout)
            ok = False
    return ok


def main():
    parser = argparse.ArgumentParser(
        description="Create SOF-ELK's out-of-box Kibana Data Views and the toolkit's own Data Views."
    )
    parser.add_argument(
        "--kibana",
        default="http://localhost:5601",
        help="Kibana base URL (default: http://localhost:5601)",
    )
    parser.add_argument("--user", help="Kibana username, if authentication is enabled")
    parser.add_argument("--password", help="Kibana password")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Delete and recreate the managed Data Views if they already exist",
    )
    parser.add_argument(
        "--toolkit-only",
        action="store_true",
        help="Only the toolkit's Data Views: skip SOF-ELK's out-of-box Data Views and Kibana defaults",
    )
    parser.add_argument(
        "--skip-kibana-settings",
        action="store_true",
        help="Do not apply SOF-ELK's Kibana advanced settings (time zone, date formats, default Data View)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the Data Views that would be created without changing Kibana",
    )
    args = parser.parse_args()

    ctx = ssl._create_unverified_context() if args.insecure else None
    headers = auth_header(args.user, args.password)

    views = []
    settings = {}
    if not args.toolkit_only:
        views.extend(("SOF-ELK", view_id, body) for view_id, body in load_sofelk_data_views())
        if not args.skip_kibana_settings:
            settings = load_sofelk_settings()
    views.extend(("toolkit", view_id, data_view_body(view_id, title)) for view_id, title in DATA_VIEWS)

    print("SOF-ELK Kibana Data View Creator")
    print(f"Kibana: {args.kibana.rstrip('/')}")
    print(f"Data Views to manage ({len(views)}):")
    for source, view_id, body in views:
        title = body["data_view"]["title"]
        if len(title) > 60:
            title = title[:57] + "..."
        print(f"  {source:<8} {view_id:<18} -> {title}")
    if settings:
        print("Kibana settings to apply: " + ", ".join(sorted(settings)))

    if args.dry_run:
        print("\nDry run only - nothing sent to Kibana.")
        return 0

    try:
        status, _ = call(args.kibana, "GET", "/api/data_views", headers=headers, ctx=ctx)
    except RuntimeError as exc:
        print(f"ERROR: cannot reach Kibana: {exc}", file=sys.stdout)
        return 1

    if status >= 300:
        print(f"ERROR: Kibana returned HTTP {status} while checking Data Views.", file=sys.stdout)
        return 1

    counts = {"created": 0, "skipped": 0, "replaced": 0, "failed": 0}
    for _source, view_id, body in views:
        counts[ensure_data_view(args, view_id, body, headers, ctx)] += 1

    settings_failed = bool(settings) and not apply_settings(args, settings, headers, ctx)

    print("\nSummary")
    print(f"  Created:    {counts['created']}")
    print(f"  Skipped:    {counts['skipped']}")
    print(f"  Replaced:   {counts['replaced']}")
    print(f"  Failed:     {counts['failed']}")
    if settings:
        print(f"  Settings:   {'FAILED' if settings_failed else 'applied'}")

    if counts["failed"] or settings_failed:
        print("One or more Data Views or settings could not be applied.")
        return 1

    print("All requested Data Views are available in Kibana.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

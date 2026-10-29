#!/usr/bin/env python3
"""
SOF-ELK_CreateDataViews.py

Create Kibana Data Views that are not included out-of-box in SOF-ELK for the
additional direct-import forensic data sources used by the SOF-ELK importers.

Creates:
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

The existing SOF-ELK Data Views for filesystem-*, evtxlogs-*, lnkfiles-* and
prefetch-* are deliberately not recreated because they already exist in the
stock SOF-ELK distribution. SOF-ELK's own aws-* Data View (for its Logstash
CloudTrail output, aws-YYYY.MM) is also left alone; the toolkit's AWS indexes get
their own, narrower patterns so the two mappings do not mix. ALB/ELB access logs
from AWS/alb2sofelk.py go to httpdlog-<source>, which SOF-ELK's stock httpdlog-*
Data View already covers.

Standard library only.
"""

import argparse
import base64
import json
import ssl
import sys
from urllib import error, request

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


def main():
    parser = argparse.ArgumentParser(
        description="Create the non-stock SOF-ELK Kibana Data Views used by the direct CSV importers."
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
        help="Delete and recreate the seventeen Data Views if they already exist",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show the Data Views that would be created without changing Kibana",
    )
    args = parser.parse_args()

    ctx = ssl._create_unverified_context() if args.insecure else None
    headers = auth_header(args.user, args.password)

    print("SOF-ELK Kibana Data View Creator")
    print(f"Kibana: {args.kibana.rstrip('/')}")
    print("Data Views to manage:")
    for view_id, title in DATA_VIEWS:
        print(f"  {view_id:<18} -> {title}")

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

    failures = 0
    created = 0
    skipped = 0
    replaced = 0

    for view_id, title in DATA_VIEWS:
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
            failures += 1
            continue

        if get_status == 200 and not args.overwrite:
            existing = get_body.get("data_view", {})
            print(
                f"[{view_id}] Already exists (title={existing.get('title', '?')}); skipping."
            )
            skipped += 1
            continue

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
                failures += 1
                continue
            if del_status >= 300:
                print(
                    f"[{view_id}] ERROR deleting: HTTP {del_status}: "
                    f"{json.dumps(del_body, ensure_ascii=False)[:500]}",
                    file=sys.stdout,
                )
                failures += 1
                continue
            replaced += 1
        elif get_status not in (404,):
            print(
                f"[{view_id}] ERROR checking: HTTP {get_status}: "
                f"{json.dumps(get_body, ensure_ascii=False)[:500]}",
                file=sys.stdout,
            )
            failures += 1
            continue

        body = data_view_body(view_id, title)
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
            failures += 1
            continue

        if post_status >= 300:
            print(
                f"[{view_id}] ERROR creating: HTTP {post_status}: "
                f"{json.dumps(post_body, ensure_ascii=False)[:500]}",
                file=sys.stdout,
            )
            failures += 1
            continue

        print(f"[{view_id}] Created successfully.")
        created += 1

    print("\nSummary")
    print(f"  Created:    {created}")
    print(f"  Skipped:    {skipped}")
    print(f"  Replaced:   {replaced}")
    print(f"  Failed:     {failures}")

    if failures:
        print("One or more Data Views could not be created.")
        return 1

    print("All requested Data Views are available in Kibana.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

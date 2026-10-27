#!/usr/bin/env python3
"""Load AWS WAF (v2) web ACL logs into SOF-ELK as aws-waf-<source>.

SOF-ELK has no WAF parser, so this importer defines the schema (index-aws-waf.json): ECS
fields where they exist and aws.waf.* for the rest, in the same style as the other AWS
indexes.

  timestamp (epoch ms)            -> @timestamp
  action                          -> aws.waf.action (ALLOW, BLOCK, COUNT, CAPTCHA, CHALLENGE), event.action
  webaclId                        -> aws.waf.web_acl_id, aws.waf.web_acl_name, cloud.region/account.id
  terminatingRuleId / Type        -> aws.waf.terminating_rule_id / _type
  terminatingRuleMatchDetails     -> aws.waf.terminating_rule_match.condition_type/location/matched_data
  ruleGroupList, nonTerminatingMatchingRules, rateBasedRuleList
                                  -> aws.waf.matched_rule_ids (every rule that matched, any action),
                                     aws.waf.rule_group_ids, aws.waf.non_terminating_rule_ids,
                                     aws.waf.rate_based_rule_names
  labels                          -> aws.waf.labels
  httpSourceName / httpSourceId   -> aws.waf.http_source_name / _id (ALB, CF, APIGW, APPSYNC, ...)
  httpRequest.clientIp / country  -> source.ip / source.geo.country_iso_code
  httpRequest.httpMethod / uri / args / httpVersion / requestId / scheme / host / fragment
                                  -> http.request.method, url.path, url.query, http.version,
                                     http.request.id, url.scheme, url.domain, url.fragment, url.original
  httpRequest.headers             -> aws.waf.request.headers (JSON text), aws.waf.request.header_names;
                                     Host -> url.domain, User-Agent -> user_agent.original,
                                     Referer -> http.request.referrer, X-Forwarded-For -> xff.ip
  ja3Fingerprint / ja4Fingerprint -> tls.client.ja3 / tls.client.ja4
The nested objects are also kept whole as JSON text under aws.waf.flattened.*.

Inputs (plain or .gz, any file name): WAF logs as delivered to S3 or Kinesis Data Firehose
(one JSON object per line, or objects concatenated with no separator), CloudWatch Logs exports
(optionally timestamp-prefixed lines), and `aws logs filter-log-events` /
subscription JSON ({"events": [...]} / {"logEvents": [...]}).

CSV (comma, tab, semicolon or pipe separated) is read too, for logs that were already converted:
  * Athena query results over the waf_logs table (lower-case columns; httprequest, labels,
    rulegrouplist, ... as struct text "{clientip=..., headers=[{name=Host, value=...}]}" or JSON);
  * flattened exports with dotted columns (httpRequest.clientIp, httpRequest.headers.0.name as
    written by CloudWatch Logs Insights, ...);
  * a column holding the whole record as JSON ("@message", "_raw", ...).
timestamp may be epoch milliseconds, epoch seconds or ISO / spreadsheet date text in CSV.

Example:
  python3 AWS/waf2sofelk.py /cases/IR-42/waflogs --source 123456789012 --dry-run
"""
import json
import re
import sys

from sof_elk_aws_common import (AwsLog, any_time, canon, compact_json, csv_records, dig,
                                looks_like_csv_header, run, set_field, snake, to_int, valid_ip)

WEBACL_RE = re.compile(r"^arn:aws[a-z-]*:waf(?:v2)?:([a-z0-9-]*):(\d{12}):(?:[a-z]+/)?webacl/([^/]+)/")
TS_PREFIX_RE = re.compile(r"^\s*\d{4}-\d{2}-\d{2}T[\d:.]+Z?\s+(?=\{)")
KNOWN = {"timestamp", "formatVersion", "webaclId", "terminatingRuleId", "terminatingRuleType",
         "action", "terminatingRuleMatchDetails", "httpSourceName", "httpSourceId",
         "ruleGroupList", "rateBasedRuleList", "nonTerminatingMatchingRules",
         "requestHeadersInserted", "responseCodeSent", "httpRequest", "labels",
         "captchaResponse", "challengeResponse", "ja3Fingerprint", "ja4Fingerprint",
         "requestBodySize", "requestBodySizeInspectedByWAF", "oversizeFields"}

# Native spelling of every key, so CSV columns in any case map back to the record structure.
NATIVE_KEYS = sorted(KNOWN) + [
    "clientIp", "country", "headers", "uri", "args", "httpVersion", "httpMethod", "requestId",
    "fragment", "scheme", "host", "name", "value", "ruleId", "ruleGroupId", "terminatingRule",
    "excludedRules", "exclusionType", "conditionType", "location", "matchedData",
    "matchedFieldName", "sensitivityLevel", "ruleMatchDetails", "rateBasedRuleId",
    "rateBasedRuleName", "limitKey", "maxRateAllowed", "limitValue", "customValues",
    "responseCode", "solveTimestamp", "failureReason", "overriddenAction", "evaluationWindowSec",
]
CSV_NAMES = {canon(k): k for k in NATIVE_KEYS}


def text(value):
    if isinstance(value, (str, int, float)) and not isinstance(value, bool):
        return str(value)
    return None


def uniq(values):
    out = []
    for v in values:
        if v and v not in out:
            out.append(v)
    return out


def match_details(doc, details):
    if not isinstance(details, list):
        return
    ctypes, locations, data = [], [], []
    for d in details:
        if not isinstance(d, dict):
            continue
        ctypes.append(text(d.get("conditionType")))
        locations.append(text(d.get("location")))
        md = d.get("matchedData")
        if isinstance(md, list):
            data.append(" ".join(str(x) for x in md))
        elif md:
            data.append(str(md))
    set_field(doc, "aws.waf.terminating_rule_match.condition_type", uniq(ctypes))
    set_field(doc, "aws.waf.terminating_rule_match.location", uniq(locations))
    set_field(doc, "aws.waf.terminating_rule_match.matched_data", uniq(data))


def matched_rules(doc, rec):
    """Every rule that matched the request, whatever its action, plus the groups it came from."""
    matched, groups, non_terminating = [], [], []
    if rec.get("terminatingRuleId") and rec.get("terminatingRuleId") != "Default_Action":
        matched.append(rec["terminatingRuleId"])
    for rule in rec.get("nonTerminatingMatchingRules") or []:
        if isinstance(rule, dict) and rule.get("ruleId"):
            matched.append(rule["ruleId"])
            non_terminating.append(rule["ruleId"])
    for group in rec.get("ruleGroupList") or []:
        if not isinstance(group, dict):
            continue
        if group.get("ruleGroupId"):
            groups.append(group["ruleGroupId"])
        term = group.get("terminatingRule")
        if isinstance(term, dict) and term.get("ruleId"):
            matched.append(term["ruleId"])
        for rule in group.get("nonTerminatingMatchingRules") or []:
            if isinstance(rule, dict) and rule.get("ruleId"):
                matched.append(rule["ruleId"])
                non_terminating.append(rule["ruleId"])
    rate = [r.get("rateBasedRuleName") or r.get("rateBasedRuleId")
            for r in rec.get("rateBasedRuleList") or [] if isinstance(r, dict)]
    set_field(doc, "aws.waf.matched_rule_ids", uniq(matched))
    set_field(doc, "aws.waf.rule_group_ids", uniq(groups))
    set_field(doc, "aws.waf.non_terminating_rule_ids", uniq(non_terminating))
    set_field(doc, "aws.waf.rate_based_rule_names", uniq(rate))


def request(doc, req, malformed):
    if not isinstance(req, dict):
        return
    ip = valid_ip(text(req.get("clientIp")))
    set_field(doc, "source.ip", ip)
    if req.get("clientIp") and not ip:
        malformed.append(f"clientIp={req.get('clientIp')}")
    country = text(req.get("country"))
    if country and country != "-":
        set_field(doc, "source.geo.country_iso_code", country)
    set_field(doc, "http.request.method", text(req.get("httpMethod")))
    set_field(doc, "http.request.id", text(req.get("requestId")))
    version = text(req.get("httpVersion"))
    set_field(doc, "http.version", version.split("/", 1)[-1] if version else None)
    path = text(req.get("uri"))
    query = text(req.get("args"))
    set_field(doc, "url.path", path)
    set_field(doc, "url.query", query)
    set_field(doc, "url.fragment", text(req.get("fragment")))
    set_field(doc, "url.scheme", (text(req.get("scheme")) or "").lower() or None)
    last = (path or "").rsplit("/", 1)[-1]
    if "." in last:
        set_field(doc, "url.extension", last.rsplit(".", 1)[1].lower()[:32] or None)

    headers = req.get("headers") if isinstance(req.get("headers"), list) else []
    by_name = {}
    for h in headers:
        if isinstance(h, dict) and h.get("name") is not None:
            by_name.setdefault(str(h["name"]).lower(), []).append(text(h.get("value")) or "")
    set_field(doc, "aws.waf.request.headers", compact_json(headers))
    set_field(doc, "aws.waf.request.header_names", sorted(by_name))
    host = text(req.get("host")) or (by_name.get("host") or [None])[0]
    set_field(doc, "url.domain", host.split(":", 1)[0].lower() if host else None)
    set_field(doc, "user_agent.original", (by_name.get("user-agent") or [None])[0])
    set_field(doc, "http.request.referrer", (by_name.get("referer") or [None])[0])
    xff = []
    for value in by_name.get("x-forwarded-for", []):
        xff += [ip for ip in (valid_ip(p.strip()) for p in value.split(",")) if ip]
    set_field(doc, "xff.ip", uniq(xff))
    if host and path is not None:
        scheme = dig(doc, "url", "scheme") or "https"
        original = f"{scheme}://{host}{path}" + (f"?{query}" if query else "")
        set_field(doc, "url.original", original)


def build(rec):
    doc, malformed = {}, []
    ts = any_time(rec.get("timestamp"), "ms")
    if ts:
        doc["@timestamp"] = ts
    elif rec.get("timestamp") is not None:
        malformed.append(f"timestamp={rec.get('timestamp')}")
    w = "aws.waf."
    set_field(doc, w + "format_version", to_int(rec.get("formatVersion")))
    acl = text(rec.get("webaclId"))
    set_field(doc, w + "web_acl_id", acl)
    m = WEBACL_RE.match(acl or "")
    if m:
        set_field(doc, "cloud.region", m.group(1) or None)  # empty for CloudFront (global)
        set_field(doc, "cloud.account.id", m.group(2))
        set_field(doc, w + "web_acl_name", m.group(3))
    action = text(rec.get("action"))
    set_field(doc, w + "action", action)
    set_field(doc, w + "terminating_rule_id", text(rec.get("terminatingRuleId")))
    set_field(doc, w + "terminating_rule_type", text(rec.get("terminatingRuleType")))
    set_field(doc, w + "http_source_name", text(rec.get("httpSourceName")))
    set_field(doc, w + "http_source_id", text(rec.get("httpSourceId")))
    set_field(doc, w + "response_code_sent", to_int(rec.get("responseCodeSent")))
    set_field(doc, w + "request_body_size", to_int(rec.get("requestBodySize")))
    set_field(doc, w + "request_body_size_inspected", to_int(rec.get("requestBodySizeInspectedByWAF")))
    oversize = rec.get("oversizeFields")
    set_field(doc, w + "oversize_fields", [str(x) for x in oversize] if isinstance(oversize, list) else text(oversize))
    labels = [l.get("name") for l in rec.get("labels") or [] if isinstance(l, dict) and l.get("name")]
    set_field(doc, w + "labels", uniq(labels))
    set_field(doc, w + "captcha_response_code", to_int(dig(rec, "captchaResponse", "responseCode")))
    set_field(doc, w + "challenge_response_code", to_int(dig(rec, "challengeResponse", "responseCode")))
    set_field(doc, "tls.client.ja3", text(rec.get("ja3Fingerprint")))
    set_field(doc, "tls.client.ja4", text(rec.get("ja4Fingerprint")))
    match_details(doc, rec.get("terminatingRuleMatchDetails"))
    matched_rules(doc, rec)
    request(doc, rec.get("httpRequest"), malformed)
    for src, dst in (("terminatingRuleMatchDetails", "terminating_rule_match_details"),
                     ("ruleGroupList", "rule_group_list"), ("rateBasedRuleList", "rate_based_rule_list"),
                     ("nonTerminatingMatchingRules", "non_terminating_matching_rules"),
                     ("captchaResponse", "captcha_response"), ("challengeResponse", "challenge_response"),
                     ("requestHeadersInserted", "request_headers_inserted")):
        set_field(doc, w + "flattened." + dst, compact_json(rec.get(src)))
    doc["event"] = {"dataset": "aws.waf", "kind": "event", "category": "web"}
    set_field(doc, "event.action", action.lower() if action else None)
    for key, value in rec.items():
        if key not in KNOWN and value not in (None, "", {}, []):
            set_field(doc, w + "unmapped." + snake(key),
                      compact_json(value) if isinstance(value, (dict, list)) else text(value))
    if malformed:
        set_field(doc, w + "malformed", malformed)
    return doc


def is_record(obj):
    return isinstance(obj, dict) and "webaclId" in obj and "httpRequest" in obj


def records(obj):
    if isinstance(obj, list):
        for item in obj:
            yield from records(item)
    elif isinstance(obj, dict):
        events = obj.get("events") or obj.get("logEvents")
        if isinstance(events, list):
            for ev in events:
                msg = ev.get("message") if isinstance(ev, dict) else None
                try:
                    yield from records(json.loads(msg)) if isinstance(msg, str) else [None]
                except ValueError:
                    yield None
        elif is_record(obj):
            yield obj
        else:
            yield None
    else:
        yield None


def record_key(rec):
    if dig(rec, "httpRequest", "requestId"):
        return json.dumps([rec.get("webaclId"), dig(rec, "httpRequest", "requestId"), rec.get("timestamp")])
    return compact_json(rec)


def is_csv_header(line):
    return looks_like_csv_header(line, [("webaclid", "message", "raw", "event", "json"), ("httprequest", "clientip",
                                                                                          "message", "raw", "event", "json")])


def parse_csv(head, fh):
    for kind, value in csv_records(fh, CSV_NAMES, head=head):
        if kind == "json":
            yield from parse(_One(value), None)
            continue
        if isinstance(value.get("timestamp"), str) and value["timestamp"].isdigit():
            value["timestamp"] = int(value["timestamp"])
        if is_record(value):
            yield record_key(value), build(value)
        else:
            yield None, "CSV row without webaclId and httpRequest columns"


class _One:
    """A string as a file for parse()."""
    def __init__(self, text):
        self.text = text

    def read(self, _size=-1):
        text, self.text = self.text, ""
        return text


def parse(fh, ctx):
    """JSON objects one per line, concatenated, or wrapped in CloudWatch Logs output; or CSV."""
    decoder = json.JSONDecoder()
    buffer = ""
    first = True
    while True:
        chunk = fh.read(1 << 20)
        if first:
            first = False
            line = chunk.lstrip("\ufeff").split("\n", 1)[0].rstrip("\r")
            if is_csv_header(line):
                yield from parse_csv(chunk.lstrip("\ufeff"), fh)
                return
        buffer += chunk
        pos = 0
        while True:
            while pos < len(buffer) and buffer[pos].isspace():
                pos += 1
            if pos >= len(buffer):
                break
            m = TS_PREFIX_RE.match(buffer, pos)
            if m:
                pos = m.end()
            try:
                obj, end = decoder.raw_decode(buffer, pos)
            except ValueError:
                if not chunk:  # end of file: the rest is not JSON
                    nl = buffer.find("\n", pos)
                    yield None, "not valid JSON"
                    if nl < 0:
                        pos = len(buffer)
                        break
                    pos = nl + 1
                    continue
                if "\n" in buffer[pos:] and len(buffer) - pos > (1 << 24):
                    nl = buffer.find("\n", pos)  # bad line in the middle of a big buffer
                    yield None, "not valid JSON"
                    pos = nl + 1
                    continue
                break  # need more data
            pos = end
            for rec in records(obj):
                if rec is None:
                    yield None, "JSON value is not a WAF log record"
                else:
                    yield record_key(rec), build(rec)
        buffer = buffer[pos:]
        if not chunk:
            break


def detect(path, head):
    h = head[:65536]
    if '"webaclId"' in h and '"httpRequest"' in h:
        return True
    first = h.lstrip("\ufeff").split("\n", 1)[0].rstrip("\r")
    if not is_csv_header(first):
        return False
    lower = first.lower()
    return "webaclid" in lower or ("webaclId" in h and "httpRequest" in h)


LOG = AwsLog(
    prefix="aws-waf", namespace="aws.waf", title="AWS WAF", dataset="aws.waf",
    detect=detect, parse=parse,
    describe=[
        "S3 / Kinesis Data Firehose delivery: JSON objects, one per line or concatenated (.gz fine)",
        "CloudWatch Logs exports (timestamp-prefixed lines allowed)",
        "`aws logs filter-log-events` / subscription JSON ({\"events\"|\"logEvents\": [...]})",
        "CSV conversions: Athena waf_logs results, flattened (httpRequest.clientIp) or raw-JSON column",
    ])

if __name__ == "__main__":
    sys.exit(run(LOG, "Load AWS WAF web ACL logs into SOF-ELK (index aws-waf-<source>)"))

#!/usr/bin/env python3
"""Parser tests for the AWS importers (standard library only, no Elasticsearch needed).

    python3 AWS/tests/test_aws_importers.py -v

Every fixture is parsed as plain text and again gzip-compressed, and every document is checked
against its index template. fixtures/<log>/ holds the native AWS formats, fixtures/<log>/csv/
the same logs already converted to CSV (Athena results, Logs Insights and spreadsheet exports): a field the template does not map would be silently dropped by
Elasticsearch (the indexes use dynamic: false).
"""
import gzip
import json
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import alb2sofelk  # noqa: E402
import cloudfrontaccess2sofelk  # noqa: E402
import cloudtrail2sofelk  # noqa: E402
import sof_elk_aws_common as common  # noqa: E402
import vpcflow2sofelk  # noqa: E402
import waf2sofelk  # noqa: E402
import eksaudit2sofelk  # noqa: E402
import route53resolver2sofelk  # noqa: E402
import securityhub2sofelk  # noqa: E402
import sof_elk_ocsf as ocsf  # noqa: E402

FIXTURES = HERE / "fixtures"


def parse_all(module, folder, **argv):
    """[(file, key, doc_or_reason)] for every fixture the importer claims, plain and gzip."""
    log = module.LOG
    args = types.SimpleNamespace(case=None, fields=None, **argv)
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        files = []
        for f in sorted((FIXTURES / folder).glob("*")):
            if f.is_file():
                files.append(f)
                gz = Path(tmp) / (f.name + ".gz")
                with open(f, "rb") as src, gzip.open(gz, "wb") as dst:
                    shutil.copyfileobj(src, dst)
                files.append(gz)
        for f in files:
            if not log.detect(f, common.head_text(f)):
                continue
            ctx = common.Context(args, f, f.name)
            with common.open_text(f) as fh:
                for offset, (key, doc) in enumerate(log.parse(fh, ctx)):
                    if key is not None:
                        common.finish_doc(log, doc, ctx, "test", offset)
                    out.append((f.name, key, doc))
    return out


class TemplateCheck(unittest.TestCase):
    def assert_mapped(self, prefix, results):
        _, _, body = common.load_templates(prefix)
        exact, open_prefixes = common.template_fields(body["mappings"])
        for name, key, doc in results:
            if key is None:
                continue
            self.assertEqual(common.unknown_fields(doc, exact, open_prefixes), [], f"{name}: {doc}")
            self.assertIn("@timestamp", doc, name)


class CloudTrailTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(cloudtrail2sofelk, "cloudtrail")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts_plain_and_gzip(self):
        self.assertEqual(len(self.docs), 2 * 18)

    def test_digest_skipped(self):
        names = {n for n, _, _ in self.results}
        self.assertFalse(any("Digest" in n for n in names))

    def test_sofelk_fields(self):
        doc = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "GetObject")
        self.assertEqual(doc["aws"]["cloudtrail"]["request_parameters"]["bucket_name"], "acme-finance")
        self.assertEqual(doc["host"]["hostname"], "acme-finance.s3.us-east-1.amazonaws.com")
        self.assertEqual(doc["destination"]["bytes"], 104857600)
        self.assertEqual(doc["source"]["ip"], "198.51.100.7")
        self.assertEqual(doc["cloud"]["region"], "us-east-1")
        self.assertIn('"key":"exports/payroll.csv"', doc["aws"]["cloudtrail"]["flattened"]["request_parameters"])

    def test_assumed_role_and_outcome(self):
        doc = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "StopLogging")
        uid = doc["aws"]["cloudtrail"]["user_identity"]
        self.assertEqual(uid["session_issuer"]["user_name"], "OrgAdmin")
        self.assertIs(uid["mfa_authenticated"], False)
        self.assertEqual(doc["event"]["outcome"], "success")
        failed = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "DeleteBucket")
        self.assertEqual(failed["event"]["outcome"], "failure")
        login = next(d for d in self.docs if d["aws"]["cloudtrail"].get("console_login") == "Failure")
        self.assertEqual(login["event"]["outcome"], "failure")

    def test_curated_parameters(self):
        run = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "RunInstances")
        self.assertEqual(run["aws"]["cloudtrail"]["request_parameters"]["image_id"], "ami-0bad")
        self.assertEqual(run["aws"]["cloudtrail"]["response_elements"]["instance_id"], ["i-01", "i-02"])
        sg = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "AuthorizeSecurityGroupIngress")
        self.assertEqual(sg["aws"]["cloudtrail"]["request_parameters"]["cidr_ip"], ["0.0.0.0/0"])
        key = next(d for d in self.docs if d["aws"]["cloudtrail"]["event_name"] == "CreateAccessKey")
        self.assertEqual(key["aws"]["cloudtrail"]["response_elements"]["access_key_id"], "AKIANEWKEY0000000003")

    def test_template(self):
        self.assert_mapped("aws-cloudtrail", self.results)


class VpcFlowTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(vpcflow2sofelk, "vpcflow")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 10)
        nodata = [r for _, k, r in self.results if k is None]
        self.assertEqual(len(nodata), 2)

    def test_v2_fields(self):
        doc = next(d for d in self.docs if d["destination"].get("port") == 22 and d["aws"]["vpcflow"].get("version") == 2)
        self.assertEqual(doc["aws"]["vpcflow"]["action"], "REJECT")
        self.assertEqual(doc["network"]["transport"], "tcp")
        self.assertEqual(doc["netflow"]["flow_duration"], 60.0)
        self.assertEqual(doc["@timestamp"], "2026-10-20T01:00:00.000Z")
        self.assertEqual(doc["destination"]["bytes"], 0)

    def test_unknown_account_dropped(self):
        doc = next(d for d in self.docs if d["destination"].get("ip") == "8.8.8.8")
        self.assertNotIn("account_id", doc["aws"]["vpcflow"])
        self.assertEqual(doc["network"]["transport"], "udp")

    def test_v5_custom_header(self):
        doc = next(d for d in self.docs if d["aws"]["vpcflow"].get("version") == 5 and d["destination"]["port"] == 443)
        self.assertEqual(doc["network"]["direction"], "egress")
        self.assertEqual(doc["aws"]["vpcflow"]["destination_service"], "S3")
        self.assertEqual(doc["aws"]["vpcflow"]["traffic_path"], "8")
        self.assertEqual(doc["network"]["tcp_flags"], ["syn", "fin"])
        self.assertEqual(doc["cloud"]["availability_zone"], "use1-az1")

    def test_community_id(self):
        # Reference value from the Community ID spec test vectors (TCP, 128.232.110.120:34855 -> 66.35.250.204:80)
        self.assertEqual(vpcflow2sofelk.community_id("128.232.110.120", "66.35.250.204", 6, 34855, 80),
                         "1:LQU9qZlK+B5F3KDmev6m5PMibrg=")

    def test_template(self):
        self.assert_mapped("aws-vpcflow", self.results)


class AlbTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(alb2sofelk, "alb")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 5)
        reasons = {r for _, k, r in self.results if k is None}
        self.assertEqual(reasons, {"Network Load Balancer (TLS listener) log line - not supported"})

    def test_request_split(self):
        doc = next(d for d in self.docs if d.get("url", {}).get("path") == "/uploads/cmd.php")
        self.assertEqual(doc["http"]["request"]["method"], "POST")
        self.assertEqual(doc["destination"]["port"], 443)
        self.assertEqual(doc["aws"]["elb"]["action_executed"], ["waf", "forward"])
        self.assertEqual(doc["aws"]["elb"]["classification"], "Ambiguous")
        self.assertEqual(doc["cloud"]["account"]["id"], "123456789012")

    def test_no_target(self):
        doc = next(d for d in self.docs if d["http"]["response"]["status_code"] == 503)
        self.assertNotIn("backend", doc)
        self.assertEqual(doc["aws"]["elb"]["request_processing_time"]["sec"], -1.0)

    def test_classic(self):
        doc = next(d for d in self.docs if d["event"]["dataset"] == "aws.elb_classic")
        self.assertEqual(doc["aws"]["elb"]["name"], "classic-lb")
        self.assertEqual(doc["backend"]["ip"], "10.0.1.16")

    def test_template(self):
        self.assert_mapped("httpdlog", self.results)


class CloudFrontTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(cloudfrontaccess2sofelk, "cloudfront")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def by_id(self, request_id):
        return next(d for d in self.docs if d["aws"]["cloudfront"]["request_id"] == request_id)

    def test_counts_plain_and_gzip(self):
        self.assertEqual(len(self.docs), 2 * 7)
        self.assertEqual([r for _, k, r in self.results if k is None], [])

    def test_fields_from_header(self):
        doc = self.by_id("rq2-Yy1_bc6cR==")
        self.assertEqual(doc["@timestamp"], "2026-10-20T01:05:10.000Z")
        self.assertEqual(doc["event"]["dataset"], "aws.cloudfront")
        self.assertEqual(doc["source"]["ip"], "198.51.100.23")
        self.assertEqual(doc["source"]["port"], 60001)
        self.assertEqual(doc["http"]["request"]["method"], "POST")
        self.assertEqual(doc["url"]["domain"], "www.example.com")
        self.assertEqual(doc["url"]["path"], "/api/upload.jsp")
        self.assertEqual(doc["url"]["query"], "cmd=whoami&x=%2E%2E%2F")
        self.assertEqual(doc["url"]["original"], "https://www.example.com/api/upload.jsp?cmd=whoami&x=%2E%2E%2F")
        self.assertEqual(doc["http"]["response"]["status_code"], 200)
        self.assertEqual(doc["http"]["request"]["referrer"], "https://www.example.com/app/")
        self.assertEqual(doc["destination"]["bytes"], 48211)
        self.assertEqual(doc["source"]["bytes"], 5120)
        self.assertEqual(doc["event"]["duration"], 415000000)
        self.assertEqual(doc["xff"]["ip"], ["10.0.0.8", "10.0.0.9"])
        self.assertEqual(doc["http"]["version"], "1.1")
        self.assertEqual(doc["tls"]["protocol"], "TLSv1.2")
        cf = doc["aws"]["cloudfront"]
        self.assertEqual(cf["distribution_id"], "E2ABCDEF123456")
        self.assertEqual(cf["distribution_domain"], "d111111abcdef8.cloudfront.net")
        self.assertEqual(cf["edge_location"], "IAD89-C1")
        self.assertEqual(cf["edge_result_type"], "Miss")

    def test_user_agent_decoded(self):
        self.assertEqual(self.by_id("rq1-Tx0_aZ5bQ==")["user_agent"]["original"], "Mozilla/5.0 (X11; Linux x86_64)")

    def test_ipv6_and_ranges(self):
        doc = self.by_id("rq3-Zz2_cd7dS==")
        self.assertEqual(doc["source"]["ip"], "2001:db8::7")
        self.assertEqual(doc["aws"]["cloudfront"]["range_end"], 15728639)
        self.assertEqual(doc["url"]["extension"], "zip")

    def test_aborted_request(self):
        doc = self.by_id("rq4-Aa3_de8eT==")
        self.assertEqual(doc["http"]["response"]["status_code"], 0)
        self.assertNotIn("tls", doc)
        self.assertEqual(doc["aws"]["cloudfront"]["edge_detailed_result_type"], "ClientCommError")

    def test_old_layout_and_new_field(self):
        old = self.by_id("rq5-Bb4_ef9fU==")
        self.assertNotIn("port", old["source"])
        self.assertEqual(old["http"]["version"], "1.1")
        new = self.by_id("rq6-Cc5_fg0gV==")
        self.assertEqual(new["aws"]["cloudfront"]["unmapped"]["c_country"], "GB")

    def test_no_other_importer_claims_cloudfront(self):
        others = [alb2sofelk, cloudtrail2sofelk, vpcflow2sofelk, waf2sofelk, eksaudit2sofelk,
                  route53resolver2sofelk, securityhub2sofelk]
        for f in sorted(FIXTURES.rglob("*")):
            if not f.is_file():
                continue
            head = common.head_text(f)
            is_cf = "cloudfront" in f.relative_to(FIXTURES).parts
            self.assertEqual(bool(cloudfrontaccess2sofelk.LOG.detect(f, head)), is_cf, f)
            if is_cf:
                self.assertFalse(any(m.LOG.detect(f, head) for m in others), f)

    def test_headerless(self):
        doc = self.by_id("rq7-Dd6_gh1hW==")
        self.assertEqual(doc["url"]["path"], "/admin/login.php")
        self.assertNotIn("distribution_id", doc["aws"]["cloudfront"])

    def test_template(self):
        self.assert_mapped("httpdlog", self.results)


class CloudFrontCsvTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(cloudfrontaccess2sofelk, "cloudfront/csv")
        cls.docs = {d["aws"]["cloudfront"]["request_id"]: d for _, k, d in cls.results if k is not None}

    def test_counts(self):
        self.assertEqual(len([k for _, k, _ in self.results if k is not None]), 2 * 4)

    def test_athena(self):
        doc = self.docs["rq8-Ee7_hi2iX=="]
        self.assertEqual(doc["source"]["ip"], "198.51.100.23")
        self.assertEqual(doc["url"]["path"], "/api/upload.jsp")
        self.assertEqual(doc["url"]["domain"], "www.example.com")
        self.assertEqual(doc["http"]["response"]["status_code"], 200)
        self.assertEqual(doc["aws"]["cloudfront"]["edge_location"], "IAD89-C1")
        self.assertEqual(doc["event"]["duration"], 415000000)

    def test_excel_dates(self):
        self.assertEqual(self.docs["rq10-Gg9_jk4kZ=="]["@timestamp"], "2026-10-20T05:15:00.000Z")

    def test_raw_line_column(self):
        doc = self.docs["rq11-Hh0_kl5lA=="]
        self.assertEqual(doc["url"]["path"], "/.env")
        self.assertEqual(doc["@timestamp"], "2026-10-20T06:00:00.000Z")

    def test_template(self):
        self.assert_mapped("httpdlog", self.results)


class WafTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(waf2sofelk, "waf")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 3)

    def test_fields(self):
        doc = next(d for d in self.docs if d["aws"]["waf"]["action"] == "BLOCK")
        self.assertEqual(doc["aws"]["waf"]["web_acl_name"], "prod-acl")
        self.assertIn("SQLi_QUERYARGUMENTS", doc["aws"]["waf"]["matched_rule_ids"])
        self.assertEqual(doc["url"]["domain"], "shop.example.com")
        self.assertEqual(doc["xff"]["ip"], ["10.9.9.9", "198.51.100.7"])
        self.assertEqual(doc["source"]["geo"]["country_iso_code"], "NL")
        self.assertEqual(doc["url"]["original"], "https://shop.example.com/index.php?id=1%27%20OR%201=1--")
        count = next(d for d in self.docs if d["url"]["path"] == "/wp-login.php")
        self.assertEqual(count["aws"]["waf"]["non_terminating_rule_ids"], ["count-bad-bots"])

    def test_template(self):
        self.assert_mapped("aws-waf", self.results)


class CloudTrailCsvTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(cloudtrail2sofelk, "cloudtrail/csv")
        cls.docs = {d["aws"]["cloudtrail"]["shared_event_id"]: d for _, k, d in cls.results if k is not None}

    def test_counts(self):
        self.assertEqual(len([1 for _, k, _ in self.results if k is not None]), 2 * 6)
        self.assertEqual([r for _, k, r in self.results if k is None], [])

    def test_athena_struct_and_json(self):
        doc = self.docs["athena-1"]
        ct = doc["aws"]["cloudtrail"]
        self.assertEqual(ct["user_identity"]["access_key_id"], "AKIAEXAMPLEDEV00001")
        self.assertEqual(doc["user"]["name"], "dev-ci")
        self.assertEqual(ct["request_parameters"]["secret_id"], "prod/db/master")
        self.assertEqual(ct["resources"]["type"], "AWS::SecretsManager::Secret")
        self.assertEqual(ct["tls_details"]["tls_version"], "TLSv1.3")
        self.assertIs(ct["read_only"], True)
        role = self.docs["athena-2"]["aws"]["cloudtrail"]["user_identity"]
        self.assertEqual(role["session_issuer"]["user_name"], "OrgAdmin")
        self.assertIs(role["mfa_authenticated"], False)

    def test_event_history_summary(self):
        doc = self.docs["sum-2"]
        self.assertEqual(doc["@timestamp"], "2026-10-20T14:21:00.000Z")  # 10/20/2026 2:21:00 PM
        self.assertEqual(doc["aws"]["cloudtrail"]["user_identity"]["access_key_id"], "ASIAEXAMPLE000002")
        self.assertEqual(doc["event"]["outcome"], "failure")
        self.assertEqual(doc["source"]["ip"], "198.51.100.7")

    def test_flattened_and_raw_column(self):
        flat = self.docs["flat-1"]
        self.assertEqual(flat["aws"]["cloudtrail"]["user_identity"]["arn"], "arn:aws:iam::123456789012:user/dev-ci")
        self.assertEqual(flat["aws"]["cloudtrail"]["request_parameters"]["user_name"], "backdoor")
        self.assertEqual(self.docs["insights-1"]["aws"]["cloudtrail"]["event_name"], "DescribeInstances")

    def test_template(self):
        self.assert_mapped("aws-cloudtrail", self.results)


class VpcFlowCsvTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(vpcflow2sofelk, "vpcflow/csv")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 4)
        self.assertEqual(len([1 for _, k, _ in self.results if k is None]), 2)  # NODATA

    def test_columns(self):
        rdp = next(d for d in self.docs if d["destination"].get("port") == 3389)
        self.assertEqual(rdp["aws"]["vpcflow"]["interface_id"], "eni-0a1b2c3d")
        self.assertEqual(rdp["@timestamp"], "2026-10-20T02:00:00.000Z")
        self.assertEqual(rdp["aws"]["vpcflow"]["unmapped"]["day"], "2026/10/20")
        insights = next(d for d in self.docs if d["source"].get("port") == 49822)
        self.assertEqual(insights["source"]["bytes"], 52428800)
        self.assertEqual(insights["aws"]["vpcflow"]["log_status"], "OK")
        self.assertTrue(any(d["source"].get("port") == 49823 for d in self.docs))  # @message column

    def test_spreadsheet_dates(self):
        ssh = next(d for d in self.docs if d["destination"].get("port") == 22)
        self.assertEqual(ssh["@timestamp"], "2026-10-20T02:10:00.000Z")
        self.assertEqual(ssh["netflow"]["flow_duration"], 60.0)
        self.assertEqual(ssh["event"]["outcome"], "failure")

    def test_template(self):
        self.assert_mapped("aws-vpcflow", self.results)


class AlbCsvTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(alb2sofelk, "alb/csv")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 4)

    def test_athena_alb(self):
        doc = next(d for d in self.docs if d.get("url", {}).get("path") == "/uploads/shell.jsp")
        self.assertEqual(doc["source"]["ip"], "198.51.100.7")
        self.assertEqual(doc["source"]["port"], 51000)
        self.assertEqual(doc["backend"]["port"], 8080)
        self.assertEqual(doc["http"]["request"]["method"], "POST")
        self.assertEqual(doc["url"]["query"], "cmd=whoami")
        self.assertEqual(doc["cloud"]["account"]["id"], "123456789012")
        ipv6 = next(d for d in self.docs if d.get("url", {}).get("path") == "/.env")
        self.assertEqual(ipv6["source"]["ip"], "2001:db8::7")
        self.assertNotIn("backend", ipv6)

    def test_athena_classic_and_raw(self):
        classic = next(d for d in self.docs if d["event"]["dataset"] == "aws.elb_classic")
        self.assertEqual(classic["backend"]["ip"], "10.0.1.16")
        self.assertEqual(classic["@timestamp"], "2026-10-20T02:17:00.000Z")
        raw = next(d for d in self.docs if d.get("url", {}).get("path") == "/export/all.csv")
        self.assertEqual(raw["destination"]["bytes"], 9000000)

    def test_template(self):
        self.assert_mapped("httpdlog", self.results)


class WafCsvTest(TemplateCheck):
    @classmethod
    def setUpClass(cls):
        cls.results = parse_all(waf2sofelk, "waf/csv")
        cls.docs = [d for _, k, d in cls.results if k is not None]

    def test_counts(self):
        self.assertEqual(len(self.docs), 2 * 3)

    def test_athena_structs(self):
        doc = next(d for d in self.docs if d["aws"]["waf"].get("terminating_rule_type") == "MANAGED_RULE_GROUP")
        self.assertEqual(doc["@timestamp"], "2026-10-20T03:00:00.000Z")
        self.assertEqual(doc["xff"]["ip"], ["10.9.9.9", "198.51.100.7"])
        self.assertEqual(doc["user_agent"]["original"], "sqlmap/1.8 (https://sqlmap.org)")
        self.assertIn("SQLi_QUERYARGUMENTS", doc["aws"]["waf"]["matched_rule_ids"])
        self.assertEqual(doc["aws"]["waf"]["labels"], ["awswaf:managed:aws:sql-database:SQLi_QueryArguments"])

    def test_insights_flattened(self):
        doc = next(d for d in self.docs if d["url"]["path"] == "/wp-login.php")
        self.assertEqual(doc["@timestamp"], "2026-10-20T03:01:00.000Z")
        self.assertEqual(doc["url"]["domain"], "shop.example.com")
        self.assertEqual(doc["aws"]["waf"]["non_terminating_rule_ids"], ["count-bad-bots"])
        raw = next(d for d in self.docs if d["url"]["path"] == "/login")
        self.assertEqual(raw["aws"]["waf"]["rate_based_rule_names"], ["rate-limit"])

    def test_template(self):
        self.assert_mapped("aws-waf", self.results)


class OddLineEndingsTest(unittest.TestCase):
    """Binary files and bare-CR (classic Mac) line endings must not crash detection, and
    CR-only CSVs must parse exactly like their CRLF/LF originals."""

    MODULES = {"cloudtrail": cloudtrail2sofelk, "vpcflow": vpcflow2sofelk, "alb": alb2sofelk, "waf": waf2sofelk,
               "route53": route53resolver2sofelk, "securityhub": securityhub2sofelk, "eks": eksaudit2sofelk,
               "securitylake": None}

    def records(self, module, path):
        args = types.SimpleNamespace(case=None, fields=None)
        ctx = common.Context(args, path, path.name)
        with common.open_text(path) as fh:
            return [doc for key, doc in module.LOG.parse(fh, ctx) if key is not None]

    def test_binary_files_are_not_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            junk = [b'\x89PNG\r\x1a\n,abc"x\rdef,' + bytes(range(256)) * 8,
                    b'a,b\r"c,d\re' + bytes(range(256)) * 8,
                    b'eventName,eventTime\r"x\ry",' + b"\x00\xff" * 100]
            for i, data in enumerate(junk):
                for name, payload in ((f"junk{i}.bin", data), (f"junk{i}.gz", gzip.compress(data))):
                    f = Path(tmp) / name
                    f.write_bytes(payload)
                    for module in filter(None, self.MODULES.values()):
                        self.assertIn(module.LOG.detect(f, common.head_text(f)), (True, False))
                        if module is not cloudtrail2sofelk:  # junk2 has CloudTrail CSV columns
                            self.assertFalse(module.LOG.detect(f, common.head_text(f)), (module.__name__, name))

    def test_cr_only_csv_parses_like_the_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            for folder, folder_module in self.MODULES.items():
                for src in sorted((FIXTURES / folder / "csv").glob("*")):
                    module = folder_module
                    if module is None:  # Security Lake CSVs: the importer named in the file
                        module = {"cloudtrail": cloudtrail2sofelk, "vpcflow": vpcflow2sofelk, "waf": waf2sofelk,
                                  "route53": route53resolver2sofelk, "securityhub": securityhub2sofelk,
                                  "eks": eksaudit2sofelk}[src.stem.split("_")[1]]
                    data = src.read_bytes().replace(b"\r\n", b"\n")
                    for suffix, payload in ((".csv", data.replace(b"\n", b"\r")),
                                            (".csv.gz", gzip.compress(data.replace(b"\n", b"\r")))):
                        f = Path(tmp) / (src.stem + "_mac" + suffix)
                        f.write_bytes(payload)
                        self.assertTrue(module.LOG.detect(f, common.head_text(f)), f"{folder}/{src.name}")
                        self.assertEqual(len(self.records(module, f)), len(self.records(module, src)),
                                         f"{folder}/{src.name}")


class SecurityLakeTest(TemplateCheck):
    """Amazon Security Lake (OCSF) exports: each importer loads its own source's records, maps
    them to its existing schema, and skips the other sources with a note."""

    MODULES = {"cloudtrail": cloudtrail2sofelk, "vpcflow": vpcflow2sofelk, "waf": waf2sofelk,
               "route53": route53resolver2sofelk, "securityhub": securityhub2sofelk, "eks": eksaudit2sofelk}

    @classmethod
    def setUpClass(cls):
        cls.results = {}
        for name, module in cls.MODULES.items():
            out = parse_all(module, "securitylake") + parse_all(module, "securitylake/csv")
            cls.results[name] = out

    def docs(self, source, file_part=""):
        return [doc for f, key, doc in self.results[source] if key is not None and file_part in f]

    def test_templates(self):
        for name, module in self.MODULES.items():
            self.assert_mapped(module.LOG.prefix, self.results[name])

    def test_every_source_recognised(self):
        for name in self.MODULES:
            self.assertTrue(self.docs(name), name)
            for doc in self.docs(name):
                self.assertEqual(doc["aws"]["securitylake"]["source"], name)
        # the mixed array: one record per importer, the other five skipped with a pointer
        for name in self.MODULES:
            mixed = [(k, d) for f, k, d in self.results[name] if f == "mixed_sources_array.json"]
            self.assertEqual(sum(1 for k, _ in mixed if k is not None), 1, name)
            self.assertEqual(sum(1 for k, d in mixed if k is None and "loaded by" in d), 5, name)

    def test_cloudtrail(self):
        docs = {d["aws"]["cloudtrail"]["event_name"]: d for d in self.docs("cloudtrail", "cloudtrail_")}
        fms = docs["DescribeSecurityGroups"]
        ct = fms["aws"]["cloudtrail"]
        self.assertEqual(fms["@timestamp"], "2026-10-20T01:00:00.000Z")
        self.assertEqual(ct["shared_event_id"], "10bee927-2572-4691-bdfa-7bec17c1794e")
        self.assertEqual(ct["user_identity"]["invoked_by"], "fms.amazonaws.com")
        self.assertEqual(ct["user_identity"]["session_issuer"]["user_name"], "AWSServiceRoleForFMS")
        self.assertIs(ct["read_only"], True)
        self.assertEqual(fms["source"]["address"], "fms.amazonaws.com")
        self.assertEqual(fms["cloud"]["account"]["id"], "111122223333")
        fail = docs["CreateUser"]
        self.assertEqual(fail["event"]["outcome"], "failure")
        self.assertEqual(fail["aws"]["cloudtrail"]["request_parameters"]["user_name"], "backup-admin")
        self.assertEqual(fail["source"]["ip"], "203.0.113.50")
        get = docs["GetObject"]
        self.assertEqual(get["aws"]["cloudtrail"]["request_parameters"]["bucket_name"], "finance-reports")
        self.assertEqual(get["destination"]["bytes"], 48213)
        self.assertIs(get["aws"]["cloudtrail"]["management_event"], False)
        self.assertIn("Invoke", docs)
        login = docs["ConsoleLogin"]
        self.assertEqual(login["aws"]["cloudtrail"]["console_login"], "Failure")
        self.assertEqual(login["event"]["outcome"], "failure")

    def test_cloudtrail_csv_matches_json(self):
        key = lambda d: (d["aws"]["cloudtrail"]["shared_event_id"], d["@timestamp"])
        js = {key(d): d for d in self.docs("cloudtrail", "cloudtrail_management")}
        for d in self.docs("cloudtrail", "athena_cloudtrail"):
            j = js[key(d)]
            for doc in (d, j):
                doc.pop("log", None)
            self.assertEqual(d, j)

    def test_cloudtrail_id_matches_native(self):
        """The OCSF event keeps eventID as its document key, like the native event."""
        rec = json.loads((FIXTURES / "securitylake" / "cloudtrail_management.jsonl").read_text().splitlines()[0])
        key, _ = cloudtrail2sofelk.from_ocsf(rec)
        self.assertEqual(key, "10bee927-2572-4691-bdfa-7bec17c1794e")

    def test_vpcflow(self):
        docs = self.docs("vpcflow", "vpcflow.jsonl")
        self.assertEqual(len(docs), 4)  # 2 records, plain + gzip; the NODATA record is skipped
        out = next(d for d in docs if d["network"]["direction"] == "egress")
        self.assertEqual(out["source"]["ip"], "10.0.1.15")
        self.assertEqual(out["destination"]["port"], 443)
        self.assertEqual(out["source"]["bytes"], 52344)
        self.assertEqual(out["aws"]["vpcflow"]["action"], "ACCEPT")
        self.assertEqual(out["netflow"]["flow_duration"], 60.0)
        self.assertEqual(out["aws"]["vpcflow"]["interface_id"], "eni-0a1b2c3d")
        self.assertEqual(out["network"]["tcp_flags"], ["ack", "syn", "fin"])
        rej = next(d for d in docs if d["network"]["direction"] == "ingress")
        self.assertEqual(rej["event"]["outcome"], "failure")
        self.assertEqual(rej["destination"]["port"], 3389)

    def test_waf(self):
        doc = self.docs("waf", "waf.jsonl")[0]
        self.assertEqual(doc["aws"]["waf"]["action"], "BLOCK")
        self.assertEqual(doc["aws"]["waf"]["web_acl_name"], "prod-acl")
        self.assertEqual(doc["source"]["ip"], "203.0.113.77")
        self.assertEqual(doc["url"]["domain"], "shop.example.com")
        self.assertEqual(doc["user_agent"]["original"], "sqlmap/1.7")
        self.assertEqual(doc["aws"]["waf"]["terminating_rule_match"]["condition_type"], ["SQL_INJECTION"])

    def test_route53(self):
        doc = self.docs("route53", "route53.jsonl")[0]
        self.assertEqual(doc["dns"]["question"]["name"], "c2.badexample.co.uk")
        self.assertEqual(doc["dns"]["question"]["registered_domain"], "badexample.co.uk")
        self.assertEqual(doc["dns"]["resolved_ip"], ["198.51.100.66"])
        self.assertEqual(doc["aws"]["route53"]["instance"], "i-0123456789abcdef0")
        blocked = [d for d in self.docs("route53", "route53.jsonl") if d["dns"]["response"]["code"] == "NXDOMAIN"][0]
        self.assertEqual(blocked["aws"]["route53"]["firewall"]["rule_action"], "BLOCK")

    def test_securityhub(self):
        docs = {d["aws"]["securityhub"]["product_name"]: d for d in self.docs("securityhub", "securityhub.jsonl")}
        gd = docs["GuardDuty"]["aws"]["securityhub"]
        self.assertEqual(gd["severity"], {"label": "HIGH", "normalized": 70})
        self.assertEqual(gd["workflow_status"], "NEW")
        self.assertEqual(gd["resource"]["type"], ["AwsEc2Instance"])
        self.assertEqual(docs["GuardDuty"]["@timestamp"], "2026-10-20T01:00:09.000Z")
        ctl = docs["Security Hub"]
        self.assertEqual(ctl["aws"]["securityhub"]["compliance"]["status"], "FAILED")
        self.assertEqual(ctl["aws"]["securitylake"]["class_uid"], 2001)

    def test_eks(self):
        doc = self.docs("eks", "eks_audit.jsonl")[0]
        self.assertEqual(doc["k8s"]["auditID"], "a1b2c3d4-audit-1")
        self.assertEqual(doc["k8s"]["user"]["groups"], ["system:masters", "system:authenticated"])
        self.assertEqual(doc["k8s"]["objectRef"]["resource"], "pods")
        self.assertEqual(doc["k8s"]["annotations"]["authorization.k8s.io/decision"], "allow")
        self.assertEqual(doc["http"]["request"]["method"], "CREATE")
        self.assertEqual(doc["http"]["response"]["status_code"], 201)
        self.assertEqual(doc["cloud"]["account"]["id"], "111122223333")

    def test_source_of(self):
        self.assertEqual(ocsf.source_of({"class_uid": 4001, "metadata": {}}), "vpcflow")
        self.assertEqual(ocsf.source_of({"class_uid": 2004, "metadata": {"product": {"name": "Inspector"}}}),
                         "securityhub")
        self.assertEqual(ocsf.source_of({"class_uid": 6003, "metadata": {"product": {"name": "Amazon EKS"}}}), "eks")
        self.assertIsNone(ocsf.source_of({"class_uid": 1001, "metadata": {"product": {"name": "Okta"}}}))
        self.assertIsNone(ocsf.source_of({"eventName": "x"}))


class NewNativeLogsTest(TemplateCheck):
    """Native Route 53 Resolver, Security Hub (ASFF) and EKS audit logs."""

    def test_route53(self):
        out = parse_all(route53resolver2sofelk, "route53") + parse_all(route53resolver2sofelk, "route53/csv")
        self.assert_mapped("aws-route53", out)
        docs = [d for _, k, d in out if k]
        self.assertEqual(len(docs), 10)  # 2 + 1 + 2 records, plain and gzip
        fw = [d for d in docs if d.get("aws", {}).get("route53", {}).get("firewall")]
        self.assertTrue(fw)
        self.assertEqual(fw[0]["aws"]["route53"]["resolver_instance"], "rslvr-in-0abc")
        self.assertEqual(fw[0]["event"]["type"], "denied")
        for f in (FIXTURES / "vpcflow").glob("*"):
            if f.is_file():
                self.assertFalse(route53resolver2sofelk.LOG.detect(f, common.head_text(f)), f)
        csv_file = FIXTURES / "route53" / "csv" / "athena_results.csv"
        self.assertFalse(vpcflow2sofelk.LOG.detect(csv_file, common.head_text(csv_file)))

    def test_securityhub(self):
        out = parse_all(securityhub2sofelk, "securityhub")
        self.assert_mapped("aws-securityhub", out)
        docs = [d for _, k, d in out if k]
        self.assertEqual(len(docs), 4)
        doc = next(d for d in docs if d["@timestamp"] == "2026-10-20T01:00:09.000Z")
        self.assertEqual(doc["source"]["ip"], "10.0.1.15")
        self.assertEqual(doc["destination"]["ip"], "198.51.100.66")
        self.assertEqual(doc["network"]["direction"], "egress")
        self.assertEqual(doc["event"]["severity"], 70)
        self.assertEqual(doc["message"], doc["aws"]["securityhub"]["title"])
        keys = {k for _, k, _ in out if k}
        self.assertEqual(len(keys), 2)  # one finding, two versions (UpdatedAt)

    def test_eks(self):
        out = parse_all(eksaudit2sofelk, "eks")
        self.assert_mapped("kubernetes", out)
        docs = [d for _, k, d in out if k]
        self.assertEqual(len(docs), 4)
        denied = next(d for d in docs if d["k8s"]["auditID"] == "a1b2c3d4-audit-2")
        self.assertEqual(denied["event"]["outcome"], "failure")
        self.assertEqual(denied["k8s"]["authorization_decision"], "forbid")
        self.assertEqual(denied["user"]["name"], "system:anonymous")
        created = next(d for d in docs if d["k8s"]["auditID"] == "a1b2c3d4-audit-1")
        self.assertIn('"privileged":true', created["k8s"]["flattened"]["request_object"])
        self.assertEqual(created["source"]["ip"], ["203.0.113.50"])
        self.assertFalse(eksaudit2sofelk.LOG.index_template)


class CommonTest(unittest.TestCase):
    def test_struct_with_json_and_dotted_keys(self):
        parsed = common.parse_struct('{operation=GetObject, request={data={"a":{"b":[1,2]},"c":"x, y=z"}, uid=r1}}')
        self.assertEqual(parsed, {"operation": "GetObject", "request": {"data": '{"a":{"b":[1,2]},"c":"x, y=z"}', "uid": "r1"}})
        self.assertEqual(common.parse_struct("{readOnly=true, userIdentity.sessionContext.sessionIssuer.userName=Admin,"
                                             " annotations.authorization.k8s.io/decision=allow}"),
                         {"readOnly": "true", "userIdentity.sessionContext.sessionIssuer.userName": "Admin",
                          "annotations.authorization.k8s.io/decision": "allow"})

    def test_struct_text(self):
        self.assertEqual(common.parse_struct("{type=IAMUser, sessioncontext={attributes={mfaauthenticated=false}},"
                                             " invokedby=null}"),
                         {"type": "IAMUser", "sessioncontext": {"attributes": {"mfaauthenticated": "false"}},
                          "invokedby": None})
        self.assertEqual(common.parse_struct("{name=X-Forwarded-For, value=10.0.0.1, 10.0.0.2}"),
                         {"name": "X-Forwarded-For", "value": "10.0.0.1, 10.0.0.2"})
        self.assertEqual(common.parse_struct("[a, b]"), ["a", "b"])
        self.assertIsNone(common.parse_struct("{not a struct"))

    def test_spreadsheet_dates(self):
        self.assertEqual(common.iso("10/20/2026 1:05 PM"), "2026-10-20T13:05:00.000Z")
        common.SETTINGS["date_order"] = "dmy"
        try:
            self.assertEqual(common.iso("20/10/2026 13:05:07"), "2026-10-20T13:05:07.000Z")
        finally:
            common.SETTINGS["date_order"] = "mdy"
        self.assertEqual(common.any_time("1792458000"), "2026-10-20T01:00:00.000Z")
        self.assertEqual(common.any_time("1792458000000", "ms"), "2026-10-20T01:00:00.000Z")

    def test_iso(self):
        self.assertEqual(common.iso("2026-10-20T01:00:05.123456Z"), "2026-10-20T01:00:05.123Z")
        self.assertEqual(common.iso("2026-10-20T01:00:05+0000"), "2026-10-20T01:00:05.000Z")
        self.assertIsNone(common.iso("2026-13-40T01:00:05Z"))

    def test_path_hints(self):
        acct, service, region = common.path_cloud_hints(
            "bucket/AWSLogs/123456789012/vpcflowlogs/eu-west-1/2026/10/20/x.log.gz")
        self.assertEqual((acct, service, region), ("123456789012", "vpcflowlogs", "eu-west-1"))

    def test_source_name(self):
        self.assertEqual(common.sanitize_source("Prod Account"), "prod-account")


if __name__ == "__main__":
    unittest.main()

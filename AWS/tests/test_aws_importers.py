#!/usr/bin/env python3
"""Parser tests for the AWS importers (standard library only, no Elasticsearch needed).

    python3 AWS/tests/test_aws_importers.py -v

Every fixture is parsed as plain text and again gzip-compressed, and every document is checked
against its index template. fixtures/<log>/ holds the native AWS formats, fixtures/<log>/csv/
the same logs already converted to CSV (Athena results, Logs Insights and spreadsheet exports): a field the template does not map would be silently dropped by
Elasticsearch (the indexes use dynamic: false).
"""
import gzip
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import alb2sofelk  # noqa: E402
import cloudtrail2sofelk  # noqa: E402
import sof_elk_aws_common as common  # noqa: E402
import vpcflow2sofelk  # noqa: E402
import waf2sofelk  # noqa: E402

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
        self.assert_mapped("aws-alb", self.results)


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
        self.assert_mapped("aws-alb", self.results)


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


class CommonTest(unittest.TestCase):
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

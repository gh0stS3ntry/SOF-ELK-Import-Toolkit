#!/usr/bin/env python3
"""Tests for AWS log discovery in SOF-ELK_ImportWrapper.py (no Elasticsearch needed).

    python3 tests/test_import_wrapper_aws.py -v

The AWS fixtures from AWS/tests/fixtures/ are copied into one case folder next to Windows
exports, and the wrapper must hand each AWS file to the importer whose own detect() claims it,
leave Windows exports to the Windows importers, and stage AWS files with their folder layout.
"""
import argparse
import gzip
import importlib.util
import io
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "AWS" / "tests" / "fixtures"
spec = importlib.util.spec_from_file_location("import_wrapper", ROOT / "SOF-ELK_ImportWrapper.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)

EXPECTED = {"cloudtrail": "AWS CloudTrail", "waf": "AWS WAF", "alb": "AWS ALB/ELB", "vpcflow": "AWS VPC Flow"}
VPC_LINE = "2 123456789012 eni-0abc 10.0.0.5 10.0.0.9 443 50000 6 10 840 1760922000 1760922060 ACCEPT OK\n"


class AwsDiscoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.aws = w.AwsDetector(ROOT)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "srizzile" / "aws"
        for folder in EXPECTED:
            shutil.copytree(FIXTURES / folder, self.root / folder)
        # gzip copies with the S3 delivery names, and a headerless VPC file recognised only by
        # its AWSLogs/<account>/vpcflowlogs/<region>/ key.
        for f in list((self.root / "cloudtrail").glob("*_CloudTrail_*.json")):
            with open(f, "rb") as src, gzip.open(f.with_name(f.name + ".gz"), "wb") as dst:
                shutil.copyfileobj(src, dst)
        key = self.root / "AWSLogs" / "123456789012" / "vpcflowlogs" / "us-east-1" / "2026" / "10" / "20"
        key.mkdir(parents=True)
        (key / "export-000").write_text(VPC_LINE)
        # Windows exports in the same tree stay with the Windows importers.
        win = self.root / "kape"
        win.mkdir()
        (win / "20261025_Amcache_UnassociatedFileEntries.csv").write_text("ProgramId,SHA1,FullPath\n")
        (win / "20261025_EvtxECmd_Output.csv").write_text("TimeCreated,EventId\n")
        (win / "notes.txt").write_text("nothing to see\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_detector_loaded(self):
        self.assertEqual(self.aws.error, "")
        self.assertEqual([label for label, _ in self.aws.detectors], list(w.AWS_IMPORTERS))

    def test_each_file_goes_to_its_importer(self):
        json_files, csv_files, linux, aws_files = w.discover(self.root, self.aws)
        self.assertEqual([p.name for p in json_files["EvtxECmd"]], ["20261025_EvtxECmd_Output.csv"])
        self.assertEqual([p.name for p in csv_files["AmcacheParser"]], ["20261025_Amcache_UnassociatedFileEntries.csv"])
        self.assertEqual(linux, [])
        claimed = {}
        for label, files in aws_files.items():
            for p in files:
                self.assertNotIn(p, claimed, f"{p} claimed twice")
                claimed[p] = label
        for p, label in claimed.items():
            folder = p.relative_to(self.root.resolve()).parts[0]
            expected = "AWS VPC Flow" if folder == "AWSLogs" else EXPECTED[folder]
            self.assertEqual(label, expected, p)
        # Every fixture except the CloudTrail digest is an AWS log.
        unclaimed = sorted(p.name for folder in EXPECTED for p in (self.root / folder).rglob("*")
                           if p.is_file() and p.resolve() not in claimed)
        self.assertEqual(len(unclaimed), 1)
        self.assertIn("CloudTrail-Digest", unclaimed[0])
        self.assertIn("export-000", {p.name for p in aws_files["AWS VPC Flow"]})
        self.assertIn("aws-waf-logs-prod-1-2026-10-20-01-00-00-abc", {p.name for p in aws_files["AWS WAF"]})
        self.assertTrue(any(p.suffix == ".gz" for p in aws_files["AWS CloudTrail"]))

    def test_security_lake_exports_go_to_every_source_importer(self):
        sl = self.root / "securitylake"
        shutil.copytree(FIXTURES / "securitylake", sl)
        _, _, _, aws_files = w.discover(self.root, self.aws)
        mixed = (sl / "mixed_sources_array.json").resolve()
        claimed = sorted(label for label, files in aws_files.items() if mixed in files)
        self.assertEqual(claimed, sorted(set(w.AWS_IMPORTERS) - {"AWS ALB/ELB"}))
        single = (sl / "route53.jsonl").resolve()
        self.assertEqual([label for label, files in aws_files.items() if single in files], ["AWS Route 53 Resolver"])
        athena = (sl / "csv" / "athena_cloudtrail.csv").resolve()
        self.assertEqual([label for label, files in aws_files.items() if athena in files], ["AWS CloudTrail"])

    def test_no_aws_detector_means_no_aws_files(self):
        _, _, _, aws_files = w.discover(self.root)
        self.assertFalse(any(aws_files.values()))

    def test_staging_keeps_the_folder_layout(self):
        _, _, _, aws_files = w.discover(self.root, self.aws)
        root = self.root.resolve()
        with w.StagingArea(root) as staging:
            staged = staging.add("AWS VPC Flow", aws_files["AWS VPC Flow"], keep_tree_from=root)
            rel = sorted(p.relative_to(staged).as_posix() for p in staged.rglob("*") if p.is_file())
            self.assertIn("AWSLogs/123456789012/vpcflowlogs/us-east-1/2026/10/20/export-000", rel)
            # The importer, run on the staged folder, must claim the same file again.
            f = staged / "AWSLogs" / "123456789012" / "vpcflowlogs" / "us-east-1" / "2026" / "10" / "20" / "export-000"
            self.assertEqual(self.aws.classify(f), ["AWS VPC Flow"])

    def test_importer_command_line(self):
        args = argparse.Namespace(
            hostname="sph", es="http://192.168.76.1:9200", user=None, password=None, insecure=False,
            batch_size=2000, max_retries=5, retry_backoff=2.0, timeout=300.0, sample_docs=2,
            log_file=None, case="srizzile", date_order="dmy", vpc_fields="version srcaddr dstaddr",
            dry_run=True)
        seen = []

        class FakeProc:
            def __init__(self, command, **_kw):
                seen.append(command)
                self.stdout = io.StringIO("ok\n")

            def wait(self):
                return 0

        with mock.patch.object(w.subprocess, "Popen", FakeProc), redirect_stdout(io.StringIO()):
            vpc = ROOT / "AWS" / "vpcflow2sofelk.py"
            ct = ROOT / "AWS" / "cloudtrail2sofelk.py"
            self.assertEqual(w.run_aws("AWS VPC Flow", vpc, self.root, 1, args), 0)
            self.assertEqual(w.run_aws("AWS CloudTrail", ct, self.root, 1, args), 0)
        vpc_cmd, ct_cmd = seen
        for cmd in seen:
            self.assertEqual(cmd[cmd.index("--source") + 1], "sph")
            self.assertEqual(cmd[cmd.index("--case") + 1], "srizzile")
            self.assertEqual(cmd[cmd.index("--date-order") + 1], "dmy")
            self.assertIn("--dry-run", cmd)
            self.assertNotIn("--hostname", cmd)
            self.assertNotIn("--workers", cmd)
        self.assertEqual(vpc_cmd[vpc_cmd.index("--fields") + 1], "version srcaddr dstaddr")
        self.assertNotIn("--fields", ct_cmd)
        # The command lines must be accepted by the importers' own argument parsers.
        sys.path.insert(0, str(ROOT / "AWS"))
        import sof_elk_aws_common as common
        import cloudtrail2sofelk
        import vpcflow2sofelk
        common.build_parser(vpcflow2sofelk.LOG, "x").parse_args(vpc_cmd[2:])
        common.build_parser(cloudtrail2sofelk.LOG, "x").parse_args(ct_cmd[2:])

    def test_ymd_date_order_is_not_passed_to_aws(self):
        args = argparse.Namespace(
            hostname="sph", es="http://x:9200", user=None, password=None, insecure=False, batch_size=1,
            max_retries=0, retry_backoff=1.0, timeout=1.0, sample_docs=1, log_file=None, case=None,
            date_order="ymd", vpc_fields=None, dry_run=False)
        seen = []

        class FakeProc:
            def __init__(self, command, **_kw):
                seen.append(command)
                self.stdout = io.StringIO("")

            def wait(self):
                return 0

        with mock.patch.object(w.subprocess, "Popen", FakeProc), redirect_stdout(io.StringIO()):
            w.run_aws("AWS WAF", ROOT / "AWS" / "waf2sofelk.py", self.root, 1, args)
        self.assertNotIn("--date-order", seen[0])


if __name__ == "__main__":
    unittest.main()

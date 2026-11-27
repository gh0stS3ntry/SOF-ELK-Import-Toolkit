#!/usr/bin/env python3
"""Tests for Java/javalog2sofelk.py and its wrapper discovery (standard library only).

    python3 tests/test_javalog.py -v

Synthetic fixtures: a Log4j log in the RD-style "%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n"
layout with iBATIS multi-line SQL (CRLF) and a "nested exception is" exception, a time-only Logback
log crossing midnight with a full stack trace, Spring Boot 2 and 3, Tomcat (JUL OneLineFormatter),
WildFly, a Log4j file with dd/MM/yyyy dates, a rotated .gz that starts mid stack trace, and files
that must not be claimed (a Python log, a Windows CBS log, an NCSA access log, a note). An
in-process mock Elasticsearch (from test_iisgeolocate.py) takes the bulk requests.
"""
import contextlib
import gzip
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "Java"))
sys.path.insert(0, str(REPO / "Linux" / "common"))
sys.path.insert(0, str(REPO))

import javalog2sofelk as jl  # noqa: E402
import sof_elk_linux_common as common  # noqa: E402
from test_iisgeolocate import MockES  # noqa: E402

SAMPLE = (
    "26-11-26 00:01:16.063 ERROR com.clt.server.mail.MailReceive [getMail :255] com.sun.mail.util.MailConnectException:"
    " Couldn't connect to host, port: 172.30.100.47, 143; timeout -1;\n"
    "  nested exception is:\n"
    "\tjava.net.ConnectException: Connection timed out (Connection timed out)\n"
    "26-11-26 00:01:16.064 ERROR com.clt.server.remote.server.QueryJob [batchEDIfile :213] java.lang.NullPointerException\n"
    "26-11-26 00:01:16.065 DEBUG com.ibatis.common.logging.jakarta.JakartaCommonsLoggingImpl [debug :27] {conn-466912} Connection\n"
    "26-11-26 00:01:16.065 DEBUG com.ibatis.common.logging.jakarta.JakartaCommonsLoggingImpl [debug :27] {pstm-466913}"
    " Executing Statement: \r\n"
    "\t\t\n"
    "\t\t\tSELECT CLSS_TP_CD\n"
    "\t\t\t     , CLSS_CD\n"
    "\t\t\t  FROM STO_SYS_CLSS_CD A, STO_SYS_USR B\n"
    "\t\t\t WHERE 1=1\n"
    "\t\t\t ORDER BY CLSS_ORD_SEQ          \n"
    "\t \n"
    "26-11-26 00:01:16.065 DEBUG com.ibatis.common.logging.jakarta.JakartaCommonsLoggingImpl [debug :27] {pstm-466913}"
    " Executing Statement: \r\n"
    "\t\t\n"
    "\t\t\tSELECT CLSS_TP_CD\n"
    "\t\t\t     , CLSS_CD\n"
    "\t\t\t  FROM STO_SYS_CLSS_CD A, STO_SYS_USR B\n"
    "\t\t\t WHERE 1=1\n"
    "\t\t\t ORDER BY CLSS_ORD_SEQ          \n"
    "\t \n"
    "26-11-26 00:44:44.542 DEBUG com.ibatis.common.logging.jakarta.JakartaCommonsLoggingImpl [debug :27] {pstm-468614}"
    " Executing Statement: \r\n"
    "        DELETE STO_UPDATE_HIST\n"
    "         WHERE USR_ID = 'INMUN01'\n"
    "26-11-26 00:44:45.000 DEBUG com.ibatis.common.logging.jakarta.JakartaCommonsLoggingImpl [debug :27] {conn-488130}"
    " Preparing Call: call OPF_BAY_PRC(\n"
    "\t\t?,?,'F'\n"
    "\t\t)\n"
    "26-11-26 00:45:00.000 DEBUG com.clt.server.Job [run :10] Update finished for 3 rows\n"
)
LOGBACK = (
    "23:59:58.100 [main] INFO  com.example.App - Starting App v1.2\n"
    "23:59:59.900 [http-nio-8080-exec-1] ERROR c.e.web.LoginController - Login failed for user admin\n"
    "java.lang.IllegalStateException: boom\n"
    "\tat com.example.web.LoginController.login(LoginController.java:42)\n"
    "\tat org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)\n"
    "Caused by: java.sql.SQLException: ORA-01017: invalid username/password\n"
    "\tat oracle.jdbc.driver.T4CTTIoer.processError(T4CTTIoer.java:450)\n"
    "\t... 12 more\n"
    "00:00:01.000 [main] WARN  com.example.App - after midnight\n"
)
SPRING = (
    "2026-11-26 10:57:51.112  INFO 45469 --- [           main] o.s.b.w.embedded.tomcat.TomcatWebServer  :"
    " Tomcat started on port(s): 8080 (http)\n"
    "2026-11-26 10:57:52.001 DEBUG 45469 --- [nio-8080-exec-1] org.hibernate.SQL                        : \n"
    "    select\n"
    "        user0_.id as id1_0_ \n"
    "    from\n"
    "        users user0_ \n"
    "    where\n"
    "        user0_.username=?\n"
)
SPRING3 = ("2026-11-26T10:57:51.112+08:00  INFO 45469 --- [demo] [           main] c.e.demo.DemoApplication"
           "                 : Started DemoApplication in 1.2 seconds\n") * 3
TOMCAT = (
    "26-Nov-2026 10:00:00.123 INFO [main] org.apache.catalina.startup.Catalina.start Server startup in [1234] milliseconds\n"
    "26-Nov-2026 10:05:00.456 SEVERE [http-nio-8080-exec-3] org.apache.catalina.core.StandardWrapperValve.invoke"
    " Servlet.service() for servlet [jsp] threw exception\n"
    "\tjava.lang.NullPointerException\n"
    "\t\tat org.apache.jsp.cmd_jsp._jspService(cmd_jsp.java:118)\n"
    "26-Nov-2026 10:06:00.000 INFO [main] org.apache.catalina.startup.HostConfig.deployWAR Deploying web application"
    " archive [/opt/tomcat/webapps/shell.war]\n"
)
WILDFLY = "".join(f"2026-11-26 10:00:0{i},123 INFO  [org.jboss.as] (MSC service thread 1-2) WFLYSRV0049: WildFly starting\n"
                  for i in range(3))
DMY = ("25/11/2026 13:00:00,000 INFO  [main] com.example.Dao:88 - first\n"
       "26/11/2026 13:00:00,000 ERROR [main] com.example.Dao:90 - second\n"
       "26/11/2026 13:00:01,000 INFO  [main] com.example.Dao:91 - third\n")
ROTATED = ("\tat com.example.Old.call(Old.java:1)\n"
           "\t... 3 more\n"
           "2026-11-24 23:00:00,000 INFO  [main] com.example.Old - rotated event\n"
           "2026-11-24 23:00:01,000 INFO  [main] com.example.Old - another\n")
PYTHON = "".join(f"2026-11-26 10:00:0{i},123 INFO starting worker {i}\n" for i in range(6))
CBS = "".join(f"2026-11-26 10:00:0{i}, Info                  CBS    Loaded Servicing Stack v10.0\n" for i in range(6))
NCSA = '192.0.2.10 - - [25/Nov/2026:09:15:01 +0800] "GET / HTTP/1.1" 200 5120\n' * 3


def write_fixtures(root: Path):
    (root / "app").mkdir(parents=True)
    (root / "app" / "stwg-server.log").write_bytes(SAMPLE.encode())
    (root / "app" / "app.2026-11-26.log").write_text(LOGBACK)
    (root / "app" / "spring.log").write_text(SPRING)
    (root / "app" / "boot3.log").write_text(SPRING3)
    (root / "tomcat").mkdir()
    (root / "tomcat" / "catalina.2026-11-26.log").write_text(TOMCAT)
    (root / "wildfly").mkdir()
    (root / "wildfly" / "server.log").write_text(WILDFLY)
    (root / "app" / "dao.log").write_text(DMY)
    with gzip.open(root / "app" / "old.log.1.gz", "wt") as fh:
        fh.write(ROTATED)
    (root / "misc").mkdir()
    (root / "misc" / "worker.log").write_text(PYTHON)
    (root / "misc" / "CBS.log").write_text(CBS)
    (root / "misc" / "access.log").write_text(NCSA)
    (root / "misc" / "notes.txt").write_text("nothing to see\n")
    return root


def args_for(**kw):
    base = dict(date_order=None, log_date=None, user_layouts=[], service=None,
                max_message_chars=jl.DEFAULT_MAX_CHARS)
    base.update(kw)
    return SimpleNamespace(**base)


def parsed(path, rel=None, tz="+08:00", **kw):
    jl.parse.seen, jl.parse.layouts = {}, {}
    args = args_for(**kw)
    profile = jl.FileProfile("app01", None, tz)
    plan, why = jl.plan_file(Path(path), rel or Path(path).name, args, profile, args.user_layouts)
    assert plan is not None, why
    return [(p, d) for p, d in jl.parse(None, profile, args, plan, common.Report())], plan


def run_importer(*argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        code = jl.main([str(a) for a in argv] + ["--retry-backoff", "0.01"])
    return code, out.getvalue()


class LayoutTest(unittest.TestCase):
    def match(self, pattern, line):
        lay = jl.Layout("t", pattern)
        m = lay.match(line)
        self.assertIsNotNone(m, (pattern, line))
        return {lay.groups[g][0]: v for g, v in m.groupdict().items()}

    def test_conversion_words(self):
        got = self.match("%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n",
                         "26-11-26 00:01:16.065 DEBUG com.x.Y [debug :27] {conn-1} Connection")
        self.assertEqual((got["level"], got["logger"], got["method"], got["line"], got["message"]),
                         ("DEBUG", "com.x.Y", "debug", "27", "{conn-1} Connection"))
        got = self.match("%d{dd MMM yyyy HH:mm:ss,SSS} %-5p [%t] (%F:%L) - %m%n",
                         "26 Nov 2026 10:00:00,123 INFO  [pool-1 thread-2] (App.java:42) - x")
        self.assertEqual((got["thread"], got["file"], got["line"]), ("pool-1 thread-2", "App.java", "42"))

    def test_spring_boot_file_pattern_with_properties_and_colours(self):
        pattern = ("%clr(%d{${LOG_DATEFORMAT_PATTERN:-yyyy-MM-dd HH:mm:ss.SSS}}){faint} %clr(${LOG_LEVEL_PATTERN:-%5p})"
                   " %clr(${PID:- }){magenta} %clr(---){faint} %clr([%15.15t]){faint} %clr(%-40.40logger{39}){cyan}"
                   " %clr(:){faint} %m%n${LOG_EXCEPTION_CONVERSION_WORD:-%wEx}")
        got = self.match(pattern, SPRING.splitlines()[0])
        self.assertEqual((got["pid"], got["thread"], got["logger"]), ("45469", "main", "o.s.b.w.embedded.tomcat.TomcatWebServer"))

    def test_log4j2_brace_composites_and_mdc(self):
        got = self.match("%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %highlight{%-5level} %logger{36} - %msg%n",
                         "2026-11-26 10:00:00.123 [main] WARN  com.example.App - hello")
        self.assertEqual(got["level"], "WARN")
        got = self.match("%d{ISO8601} [%X{traceId}] %-5p %c - %m%n", "2026-11-26 10:00:00,123 [abc123] INFO  a.b.C - x")
        self.assertEqual(got["mdc"], "abc123")

    def test_dates(self):
        ctx = jl.FileContext(__file__, "x.log", None)
        parse = lambda fmt, raw: jl.make_date(fmt).parse(raw, ctx)[0]  # noqa: E731
        self.assertEqual(parse("yyyy-MM-dd'T'HH:mm:ss.SSSXXX", "2026-11-26T10:00:00.123+08:00").utcoffset().total_seconds(), 28800)
        self.assertEqual(parse("UNIX_MILLIS", "1764122400123").year, 2025)
        self.assertEqual(parse("DATE", "26 Nov 2026 10:00:00,123").month, 11)
        self.assertEqual(parse(None, "26-Nov-2026 10:00:00.123").day, 26)
        self.assertEqual(parse(None, "Nov 26, 2026 1:02:03 PM").hour, 13)
        self.assertEqual(jl.numeric_orders("26", "11", "26"), ["ymd", "dmy"])
        self.assertEqual(jl.numeric_orders("11", "26", "2026"), ["mdy"])

    def test_pattern_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            props = Path(tmp) / "log4j.properties"
            props.write_text("log4j.rootLogger=DEBUG, R\nlog4j.appender.R.layout.ConversionPattern="
                             "%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n\n")
            xml = Path(tmp) / "logback.xml"
            xml.write_text("<configuration><appender><encoder><pattern>%d{HH:mm:ss.SSS} [%thread] %-5level"
                           " %logger{36} - %msg%n</pattern></encoder></appender>"
                           "<appender><layout><Pattern>%d %p &lt;%c&gt; %m%n</Pattern></layout></appender></configuration>")
            self.assertEqual(jl.patterns_from_config(props), ["%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n"])
            self.assertEqual(jl.patterns_from_config(xml), ["%d{HH:mm:ss.SSS} [%thread] %-5level %logger{36} - %msg%n",
                                                            "%d %p <%c> %m%n"])

    def test_service_names(self):
        self.assertEqual(jl.service_from_name("stwg-server.log"), "stwg-server")
        self.assertEqual(jl.service_from_name("catalina.2026-11-26.log"), "catalina")
        self.assertEqual(jl.service_from_name("app.log.3.gz"), "app")
        self.assertEqual(jl.service_from_name("server.log.2026-11-26"), "server")


class ParseTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_detect(self):
        for rel in ("app/stwg-server.log", "app/app.2026-11-26.log", "app/spring.log", "app/boot3.log",
                    "tomcat/catalina.2026-11-26.log", "wildfly/server.log", "app/dao.log", "app/old.log.1.gz"):
            self.assertTrue(jl.detect(self.root / rel), rel)
        for rel in ("misc/worker.log", "misc/CBS.log", "misc/access.log", "misc/notes.txt"):
            self.assertFalse(jl.detect(self.root / rel), rel)

    def test_sample_layout_multiline_sql_and_exceptions(self):
        rows, plan = parsed(self.root / "app" / "stwg-server.log", "app/stwg-server.log")
        self.assertEqual(plan.layouts[0].name, "log4j-logger-method-line")
        docs = [d for p, d in rows]
        self.assertEqual(len(docs), 8)
        mail, npe, conn, sql, sql_dup, delete, call, plain = docs
        self.assertEqual(mail["@timestamp"], "2026-11-25T16:01:16.063000Z")     # +08:00 -> UTC
        self.assertEqual(mail["javalog"]["timestamp_original"], "26-11-26 00:01:16.063")
        self.assertEqual(mail["log"]["level"], "ERROR")
        self.assertEqual(mail["log"]["logger"], "com.clt.server.mail.MailReceive")
        self.assertEqual(mail["log"]["origin"], {"function": "getMail", "file": {"line": 255}})
        self.assertEqual(mail["error"]["type"], "com.sun.mail.util.MailConnectException")
        self.assertEqual(mail["javalog"]["exception"]["root_cause"], "java.net.ConnectException")
        self.assertEqual(mail["javalog"]["line_count"], 3)
        self.assertEqual(mail["tags"], ["multiline", "exception", "stack_trace"])
        self.assertTrue(mail["message"].endswith("Connection timed out (Connection timed out)"))
        self.assertEqual(npe["error"]["type"], "java.lang.NullPointerException")
        self.assertNotIn("stack_trace", npe["error"])
        self.assertEqual(conn["javalog"]["sql"], {"object_id": "conn-466912"})
        self.assertEqual(sql["javalog"]["sql"]["verb"], "SELECT")
        self.assertEqual(sql["javalog"]["sql"]["statement"],
                         "SELECT CLSS_TP_CD , CLSS_CD FROM STO_SYS_CLSS_CD A, STO_SYS_USR B WHERE 1=1 ORDER BY CLSS_ORD_SEQ")
        self.assertEqual(sql["javalog"]["sql"]["tables"], ["STO_SYS_CLSS_CD", "STO_SYS_USR"])
        self.assertEqual(sql["javalog"]["sql"]["object_id"], "pstm-466913")
        self.assertEqual(sql["javalog"]["first_line"], "{pstm-466913} Executing Statement:")
        self.assertEqual(sql["javalog"]["line_count"], 8)
        self.assertNotIn("\r", sql["message"])
        self.assertEqual(sql["log"]["offset"], 5)
        self.assertEqual(delete["javalog"]["sql"]["tables"], ["STO_UPDATE_HIST"])
        self.assertEqual(call["javalog"]["sql"]["verb"], "CALL")
        self.assertEqual(call["javalog"]["sql"]["tables"], ["OPF_BAY_PRC"])
        self.assertNotIn("sql", plain.get("javalog", {}))                         # "Update finished" is not SQL
        self.assertEqual(sql["service"]["name"], "stwg-server")
        # the duplicated event keeps its own document: same family and text, next occurrence
        ids = [p for p, _d in rows]
        self.assertEqual(ids[3][:2], ids[4][:2])
        self.assertEqual((ids[3][2], ids[4][2]), (0, 1))
        self.assertEqual(ids[3][0], "stwg-server.log")

    def test_time_only_logback_with_stack_trace_and_midnight(self):
        rows, plan = parsed(self.root / "app" / "app.2026-11-26.log")
        self.assertEqual(plan.layouts[0].name, "logback-default")
        docs = [d for _p, d in rows]
        self.assertEqual([d["@timestamp"] for d in docs],
                         ["2026-11-26T15:59:58.100000Z", "2026-11-26T15:59:59.900000Z", "2026-11-26T16:00:01.000000Z"])
        err = docs[1]
        self.assertEqual(err["process"]["thread"]["name"], "http-nio-8080-exec-1")
        self.assertEqual(err["error"]["type"], "java.lang.IllegalStateException")
        self.assertEqual(err["error"]["message"], "boom")
        self.assertEqual(err["javalog"]["exception"]["classes"],
                         ["java.lang.IllegalStateException", "java.sql.SQLException"])
        self.assertEqual(err["javalog"]["exception"]["root_cause_message"], "ORA-01017: invalid username/password")
        self.assertEqual(err["javalog"]["exception"]["top_frame"],
                         "com.example.web.LoginController.login(LoginController.java:42)")
        self.assertEqual(err["javalog"]["exception"]["frame_count"], 3)
        self.assertTrue(err["error"]["stack_trace"].startswith("java.lang.IllegalStateException: boom\n\tat "))
        self.assertEqual(err["javalog"]["line_count"], 7)

    def test_log_date_option_and_mtime(self):
        import datetime as dt
        rows, plan = parsed(self.root / "app" / "app.2026-11-26.log", "x.log", log_date=dt.date(2026, 1, 2))
        self.assertEqual(rows[0][1]["@timestamp"][:10], "2026-01-02")
        self.assertEqual(plan.ctx.base_source, "--log-date")

    def test_spring_boot_and_hibernate_sql(self):
        rows, plan = parsed(self.root / "app" / "spring.log", tz=None)
        self.assertEqual(plan.layouts[0].name, "spring-boot")
        started, sql = [d for _p, d in rows]
        self.assertEqual(started["process"]["pid"], 45469)
        self.assertEqual(started["log"]["logger"], "o.s.b.w.embedded.tomcat.TomcatWebServer")
        self.assertEqual(started["@timestamp"], "2026-11-26T10:57:51.112000Z")   # no --local-tz: UTC
        self.assertEqual(started["event"]["timezone"], "UTC")
        self.assertEqual(sql["javalog"]["sql"]["verb"], "SELECT")
        self.assertEqual(sql["javalog"]["sql"]["tables"], ["USERS"])
        rows, plan = parsed(self.root / "app" / "boot3.log")
        doc = rows[0][1]
        self.assertEqual(plan.layouts[0].name, "spring-boot-3")
        self.assertEqual(doc["service"]["name"], "demo")
        self.assertEqual(doc["@timestamp"], "2026-11-26T02:57:51.112000Z")       # its own offset wins

    def test_tomcat_wildfly_and_dmy(self):
        rows, plan = parsed(self.root / "tomcat" / "catalina.2026-11-26.log")
        self.assertEqual(plan.layouts[0].name, "jul-oneline")
        docs = [d for _p, d in rows]
        self.assertEqual(docs[1]["log"]["level"], "SEVERE")
        self.assertEqual(docs[1]["log"]["logger"], "org.apache.catalina.core.StandardWrapperValve.invoke")
        self.assertEqual(docs[1]["error"]["type"], "java.lang.NullPointerException")
        self.assertEqual(docs[1]["javalog"]["exception"]["top_frame"], "org.apache.jsp.cmd_jsp._jspService(cmd_jsp.java:118)")
        rows, plan = parsed(self.root / "wildfly" / "server.log")
        self.assertEqual(plan.layouts[0].name, "wildfly")
        self.assertEqual(rows[0][1]["process"]["thread"]["name"], "MSC service thread 1-2")
        self.assertEqual(rows[0][1]["log"]["logger"], "org.jboss.as")
        rows, plan = parsed(self.root / "app" / "dao.log")
        self.assertEqual(plan.ctx.order, "dmy")                                  # 25/11 rules out MM/dd
        self.assertEqual(plan.layouts[0].name, "log4j-level-thread-logger-line")
        self.assertEqual([d["@timestamp"][:10] for _p, d in rows], ["2026-11-25", "2026-11-26", "2026-11-26"])
        self.assertEqual(rows[1][1]["log"]["origin"]["file"]["line"], 90)

    def test_orphan_lines_and_gzip(self):
        rows, _plan = parsed(self.root / "app" / "old.log.1.gz")
        docs = [d for _p, d in rows]
        self.assertEqual(len(docs), 3)
        self.assertIn("orphan_lines", docs[0]["tags"])
        self.assertEqual(docs[0]["@timestamp"], docs[1]["@timestamp"])
        self.assertNotIn("log", docs[0].get("log", {}).get("level", ""))
        self.assertEqual(docs[0]["javalog"]["line_count"], 2)

    def test_truncation(self):
        path = self.root / "app" / "big.log"
        path.write_text("2026-11-26 10:00:00,000 INFO  [main] com.example.Big - payload\n" + "x" * 80 + "\n" * 1
                        + ("y" * 100 + "\n") * 50 + "2026-11-26 10:00:01,000 INFO  [main] com.example.Big - next\n")
        rows, _plan = parsed(path, max_message_chars=1000)
        big = rows[0][1]
        self.assertIn("message_truncated", big["tags"])
        self.assertLess(len(big["message"]), 1100)
        self.assertEqual(big["javalog"]["line_count"], 52)

    def test_user_pattern(self):
        path = self.root / "app" / "custom.log"
        path.write_text("2026-11-26 10:00:00 | abc123 | bob | com.example.Svc | login ok\n"
                        "2026-11-26 10:00:01 | abc124 | eve | com.example.Svc | login failed\n")
        lay = jl.Layout("custom", "%d{yyyy-MM-dd HH:mm:ss} | %X{traceId} | %X{user} | %c | %m%n")
        rows, _plan = parsed(path, user_layouts=[lay])
        doc = rows[1][1]
        self.assertEqual(doc["trace"]["id"], "abc124")
        self.assertEqual(doc["user"]["name"], "eve")
        self.assertEqual(doc["javalog"]["mdc"], ["traceId=abc124", "user=eve"])
        self.assertEqual(doc["javalog"]["layout"], "custom")

    def test_every_field_is_mapped(self):
        exact = common.template_fields(common.load_templates("javalog", "java")[2]["mappings"])
        for path in sorted(self.root.rglob("*")):
            if path.is_file() and path.parent.name != "misc":
                for _p, doc in parsed(path)[0]:
                    doc = dict(doc, host={"name": "app01", "os": {"type": "linux"}}, case="IR-1")
                    self.assertEqual(common.unknown_fields(doc, exact), [], path.name)


class LoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name))
        self.es = MockES()

    def tearDown(self):
        self.es.close()
        self.tmp.cleanup()

    def test_load_and_rerun(self):
        code, out = run_importer(self.root, "--hostname", "APP01", "--case", "IR-1", "--local-tz", "+08:00",
                                 "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("8 Java log file(s)", out)
        self.assertIn("skipped 4 file(s)", out)
        self.assertIn("Index 'javalog-app01': created", out)
        index = self.es.indices["javalog-app01"]
        self.assertEqual(index["mappings"]["_meta"]["toolkit_schema"], "javalog")
        docs = list(index["docs"].values())
        self.assertEqual(len(docs), 28)
        self.assertEqual({d["case"] for d in docs}, {"IR-1"})
        self.assertEqual({d["host"]["name"] for d in docs}, {"app01"})
        self.assertEqual({d["event"]["dataset"] for d in docs}, {"java.log"})
        self.assertNotIn("fields not in index-javalog.json", out)
        code, out = run_importer(self.root / "app", "--hostname", "APP01", "--local-tz", "+08:00", "--es", self.es.url)
        self.assertEqual(code, 0, out)
        self.assertIn("Index 'javalog-app01': appending", out)
        self.assertIn("-> 0 new documents", out)
        self.assertEqual(len(index["docs"]), 28)

    def test_pattern_option_and_dry_run(self):
        code, out = run_importer(self.root / "app" / "stwg-server.log", "--hostname", "APP01", "--dry-run",
                                 "--pattern", "%d{yy-MM-dd HH:mm:ss.SSS} %-5p %c [%M :%L] %m%n")
        self.assertEqual(code, 0, out)
        self.assertIn("layout custom", out)
        self.assertIn("8 record(s) parsed", out)
        self.assertIn("no --local-tz given", out)
        code, out = run_importer(self.root / "misc", "--hostname", "APP01", "--dry-run")
        self.assertEqual(code, 1, out)
        self.assertIn("No Java application logs found.", out)


def load_wrapper():
    import importlib.util
    spec = importlib.util.spec_from_file_location("sof_elk_import_wrapper", REPO / "SOF-ELK_ImportWrapper.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WrapperDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = write_fixtures(Path(self.tmp.name) / "evidence")
        self.w = load_wrapper()

    def tearDown(self):
        self.tmp.cleanup()

    def test_discovery(self):
        javalog = self.w.JavaLogDetector(REPO)
        ncsa = self.w.NcsaDetector(REPO)
        self.assertEqual((javalog.error, ncsa.error), ("", ""))
        self.assertEqual(self.w.CSV_IMPORTERS[self.w.JAVALOG_LABEL], ("javalog2sofelk.py", "javalog"))
        self.assertNotIn(self.w.JAVALOG_LABEL, self.w.NO_LOCAL_TZ)     # --local-tz is passed on
        _json, csv_files, _linux, _aws = self.w.discover(self.root, None, ncsa, javalog)
        names = sorted(p.relative_to(self.root).as_posix() for p in csv_files[self.w.JAVALOG_LABEL])
        self.assertEqual(names, ["app/app.2026-11-26.log", "app/boot3.log", "app/dao.log", "app/old.log.1.gz",
                                 "app/spring.log", "app/stwg-server.log", "tomcat/catalina.2026-11-26.log",
                                 "wildfly/server.log"])
        self.assertEqual([p.name for p in csv_files[self.w.NCSA_LABEL]], ["access.log"])
        _json, csv_files, _linux, _aws = self.w.discover(self.root, None, ncsa)
        self.assertEqual(csv_files[self.w.JAVALOG_LABEL], [])


if __name__ == "__main__":
    unittest.main()

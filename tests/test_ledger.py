"""Offline tests: no network, OSV and the exploited lists are stubbed.

GitHub, OSV, CISA KEV and ENISA EUVD are played by a local HTTP server on
127.0.0.1 (FakeAPI) where a test needs the real HTTP code path.
"""

import argparse
import contextlib
import datetime as dt
import io
import json
import os
import pathlib
import runpy
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from unittest import mock

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parent))

import ledger

FIX = HERE / "fixtures"
LOG4J = "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"


def load(name):
    return json.loads((FIX / name).read_text())


class FakeOSV(ledger.OSV):
    """log4j-core 2.14.1 has two advisories; nothing else is vulnerable."""

    VULNS: ClassVar[dict] = {
        "GHSA-jfh8-c2jp-5v3q": {
            "id": "GHSA-jfh8-c2jp-5v3q",
            "aliases": ["CVE-2021-44228"],
            "summary": "Remote code injection in Log4j",
        },
        "GHSA-8489-44mv-ggj8": {
            "id": "GHSA-8489-44mv-ggj8",
            "aliases": ["CVE-2021-44832"],
            "summary": "Improper input validation in Log4j",
        },
    }

    def __init__(self):
        self.queried = None

        def query(purls):
            self.queried = purls
            return {LOG4J: list(self.VULNS)} if LOG4J in purls else {}

        super().__init__(query=query, fetch=self.VULNS.__getitem__)


def run_main(argv):
    """ledger.main(argv) -> (exit code, stdout)."""
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = ledger.main(argv)
    return code, out.getvalue()


class FakeAPI:
    """GitHub, OSV, KEV and EUVD stand-in on 127.0.0.1.

    routes maps (method, path) to (status, payload) or to a function of the
    request returning one; a route without the query string matches any query.
    Payloads that are not bytes are sent as JSON. Every request is recorded.
    """

    def __init__(self):
        self.routes = {}
        self.requests = []
        api = self

        class Handler(BaseHTTPRequestHandler):
            def serve(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                req = {
                    "method": self.command,
                    "path": self.path,
                    "headers": dict(self.headers),
                    "json": json.loads(body) if body else None,
                }
                api.requests.append(req)
                route = api.routes.get((self.command, self.path)) or api.routes.get(
                    (self.command, self.path.split("?", 1)[0]),
                    (404, {"message": "Not Found"}),
                )
                status, payload = route(req) if callable(route) else route
                if not isinstance(payload, bytes):
                    payload = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = serve

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(
            target=self.server.serve_forever, args=(0.01,), daemon=True
        ).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def paths(self, method="GET"):
        return [r["path"] for r in self.requests if r["method"] == method]


class ServerTest(unittest.TestCase):
    """Base: a FakeAPI as GitHub (/) and OSV (/osv), GitHub env vars cleared."""

    def setUp(self):
        self.api = FakeAPI()
        self.addCleanup(self.api.close)
        for name, value in (
            ("GITHUB_API", self.api.url),
            ("OSV_API", self.api.url + "/osv"),
        ):
            patcher = mock.patch.object(ledger, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        env = mock.patch.dict(os.environ)
        env.start()
        self.addCleanup(env.stop)
        for name in (
            "GITHUB_TOKEN",
            "GITHUB_REPOSITORY",
            "GITHUB_SHA",
            "GITHUB_STEP_SUMMARY",
        ):
            os.environ.pop(name, None)


class PurlTest(unittest.TestCase):
    def test_cyclonedx_nested(self):
        self.assertEqual(
            ledger.purls(load("cyclonedx.json")),
            [
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "pkg:maven/org.apache.commons/commons-text@1.10.0",
                LOG4J,
            ],
        )

    def test_spdx(self):
        self.assertEqual(len(ledger.purls(load("spdx.json"))), 3)

    def test_versioned_skips_ranges(self):
        got = [p for p in ledger.purls(load("spdx.json")) if ledger.versioned(p)]
        self.assertEqual(got, ["pkg:npm/lodash@4.17.20"])
        self.assertFalse(ledger.versioned("pkg:npm/lodash"))
        self.assertTrue(ledger.versioned("pkg:deb/debian/curl@7.88.1-10?arch=amd64"))

    def test_format(self):
        self.assertEqual(ledger.sbom_format(load("cyclonedx.json")), "CycloneDX 1.6")
        self.assertEqual(ledger.sbom_format(load("spdx.json")), "SPDX-2.3")
        with self.assertRaises(ValueError):
            ledger.sbom_format({"hello": 1})

    def test_attestable(self):
        self.assertIsNone(ledger.attestation_problem(load("cyclonedx.json")))
        self.assertIsNone(ledger.attestation_problem(load("spdx.json")))
        bare = {"bomFormat": "CycloneDX", "specVersion": "1.6"}
        self.assertIn("serialNumber", ledger.attestation_problem(bare))


class CheckTest(unittest.TestCase):
    def test_exploited_flagged(self):
        kev = {v["cveID"]: v for v in load("kev.json")["vulnerabilities"]}
        osv = FakeOSV()
        findings, checked = ledger.check_sbom(
            load("cyclonedx.json"), osv, {"CISA KEV": kev}
        )
        self.assertEqual(checked, 3)
        by_cve = {f["cves"][0]: f for f in findings}
        self.assertEqual(by_cve["CVE-2021-44228"]["exploited"], ["CISA KEV"])
        self.assertEqual(by_cve["CVE-2021-44832"]["exploited"], [])

    def test_two_sources(self):
        osv = FakeOSV()
        exploited = {
            "CISA KEV": {"CVE-2021-44228": {}},
            "ENISA EUVD": {"CVE-2021-44228": {}},
        }
        findings, _ = ledger.check_sbom(load("cyclonedx.json"), osv, exploited)
        hit = next(f for f in findings if f["exploited"])
        self.assertEqual(hit["exploited"], ["CISA KEV", "ENISA EUVD"])

    def test_report_and_issue_text(self):
        kev = {v["cveID"]: v for v in load("kev.json")["vulnerabilities"]}
        findings, checked = ledger.check_sbom(
            load("cyclonedx.json"), FakeOSV(), {"CISA KEV": kev}
        )
        rows = [
            {
                "version": "1.2.0",
                "support_until": "2031-12-31",
                "checked": checked,
                "findings": findings,
            }
        ]
        md = ledger.report(rows, dt.date(2026, 10, 17))
        self.assertIn("| 1.2.0 | 2031-12-31 | 3 | 2 | **1** |", md)
        hit = next(f for f in findings if f["exploited"])
        title = ledger.issue_title("1.2.0", hit, "CVE-2021-44228")
        self.assertEqual(
            title,
            "CRA: actively exploited CVE-2021-44228 in 1.2.0 (pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1)",
        )
        body = ledger.issue_body(
            "1.2.0",
            {"support_until": "2031-12-31"},
            hit,
            "CVE-2021-44228",
            {"CISA KEV": kev},
        )
        self.assertIn("24 hours", body)
        self.assertIn(ledger.ENISA_SRP, body)
        self.assertIn("2021-12-10", body)


class RecordTest(unittest.TestCase):
    def args(self, **kw):
        base = {
            "product": "demo",
            "version": "1.2.0",
            "support_until": "2031-12-31",
            "sbom": str(FIX / "cyclonedx.json"),
            "subject": [str(FIX / "spdx.json")],
            "attestation": ["https://github.com/o/r/attestations/1", ""],
            "security_policy": "SECURITY.md",
            "repo": "o/r",
            "commit": "abc123",
        }
        base.update(kw)
        return argparse.Namespace(**base)

    def test_evidence(self):
        now = dt.datetime(2026, 10, 17, 12, 0, tzinfo=dt.timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            policy = pathlib.Path(d, "SECURITY.md")
            policy.write_text("report here")
            ev = ledger.build_evidence(self.args(security_policy=str(policy)), now=now)
        self.assertEqual(ev["schema"], "release-ledger/v1")
        self.assertEqual(ev["released_at"], "2026-10-17T12:00:00Z")
        self.assertEqual(ev["sbom"]["packages"], 3)
        self.assertEqual(ev["sbom"]["format"], "CycloneDX 1.6")
        self.assertEqual(len(ev["sbom"]["sha256"]), 64)
        self.assertEqual(ev["subjects"][0]["name"], "spdx.json")
        self.assertEqual(ev["attestations"], ["https://github.com/o/r/attestations/1"])
        self.assertTrue(
            ev["security_policy"].startswith("https://github.com/o/r/blob/abc123/")
        )

    def test_missing_policy_is_none(self):
        ev = ledger.build_evidence(self.args(security_policy="no-such-file.md"))
        self.assertIsNone(ev["security_policy"])

    def test_support_period_must_be_future(self):
        with self.assertRaises(ValueError):
            ledger.build_evidence(self.args(support_until="2020-01-01"))


class MonitorTest(unittest.TestCase):
    """monitor --sbom end to end, with OSV stubbed and KEV read from a file:// URL."""

    def setUp(self):
        fake = FakeOSV()
        self.saved = (ledger.osv_query, ledger.http_json)
        ledger.osv_query = fake.query
        real = ledger.http_json

        def http_json(url, **kw):
            if url.startswith(ledger.OSV_API + "/vulns/"):
                return FakeOSV.VULNS[url.rsplit("/", 1)[1]]
            return real(url, **kw)

        ledger.http_json = http_json

    def tearDown(self):
        ledger.osv_query, ledger.http_json = self.saved

    def run_monitor(self, *extra):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d, "findings.json")
            code = ledger.main(
                [
                    "monitor",
                    "--sbom",
                    str(FIX / "cyclonedx.json"),
                    "--version",
                    "1.2.0",
                    "--kev-url",
                    (FIX / "kev.json").as_uri(),
                    "--no-euvd",
                    "--out",
                    str(out),
                    *extra,
                ]
            )
            return code, json.loads(out.read_text())

    def test_fails_on_exploited(self):
        code, data = self.run_monitor()
        self.assertEqual(code, 1)
        self.assertEqual(len(data["releases"][0]["findings"]), 2)

    def test_never(self):
        code, _ = self.run_monitor("--fail-on", "never")
        self.assertEqual(code, 0)


class HttpTest(ServerTest):
    def test_get_sends_token_and_accept(self):
        self.api.routes[("GET", "/blob")] = (200, b"raw bytes")
        body = ledger.http(
            self.api.url + "/blob", token="t0k", accept="application/octet-stream"
        )
        self.assertEqual(body, b"raw bytes")
        req = self.api.requests[0]
        self.assertEqual(req["headers"]["Authorization"], "Bearer t0k")
        self.assertEqual(req["headers"]["Accept"], "application/octet-stream")
        self.assertEqual(req["headers"]["User-Agent"], ledger.USER_AGENT)
        self.assertIsNone(req["json"])

    def test_post_json_without_token(self):
        self.api.routes[("POST", "/echo")] = lambda req: (201, req["json"])
        got = ledger.http_json(self.api.url + "/echo", data={"a": [1]}, method="POST")
        self.assertEqual(got, {"a": [1]})
        req = self.api.requests[0]
        self.assertEqual(req["method"], "POST")
        self.assertEqual(req["headers"]["Content-Type"], "application/json")
        self.assertNotIn("Authorization", req["headers"])

    def test_error_status_raises(self):
        self.api.routes[("GET", "/down")] = (503, {"message": "down"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            ledger.http(self.api.url + "/down")
        self.assertEqual(cm.exception.code, 503)
        cm.exception.close()


class GithubPagesTest(ServerTest):
    def test_follows_full_pages_until_empty(self):
        self.api.routes[("GET", "/items?per_page=100&page=1")] = (
            200,
            list(range(100)),
        )
        self.api.routes[("GET", "/items?per_page=100&page=2")] = (200, [])
        self.assertEqual(list(ledger.github_pages("/items", "t")), list(range(100)))
        self.assertEqual(
            self.api.paths(),
            ["/items?per_page=100&page=1", "/items?per_page=100&page=2"],
        )
        self.assertEqual(self.api.requests[0]["headers"]["Authorization"], "Bearer t")

    def test_short_page_is_the_last(self):
        self.api.routes[("GET", "/items?state=all&per_page=100&page=1")] = (
            200,
            ["a", "b"],
        )
        self.assertEqual(
            list(ledger.github_pages("/items?state=all", None)), ["a", "b"]
        )
        self.assertEqual(len(self.api.requests), 1)


class SbomCheckTest(unittest.TestCase):
    def test_problems(self):
        self.assertEqual(
            ledger.attestation_problem({"hello": 1}),
            "not a CycloneDX or SPDX JSON document",
        )
        self.assertEqual(
            ledger.attestation_problem({"spdxVersion": "SPDX-2.3"}),
            "SPDX SBOM has no SPDXID",
        )

    def test_spdx_ignores_other_refs(self):
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "externalRefs": [
                        {"referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:a"},
                        {"referenceType": "purl", "referenceLocator": "pkg:npm/a@1"},
                        {"referenceType": "purl", "referenceLocator": ""},
                    ]
                },
                {},
            ],
        }
        self.assertEqual(ledger.purls(sbom), ["pkg:npm/a@1"])

    def test_cli_ok(self):
        sbom = str(FIX / "spdx.json")
        self.assertEqual(run_main(["sbom-check", sbom]), (0, f"{sbom}: ok\n"))

    def test_cli_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            sbom = pathlib.Path(d, "bare.json")
            sbom.write_text(json.dumps({"bomFormat": "CycloneDX"}))
            with self.assertRaises(SystemExit) as cm:
                run_main(["sbom-check", str(sbom)])
        self.assertEqual(
            cm.exception.code,
            f"{sbom}: CycloneDX SBOM has no serialNumber (urn:uuid:...). "
            "SBOM attestations need it.",
        )


class SbomExportTest(ServerTest):
    ROUTE = ("GET", "/repos/o/r/dependency-graph/sbom")

    def setUp(self):
        super().setUp()
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.out = pathlib.Path(d.name, "sbom.json")

    def export(self, *extra):
        code, stdout = run_main(["sbom-export", "--out", str(self.out), *extra])
        return code, stdout, self.out

    def test_writes_sbom(self):
        self.api.routes[self.ROUTE] = (200, {"sbom": load("spdx.json")})
        code, stdout, out = self.export("--repo", "o/r", "--token", "t")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.read_text()), load("spdx.json"))
        self.assertTrue(out.read_text().endswith("}\n"))
        self.assertEqual(
            stdout, f"{out}: 3 packages from the dependency graph of o/r\n"
        )
        self.assertEqual(self.api.requests[0]["headers"]["Authorization"], "Bearer t")

    def test_repo_and_token_from_env(self):
        os.environ.update(GITHUB_REPOSITORY="o/r", GITHUB_TOKEN="env-token")
        self.api.routes[self.ROUTE] = (200, {"sbom": load("cyclonedx.json")})
        code, _, out = self.export()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.read_text())["bomFormat"], "CycloneDX")
        self.assertEqual(
            self.api.requests[0]["headers"]["Authorization"], "Bearer env-token"
        )

    def test_repo_required_without_env(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as cm:
            self.export()
        self.assertEqual(cm.exception.code, 2)
        self.assertIn("--repo", err.getvalue())

    def test_no_dependency_graph(self):
        for status in (403, 404):
            with self.subTest(status=status):
                self.api.routes[self.ROUTE] = (status, {"message": "nope"})
                with self.assertRaises(SystemExit) as cm:
                    self.export("--repo", "o/r")
                self.assertIn(
                    f"No dependency-graph SBOM for o/r (HTTP {status})",
                    cm.exception.code,
                )
                self.assertFalse(self.out.exists())
                cm.exception.__context__.close()  # the HTTPError it reports

    def test_other_errors_propagate(self):
        self.api.routes[self.ROUTE] = (500, {"message": "boom"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            self.export("--repo", "o/r")
        self.assertEqual(cm.exception.code, 500)
        cm.exception.close()


class RecordCliTest(unittest.TestCase):
    def record(self, d, *extra):
        out = pathlib.Path(d, "cra-evidence.json")
        code, stdout = run_main(
            [
                "record",
                "--product",
                "demo",
                "--version",
                "1.2.0",
                "--support-until",
                "2099-12-31",
                "--sbom",
                str(FIX / "cyclonedx.json"),
                "--repo",
                "o/r",
                "--commit",
                "abc123",
                "--out",
                str(out),
                *extra,
            ]
        )
        return code, stdout, json.loads(out.read_text())

    def test_warns_about_missing_policy_and_attestation(self):
        with tempfile.TemporaryDirectory() as d:
            code, stdout, ev = self.record(
                d, "--security-policy", str(pathlib.Path(d, "SECURITY.md"))
            )
        self.assertEqual(code, 0)
        self.assertEqual(ev["version"], "1.2.0")
        self.assertIsNone(ev["security_policy"])
        self.assertEqual(ev["attestations"], [])
        self.assertIn('"product": "demo"', stdout)
        self.assertIn("SECURITY.md not found", stdout)
        self.assertIn("::notice::No signed attestation recorded", stdout)

    def test_quiet_when_complete(self):
        with tempfile.TemporaryDirectory() as d:
            policy = pathlib.Path(d, "SECURITY.md")
            policy.write_text("report here")
            subject = pathlib.Path(d, "app.tar.gz")
            subject.write_bytes(b"release")
            code, stdout, ev = self.record(
                d,
                "--security-policy",
                str(policy),
                "--subject",
                str(subject),
                "--attestation",
                "https://github.com/o/r/attestations/9",
            )
        self.assertEqual(code, 0)
        self.assertEqual(ev["attestations"], ["https://github.com/o/r/attestations/9"])
        self.assertEqual(
            ev["subjects"],
            [
                {
                    "name": "app.tar.gz",
                    "sha256": "a4d451ec23463726f72c43d64c710968f6b602cd653b4de8adee1b556240a829",
                }
            ],
        )
        self.assertNotIn("::warning::", stdout)
        self.assertNotIn("::notice::", stdout)


class FeedsTest(ServerTest):
    def test_euvd_list(self):
        self.api.routes[("GET", "/euvd?size=100&page=0")] = (
            200,
            [
                {"id": "EUVD-1", "aliases": "GHSA-xxxx CVE-2021-44228\n"},
                {"id": "EUVD-2", "aliases": None},
            ],
        )
        got = ledger.load_euvd(self.api.url + "/euvd")
        self.assertEqual(list(got), ["CVE-2021-44228"])
        self.assertEqual(got["CVE-2021-44228"]["id"], "EUVD-1")
        self.assertEqual(len(self.api.requests), 1)

    def test_euvd_pages(self):
        first = [{"aliases": f"CVE-2024-{i:04d}"} for i in range(100)]
        self.api.routes[("GET", "/euvd?size=100&page=0")] = (200, {"items": first})
        self.api.routes[("GET", "/euvd?size=100&page=1")] = (
            200,
            {"items": [{"aliases": "CVE-2025-0001"}]},
        )
        got = ledger.load_euvd(self.api.url + "/euvd")
        self.assertEqual(len(got), 101)
        self.assertIn("CVE-2025-0001", got)
        self.assertEqual(len(self.api.requests), 2)

    def test_osv_batches(self):
        def querybatch(req):
            results = []
            for q in req["json"]["queries"]:
                purl = q["package"]["purl"]
                results.append({"vulns": [{"id": "GHSA-1"}]} if purl == LOG4J else {})
            return 200, {"results": results}

        self.api.routes[("POST", "/osv/querybatch")] = querybatch
        purl_list = ["pkg:npm/a@1", "pkg:npm/b@2", LOG4J]
        with mock.patch.object(ledger, "OSV_BATCH", 2):
            got = ledger.osv_query(purl_list)
        self.assertEqual(got, {LOG4J: ["GHSA-1"]})
        sent = [
            [q["package"]["purl"] for q in r["json"]["queries"]]
            for r in self.api.requests
        ]
        self.assertEqual(sent, [purl_list[:2], purl_list[2:]])

    def test_osv_vuln_is_fetched_once(self):
        vuln = FakeOSV.VULNS["GHSA-jfh8-c2jp-5v3q"]
        self.api.routes[("GET", "/osv/vulns/GHSA-jfh8-c2jp-5v3q")] = (200, vuln)
        osv = ledger.OSV()
        self.assertEqual(osv.vuln("GHSA-jfh8-c2jp-5v3q"), vuln)
        self.assertEqual(osv.vuln("GHSA-jfh8-c2jp-5v3q"), vuln)
        self.assertEqual(len(self.api.requests), 1)


class OpenIssueTest(ServerTest):
    TITLE = "CRA: actively exploited CVE-2021-44228 in 1.2.0 (pkg:maven/x/y@1)"

    def search(self, *titles):
        self.api.routes[("GET", "/search/issues")] = (
            200,
            {
                "items": [
                    {"title": t, "html_url": f"u/{i}"} for i, t in enumerate(titles)
                ]
            },
        )

    def test_reuses_existing_issue(self):
        self.search(self.TITLE + " (old)", self.TITLE)
        url = ledger.open_issue("o/r", "t", self.TITLE, "body")
        self.assertEqual(url, "u/1")
        self.assertEqual(self.api.paths("POST"), [])
        query = urllib.parse.unquote(self.api.requests[0]["path"].split("q=", 1)[1])
        self.assertEqual(query, f'repo:o/r is:issue in:title "{self.TITLE}"')

    def test_creates_labelled_issue(self):
        self.search()
        self.api.routes[("POST", "/repos/o/r/issues")] = (201, {"html_url": "u/new"})
        self.assertEqual(ledger.open_issue("o/r", "t", self.TITLE, "body"), "u/new")
        post = self.api.requests[-1]
        self.assertEqual(
            post["json"], {"title": self.TITLE, "body": "body", "labels": ["cra"]}
        )
        self.assertEqual(post["headers"]["Authorization"], "Bearer t")

    def test_retries_without_label(self):
        self.search()
        replies = [(422, {"message": "Validation Failed"}), (201, {"html_url": "u/9"})]
        self.api.routes[("POST", "/repos/o/r/issues")] = lambda req: replies.pop(0)
        self.assertEqual(ledger.open_issue("o/r", "t", self.TITLE, "body"), "u/9")
        posts = [r["json"] for r in self.api.requests if r["method"] == "POST"]
        self.assertEqual(posts[0]["labels"], ["cra"])
        self.assertEqual(posts[1], {"title": self.TITLE, "body": "body"})

    def test_other_errors_propagate(self):
        self.search()
        self.api.routes[("POST", "/repos/o/r/issues")] = (403, {"message": "no"})
        with self.assertRaises(urllib.error.HTTPError) as cm:
            ledger.open_issue("o/r", "t", self.TITLE, "body")
        self.assertEqual(cm.exception.code, 403)
        cm.exception.close()
        self.assertEqual(len(self.api.paths("POST")), 1)


class ReportTest(unittest.TestCase):
    def test_nothing_in_support(self):
        self.assertEqual(
            ledger.report([], dt.date(2026, 10, 22)),
            "## release-ledger: 2026-10-22\n\n"
            "No release with cra-evidence.json is in its support period.\n",
        )

    def test_section_only_for_exploited(self):
        finding = {"purl": LOG4J, "cves": ["CVE-2021-44228"], "exploited": []}
        rows = [
            {
                "version": "1.0.0",
                "support_until": "2030-01-01",
                "checked": 1,
                "findings": [finding],
            },
            {
                "version": "2.0.0",
                "support_until": "2031-01-01",
                "checked": 1,
                "findings": [dict(finding, exploited=["ENISA EUVD"])],
            },
        ]
        md = ledger.report(rows, dt.date(2026, 10, 22))
        self.assertIn("| 1.0.0 | 2030-01-01 | 1 | 1 | 0 |", md)
        self.assertIn("| 2.0.0 | 2031-01-01 | 1 | 1 | **1** |", md)
        self.assertNotIn("### 1.0.0", md)
        self.assertIn(
            f"### 2.0.0: actively exploited\n\n- CVE-2021-44228 in `{LOG4J}` (ENISA EUVD)",
            md,
        )

    def test_issue_body_without_kev(self):
        finding = {
            "purl": LOG4J,
            "id": "GHSA-jfh8-c2jp-5v3q",
            "summary": "",
            "exploited": ["ENISA EUVD"],
        }
        body = ledger.issue_body(
            "1.2.0",
            {"support_until": "2031-12-31"},
            finding,
            "CVE-2021-44228",
            {"ENISA EUVD": {"CVE-2021-44228": {}}},
        )
        self.assertIn("listed as actively exploited by: ENISA EUVD.", body)
        self.assertIn("until **2031-12-31**", body)
        self.assertNotIn("CISA KEV", body)
        self.assertNotIn("> ", body)


class MonitorReleasesTest(ServerTest):
    """monitor against a repository's releases, every service on FakeAPI."""

    def setUp(self):
        super().setUp()
        api, url = self.api, self.api.url
        api.routes[("GET", "/kev.json")] = (200, load("kev.json"))
        api.routes[("GET", "/euvd?size=100&page=0")] = (
            200,
            [{"id": "EUVD-2021-1", "aliases": "CVE-2021-44228"}],
        )

        def querybatch(req):
            purls = [q["package"]["purl"] for q in req["json"]["queries"]]
            vulns = [{"id": v} for v in FakeOSV.VULNS]
            return 200, {
                "results": [{"vulns": vulns} if p == LOG4J else {} for p in purls]
            }

        api.routes[("POST", "/osv/querybatch")] = querybatch
        for vid, vuln in FakeOSV.VULNS.items():
            api.routes[("GET", f"/osv/vulns/{vid}")] = (200, vuln)

        def release(n, tag, support_until, sbom_name="sbom.cdx.json", **kw):
            evidence = {
                "version": tag.lstrip("v"),
                "support_until": support_until,
                "sbom": {"file": sbom_name},
            }
            api.routes[("GET", f"/assets/{n}/evidence")] = (
                200,
                json.dumps(evidence).encode(),
            )
            api.routes[("GET", f"/assets/{n}/sbom")] = (
                200,
                (FIX / "cyclonedx.json").read_bytes(),
            )
            assets = [
                {"name": ledger.EVIDENCE_NAME, "url": f"{url}/assets/{n}/evidence"},
                {"name": "sbom.cdx.json", "url": f"{url}/assets/{n}/sbom"},
            ]
            return dict({"tag_name": tag, "assets": assets}, **kw)

        api.routes[("GET", "/repos/o/r/releases?per_page=100&page=1")] = (
            200,
            [
                release(1, "v2.0.0-rc1", "2031-12-31", draft=True),
                {"tag_name": "v0.1.0", "assets": []},
                release(2, "v0.9.0", "2026-10-21"),
                release(3, "v1.1.0", "2030-06-30", sbom_name="gone.cdx.json"),
                release(4, "v1.2.0", "2031-12-31"),
            ],
        )
        api.routes[("GET", "/search/issues")] = (200, {"items": []})
        api.routes[("POST", "/repos/o/r/issues")] = (201, {"html_url": "u/42"})

    def monitor(self, *extra):
        return run_main(
            [
                "monitor",
                "--repo",
                "o/r",
                "--token",
                "t",
                "--today",
                "2026-10-22",
                "--kev-url",
                self.api.url + "/kev.json",
                "--euvd-url",
                self.api.url + "/euvd",
                *extra,
            ]
        )

    def test_opens_issue_for_exploited_cve(self):
        with tempfile.TemporaryDirectory() as d:
            summary = pathlib.Path(d, "summary.md")
            summary.write_text("earlier step\n")
            os.environ["GITHUB_STEP_SUMMARY"] = str(summary)
            out = pathlib.Path(d, "findings.json")
            code, stdout = self.monitor("--out", str(out))
            data = json.loads(out.read_text())
            summary_text = summary.read_text()

        self.assertEqual(code, 1)
        self.assertIn(
            "::warning::v1.1.0: evidence names an SBOM asset that is missing.", stdout
        )
        self.assertEqual(data["date"], "2026-10-22")
        [row] = data["releases"]  # draft, no evidence, expired, no SBOM: skipped
        self.assertEqual(row["version"], "1.2.0")
        self.assertEqual(row["checked"], 3)
        self.assertEqual(row["issues"], ["u/42"])
        exploited = {f["id"]: f["exploited"] for f in row["findings"]}
        self.assertEqual(
            exploited,
            {
                "GHSA-jfh8-c2jp-5v3q": ["CISA KEV", "ENISA EUVD"],
                "GHSA-8489-44mv-ggj8": [],
            },
        )
        report = ledger.report(data["releases"], dt.date(2026, 10, 22))
        self.assertIn(report, stdout)
        self.assertEqual(summary_text, "earlier step\n" + report)

        gets = self.api.paths()
        self.assertNotIn("/assets/1/evidence", gets)  # the draft
        self.assertNotIn("/assets/2/sbom", gets)  # out of support
        self.assertIn("/assets/4/sbom", gets)
        asset_req = next(r for r in self.api.requests if r["path"] == "/assets/4/sbom")
        self.assertEqual(asset_req["headers"]["Accept"], "application/octet-stream")
        self.assertEqual(asset_req["headers"]["Authorization"], "Bearer t")
        [post] = [
            r
            for r in self.api.requests
            if r["method"] == "POST" and "issues" in r["path"]
        ]
        self.assertEqual(
            post["json"]["title"],
            f"CRA: actively exploited CVE-2021-44228 in 1.2.0 ({LOG4J})",
        )
        self.assertIn("CISA KEV added it on 2021-12-10", post["json"]["body"])

    def test_euvd_down_and_no_issues(self):
        self.api.routes[("GET", "/euvd?size=100&page=0")] = (502, {"message": "bad"})
        code, stdout = self.monitor("--no-open-issues", "--fail-on", "any")
        self.assertEqual(code, 1)
        self.assertIn("::warning::ENISA EUVD not reachable (HTTP Error 502", stdout)
        self.assertIn("| 1.2.0 | 2031-12-31 | 3 | 2 | **1** |", stdout)
        self.assertIn("(CISA KEV)", stdout)
        self.assertNotIn("ENISA EUVD)", stdout)
        self.assertEqual(self.api.paths("POST"), ["/osv/querybatch"])
        self.assertNotIn("/search/issues", [p.split("?")[0] for p in self.api.paths()])

    def test_nothing_found_passes(self):
        self.api.routes[("POST", "/osv/querybatch")] = (200, {"results": []})
        code, stdout = self.monitor("--no-euvd")
        self.assertEqual(code, 0)
        self.assertIn("| 1.2.0 | 2031-12-31 | 3 | 0 | 0 |", stdout)
        self.assertNotIn("/euvd", [p.split("?")[0] for p in self.api.paths()])


class ScriptTest(unittest.TestCase):
    """`python ledger.py ...` exits with main()'s result."""

    def run_script(self, *argv):
        out = io.StringIO()
        argv_patch = mock.patch.object(sys, "argv", ["ledger.py", *argv])
        argv_patch.start()
        self.addCleanup(argv_patch.stop)
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            runpy.run_path(str(HERE.parent / "ledger.py"), run_name="__main__")
        return cm.exception.code, out.getvalue()

    def test_exit_status(self):
        sbom = str(FIX / "cyclonedx.json")
        self.assertEqual(self.run_script("sbom-check", sbom), (0, f"{sbom}: ok\n"))


if __name__ == "__main__":
    unittest.main()

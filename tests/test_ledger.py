"""Offline tests: no network, OSV and the exploited lists are stubbed."""

import argparse
import datetime as dt
import json
import pathlib
import sys
import tempfile
import unittest
from typing import ClassVar

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


class RedirectTest(unittest.TestCase):
    """The token goes to the host it was meant for, never to a redirect target."""

    def auth_seen_after_redirect(self, target_host):
        import http.server
        import threading

        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            # /asset answers like the GitHub API does for a release asset: a
            # redirect to the storage host, which serves the bytes.
            def do_GET(self):
                if self.path == "/asset":
                    port = self.server.server_port
                    self.send_response(302)
                    self.send_header("Location", f"http://{target_host}:{port}/blob")
                    self.end_headers()
                    return
                seen["auth"] = self.headers.get("Authorization")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"asset")

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        body = ledger.http(
            f"http://127.0.0.1:{server.server_port}/asset", token="SECRET"
        )
        self.assertEqual(body, b"asset")
        return seen["auth"]

    def test_token_not_sent_to_another_host(self):
        self.assertIsNone(self.auth_seen_after_redirect("localhost"))

    def test_token_kept_on_the_same_host(self):
        self.assertEqual(self.auth_seen_after_redirect("127.0.0.1"), "Bearer SECRET")


if __name__ == "__main__":
    unittest.main()

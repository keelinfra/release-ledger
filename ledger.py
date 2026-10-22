#!/usr/bin/env python3
"""release-ledger: EU Cyber Resilience Act evidence for every release.

Subcommands:
  sbom-export  Write the repository's SBOM from GitHub's dependency graph.
  record       Write cra-evidence.json for one release.
  monitor      Check every release still in its support period for known
               vulnerabilities, and flag the ones known to be exploited.

Standard library only, so it runs on any runner with Python 3.9 or newer.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

SCHEMA = "release-ledger/v1"
EVIDENCE_NAME = "cra-evidence.json"
USER_AGENT = "keelinfra-release-ledger/1 (+https://github.com/keelinfra/release-ledger)"
GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
OSV_API = "https://api.osv.dev/v1"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EUVD_URL = "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
ENISA_SRP = "https://portal.cra-srp.enisa.europa.eu"
OSV_BATCH = 1000


# --- HTTP ------------------------------------------------------------------


class _SameHostAuth(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but send the token only to the host it was meant for.

    urllib copies every header onto the redirected request, so a release asset
    download (api.github.com answers with a redirect to a storage host) would
    hand the token to that storage host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            old_url = urllib.parse.urlsplit(req.full_url)
            new_url = urllib.parse.urlsplit(new.full_url)
            if (old_url.scheme, old_url.netloc) != (new_url.scheme, new_url.netloc):
                new.remove_header("Authorization")
        return new


_opener = urllib.request.build_opener(_SameHostAuth)


def http(url, data=None, token=None, accept="application/json", method=None):
    """Return the response body as bytes."""
    headers = {"User-Agent": USER_AGENT, "Accept": accept}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with _opener.open(req, timeout=60) as resp:
        return resp.read()


def http_json(url, **kw):
    return json.loads(http(url, **kw))


def github_pages(path, token):
    """Yield items from a paginated GitHub list endpoint."""
    page = 1
    while True:
        sep = "&" if "?" in path else "?"
        items = http_json(
            f"{GITHUB_API}{path}{sep}per_page=100&page={page}", token=token
        )
        if not items:
            return
        yield from items
        if len(items) < 100:
            return
        page += 1


# --- SBOM ------------------------------------------------------------------


def sbom_format(sbom):
    if sbom.get("bomFormat") == "CycloneDX":
        return "CycloneDX " + str(sbom.get("specVersion", "?"))
    if "spdxVersion" in sbom:
        return sbom["spdxVersion"]
    raise ValueError("not a CycloneDX or SPDX JSON document")


def attestation_problem(sbom):
    """Why actions/attest would refuse this SBOM, or None.

    It wants a CycloneDX serialNumber, or an SPDX SPDXID, besides the format.
    """
    try:
        sbom_format(sbom)
    except ValueError as e:
        return str(e)
    if sbom.get("bomFormat") == "CycloneDX" and not sbom.get("serialNumber"):
        return "CycloneDX SBOM has no serialNumber (urn:uuid:...)"
    if "spdxVersion" in sbom and not sbom.get("SPDXID"):
        return "SPDX SBOM has no SPDXID"
    return None


def cmd_sbom_check(args):
    with open(args.sbom) as f:
        problem = attestation_problem(json.load(f))
    if problem:
        sys.exit(f"{args.sbom}: {problem}. SBOM attestations need it.")
    print(f"{args.sbom}: ok")


def purls(sbom):
    """Every package URL in a CycloneDX or SPDX JSON SBOM, de-duplicated."""
    found = []
    if sbom.get("bomFormat") == "CycloneDX":
        stack = list(sbom.get("components", []))
        while stack:
            c = stack.pop()
            if c.get("purl"):
                found.append(c["purl"])
            stack.extend(c.get("components", []))
    else:
        for pkg in sbom.get("packages", []):
            for ref in pkg.get("externalRefs", []):
                if ref.get("referenceType") == "purl" and ref.get("referenceLocator"):
                    found.append(ref["referenceLocator"])
    return sorted(set(found))


def versioned(purl):
    """True when the purl names one exact version, which is all OSV can match."""
    if "@" not in purl:
        return False
    version = purl.rsplit("@", 1)[1].split("?", 1)[0].split("#", 1)[0]
    version = urllib.parse.unquote(version)
    return bool(version) and not any(ch in version for ch in "^~<>*= ,|")


def cmd_sbom_export(args):
    try:
        data = http_json(
            f"{GITHUB_API}/repos/{args.repo}/dependency-graph/sbom", token=args.token
        )
    except urllib.error.HTTPError as e:
        if e.code not in (403, 404):
            raise
        sys.exit(
            f"No dependency-graph SBOM for {args.repo} (HTTP {e.code}). Turn on the"
            " dependency graph (Settings > Advanced Security), or pass an SBOM from"
            " your build with `sbom:`."
        )
    with open(args.out, "w") as f:
        json.dump(data["sbom"], f, indent=2)
        f.write("\n")
    print(
        f"{args.out}: {len(purls(data['sbom']))} packages from the dependency graph of {args.repo}"
    )


# --- record ----------------------------------------------------------------


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def parse_date(text):
    return dt.date.fromisoformat(text)


def build_evidence(args, now=None):
    with open(args.sbom) as f:
        sbom = json.load(f)
    released = now or dt.datetime.now(dt.timezone.utc)
    support_until = parse_date(args.support_until)
    if support_until <= released.date():
        raise ValueError(f"support-until {support_until} is not in the future")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    repo_url = f"{server}/{args.repo}" if args.repo else None
    evidence = {
        "schema": SCHEMA,
        "product": args.product,
        "version": args.version,
        "repository": repo_url,
        "commit": args.commit,
        "released_at": released.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "support_until": support_until.isoformat(),
        "sbom": {
            "file": os.path.basename(args.sbom),
            "format": sbom_format(sbom),
            "sha256": sha256(args.sbom),
            "packages": len(purls(sbom)),
        },
        "subjects": [
            {"name": os.path.basename(p), "sha256": sha256(p)} for p in args.subject
        ],
        "attestations": [u for u in args.attestation if u],
        "security_policy": None,
    }
    if args.security_policy and os.path.exists(args.security_policy) and repo_url:
        evidence["security_policy"] = (
            f"{repo_url}/blob/{args.commit}/{args.security_policy}"
        )
    return evidence


def cmd_record(args):
    evidence = build_evidence(args)
    with open(args.out, "w") as f:
        json.dump(evidence, f, indent=2)
        f.write("\n")
    print(json.dumps(evidence, indent=2))
    if not evidence["security_policy"]:
        print(
            f"::warning::{args.security_policy} not found: the CRA asks for a published "
            "vulnerability disclosure policy (Annex I part II)."
        )
    if not evidence["attestations"]:
        print(
            "::notice::No signed attestation recorded: pass subject-path to attest the release files."
        )


# --- monitor ---------------------------------------------------------------


def load_kev(url):
    data = http_json(url)
    return {v["cveID"]: v for v in data["vulnerabilities"]}


def load_euvd(url):
    """CVE id -> EUVD entry, for vulnerabilities ENISA lists as exploited."""
    out = {}
    page = 0
    while True:
        data = http_json(f"{url}?size=100&page={page}")
        items = data if isinstance(data, list) else data.get("items", [])
        for item in items:
            for alias in (item.get("aliases") or "").split():
                if alias.startswith("CVE-"):
                    out[alias] = item
        if isinstance(data, list) or len(items) < 100:
            return out
        page += 1


def osv_query(purl_list):
    """purl -> list of OSV vulnerability ids."""
    result = {}
    for i in range(0, len(purl_list), OSV_BATCH):
        chunk = purl_list[i : i + OSV_BATCH]
        resp = http_json(
            f"{OSV_API}/querybatch",
            data={"queries": [{"package": {"purl": p}} for p in chunk]},
        )
        for p, r in zip(chunk, resp.get("results", [])):
            ids = [v["id"] for v in r.get("vulns", [])]
            if ids:
                result[p] = ids
    return result


class OSV:
    def __init__(self, query=None, fetch=None):
        self.query = query or (lambda purl_list: osv_query(purl_list))
        self.fetch = fetch or (lambda vid: http_json(f"{OSV_API}/vulns/{vid}"))
        self.cache = {}

    def vuln(self, vid):
        if vid not in self.cache:
            self.cache[vid] = self.fetch(vid)
        return self.cache[vid]


def cve_ids(vuln):
    ids = [vuln.get("id", "")] + list(vuln.get("aliases", []))
    return sorted({i for i in ids if i.startswith("CVE-")})


def check_sbom(sbom, osv, exploited):
    """Findings for one SBOM: [{purl, id, cves, summary, exploited: [source,...]}]."""
    candidates = [p for p in purls(sbom) if versioned(p)]
    findings = []
    for purl, ids in sorted(osv.query(candidates).items()):
        for vid in ids:
            v = osv.vuln(vid)
            cves = cve_ids(v)
            sources = sorted(
                {
                    src
                    for cve in cves
                    for src, known in exploited.items()
                    if cve in known
                }
            )
            findings.append(
                {
                    "purl": purl,
                    "id": vid,
                    "cves": cves,
                    "summary": v.get("summary") or v.get("details", "")[:160],
                    "exploited": sources,
                }
            )
    return findings, len(candidates)


def evidence_releases(repo, token):
    """(release, evidence, sbom asset) for every release that carries evidence."""
    for rel in github_pages(f"/repos/{repo}/releases", token):
        if rel.get("draft"):
            continue
        assets = {a["name"]: a for a in rel.get("assets", [])}
        if EVIDENCE_NAME not in assets:
            continue
        evidence = json.loads(asset_bytes(assets[EVIDENCE_NAME], token))
        sbom_asset = assets.get(evidence.get("sbom", {}).get("file", ""))
        yield rel, evidence, sbom_asset


def asset_bytes(asset, token):
    return http(asset["url"], token=token, accept="application/octet-stream")


def issue_title(version, finding, cve):
    pkg = finding["purl"].split("?", 1)[0]
    return f"CRA: actively exploited {cve} in {version} ({pkg})"


def issue_body(version, evidence, finding, cve, exploited):
    sources = ", ".join(finding["exploited"])
    kev = exploited.get("CISA KEV", {}).get(cve)
    lines = [
        (
            f"Release **{version}** ships `{finding['purl']}`, affected by **{cve}** "
            f"([{finding['id']}](https://osv.dev/vulnerability/{finding['id']})), "
            f"which is listed as actively exploited by: {sources}."
        ),
        "",
        f"> {finding['summary']}" if finding["summary"] else "",
        "",
        (
            f"This release is in its support period until **{evidence.get('support_until')}**. "
            "If the vulnerability is exploitable in your product, the EU Cyber Resilience Act "
            "(Art. 14) asks the manufacturer to notify through ENISA's Single Reporting Platform:"
        ),
        "",
        "- [ ] Assess whether the product is affected (the clock starts once you are reasonably sure)",
        "- [ ] Early warning within **24 hours**",
        "- [ ] Notification within **72 hours**, with mitigations users can apply",
        "- [ ] Final report within **14 days** of a fix being available",
        "- [ ] Tell affected users; publish a fixed release",
        "",
        f"Reporting platform: {ENISA_SRP}",
    ]
    if kev:
        lines += [
            "",
            f"CISA KEV added it on {kev.get('dateAdded')}: {kev.get('vulnerabilityName')}.",
        ]
    lines += [
        "",
        "_Opened by [release-ledger](https://github.com/keelinfra/release-ledger)._",
    ]
    return "\n".join(lines)


def open_issue(repo, token, title, body):
    """Open the issue unless one with the same title already exists. Returns its URL."""
    q = urllib.parse.quote(f'repo:{repo} is:issue in:title "{title}"')
    found = http_json(f"{GITHUB_API}/search/issues?q={q}", token=token)
    for item in found.get("items", []):
        if item["title"] == title:
            return item["html_url"]
    issue = {"title": title, "body": body, "labels": ["cra"]}
    url = f"{GITHUB_API}/repos/{repo}/issues"
    try:
        created = http_json(url, data=issue, token=token, method="POST")
    except urllib.error.HTTPError as e:
        if e.code != 422:  # e.g. the token may not create the label
            raise
        del issue["labels"]
        created = http_json(url, data=issue, token=token, method="POST")
    return created["html_url"]


def report(rows, today):
    """Markdown summary of all checked releases."""
    out = [f"## release-ledger: {today.isoformat()}", ""]
    if not rows:
        out.append("No release with cra-evidence.json is in its support period.")
        return "\n".join(out) + "\n"
    out += [
        "| Release | Supported until | Packages checked | Known vulnerabilities | Exploited |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        exp = sum(1 for f in r["findings"] if f["exploited"])
        out.append(
            f"| {r['version']} | {r['support_until']} | {r['checked']} | {len(r['findings'])} | {'**' + str(exp) + '**' if exp else 0} |"
        )
    for r in rows:
        hits = [f for f in r["findings"] if f["exploited"]]
        if hits:
            out += ["", f"### {r['version']}: actively exploited", ""]
            for f in hits:
                out.append(
                    f"- {', '.join(f['cves'])} in `{f['purl']}` ({', '.join(f['exploited'])})"
                )
    return "\n".join(out) + "\n"


def cmd_monitor(args):
    today = (
        parse_date(args.today)
        if args.today
        else dt.datetime.now(dt.timezone.utc).date()
    )
    exploited = {}
    exploited["CISA KEV"] = load_kev(args.kev_url)
    if args.euvd:
        try:
            exploited["ENISA EUVD"] = load_euvd(args.euvd_url)
        except (urllib.error.URLError, ValueError, KeyError) as e:
            print(
                f"::warning::ENISA EUVD not reachable ({e}); checking against CISA KEV only."
            )
    osv = OSV()

    if args.sbom:
        targets = [
            (
                {
                    "version": args.version or "local",
                    "support_until": args.support_until or "-",
                },
                args.sbom,
            )
        ]
    else:
        targets = []
        for rel, evidence, sbom_asset in evidence_releases(args.repo, args.token):
            if parse_date(evidence["support_until"]) < today:
                continue
            if not sbom_asset:
                print(
                    f"::warning::{rel['tag_name']}: evidence names an SBOM asset that is missing."
                )
                continue
            targets.append((evidence, sbom_asset))

    rows = []
    for evidence, src in targets:
        if isinstance(src, str):
            with open(src) as f:
                sbom = json.load(f)
        else:
            sbom = json.loads(asset_bytes(src, args.token))
        findings, checked = check_sbom(sbom, osv, exploited)
        rows.append(
            {
                "version": evidence["version"],
                "support_until": evidence["support_until"],
                "checked": checked,
                "findings": findings,
                "issues": [],
            }
        )
        if args.open_issues and not args.sbom:
            for f in findings:
                for cve in f["cves"]:
                    if any(cve in exploited[s] for s in f["exploited"]):
                        title = issue_title(evidence["version"], f, cve)
                        url = open_issue(
                            args.repo,
                            args.token,
                            title,
                            issue_body(
                                evidence["version"], evidence, f, cve, exploited
                            ),
                        )
                        rows[-1]["issues"].append(url)

    summary = report(rows, today)
    print(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(summary)
    if args.out:
        with open(args.out, "w") as f:
            json.dump({"date": today.isoformat(), "releases": rows}, f, indent=2)
            f.write("\n")

    exploited_hits = sum(1 for r in rows for f in r["findings"] if f["exploited"])
    any_hits = sum(len(r["findings"]) for r in rows)
    if (args.fail_on == "exploited" and exploited_hits) or (
        args.fail_on == "any" and any_hits
    ):
        return 1
    return 0


# --- CLI -------------------------------------------------------------------


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")

    s = sub.add_parser("sbom-export", help="SBOM from GitHub's dependency graph")
    s.add_argument("--repo", default=repo, required=repo is None)
    s.add_argument("--token", default=token)
    s.add_argument("--out", required=True)
    s.set_defaults(func=cmd_sbom_export)

    c = sub.add_parser("sbom-check", help="check an SBOM can be attested")
    c.add_argument("sbom")
    c.set_defaults(func=cmd_sbom_check)

    r = sub.add_parser("record", help="write cra-evidence.json for a release")
    r.add_argument("--product", required=True)
    r.add_argument("--version", required=True)
    r.add_argument("--support-until", required=True, help="YYYY-MM-DD")
    r.add_argument("--sbom", required=True)
    r.add_argument(
        "--subject", action="append", default=[], help="a released file (repeatable)"
    )
    r.add_argument(
        "--attestation",
        action="append",
        default=[],
        help="attestation URL (repeatable)",
    )
    r.add_argument("--security-policy", default="SECURITY.md")
    r.add_argument("--repo", default=repo)
    r.add_argument("--commit", default=os.environ.get("GITHUB_SHA"))
    r.add_argument("--out", default=EVIDENCE_NAME)
    r.set_defaults(func=cmd_record)

    m = sub.add_parser(
        "monitor", help="check supported releases for exploited vulnerabilities"
    )
    m.add_argument("--repo", default=repo)
    m.add_argument("--token", default=token)
    m.add_argument(
        "--sbom", help="check this SBOM file instead of the repository's releases"
    )
    m.add_argument("--version", help="label for --sbom")
    m.add_argument("--support-until", help="label for --sbom")
    m.add_argument("--today", help="YYYY-MM-DD; default: today")
    m.add_argument("--kev-url", default=KEV_URL)
    m.add_argument("--euvd", action=argparse.BooleanOptionalAction, default=True)
    m.add_argument("--euvd-url", default=EUVD_URL)
    m.add_argument("--open-issues", action=argparse.BooleanOptionalAction, default=True)
    m.add_argument(
        "--fail-on", choices=["exploited", "any", "never"], default="exploited"
    )
    m.add_argument("--out", help="write findings as JSON here")
    m.set_defaults(func=cmd_monitor)

    args = p.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())

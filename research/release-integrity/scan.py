#!/usr/bin/env python3
"""Could someone swap the files in your latest GitHub release?

For the most-starred Go and Rust CLI projects that ship binaries on GitHub
Releases, look at the latest release and record:

- immutable: GitHub's immutable releases are on for it (assets can't be
  replaced or deleted, the tag can't move);
- provenance: a GitHub build-provenance attestation exists for its binaries,
  so a swapped file fails `gh attestation verify`;
- signed: it ships signatures (cosign/sigstore, GPG, minisign, SLSA
  .intoto.jsonl) that a swapped file would fail;
- checksums: it ships a checksum file. That alone doesn't help: whoever can
  replace a binary can replace the checksum file next to it.

Usage:
  scan.py                      # search + scan, writes results.json/.csv/summary.md
  scan.py --repos o/r o2/r2    # scan these repos only (local test)

Needs GITHUB_TOKEN. Standard library only.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
TOKEN = os.environ.get("GITHUB_TOKEN", "")
NOW = dt.datetime.now(dt.timezone.utc)

CHECKSUM = re.compile(r"(checksum|sha256|sha512|sha1sum|md5|\.sum$|sums$|\.sha\d*$)", re.I)
SIGNATURE = re.compile(
    r"(\.sig$|\.asc$|\.pem$|\.cert$|\.crt$|\.minisig$|\.sigstore(\.json)?$|\.bundle$|\.intoto\.jsonl$|\.att$)",
    re.I,
)
METADATA = re.compile(
    r"(\.txt$|\.json$|\.md$|\.yaml$|\.yml$|\.spdx$|\.cdx$|\.sbom$|\.html$|\.xml$|\.sh$|\.ps1$|\.toml$|\.lock$)",
    re.I,
)

calls = 0


def get(path, params=None, ok404=False):
    """GET a REST path; waits out rate limits."""
    global calls
    url = path if path.startswith("http") else API + path
    if params:
        url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
    for attempt in range(6):
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "keelinfra-release-integrity-scan",
                **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {}),
            },
        )
        try:
            calls += 1
            with urllib.request.urlopen(req, timeout=60) as r:
                remaining = int(r.headers.get("X-RateLimit-Remaining", "100"))
                reset = int(r.headers.get("X-RateLimit-Reset", "0"))
                body = json.loads(r.read() or b"null")
                if remaining < 3:
                    wait = max(0, reset - time.time()) + 5
                    print(f"rate limit low, sleeping {wait:.0f}s", flush=True)
                    time.sleep(wait)
                return body
        except urllib.error.HTTPError as e:
            if e.code == 404 and ok404:
                return None
            if e.code in (403, 429):
                reset = int(e.headers.get("X-RateLimit-Reset", "0"))
                retry = int(e.headers.get("Retry-After", "0"))
                wait = max(retry, reset - time.time(), 30) + 5
                print(f"HTTP {e.code} on {url}, sleeping {wait:.0f}s", flush=True)
                time.sleep(min(wait, 3700))
                continue
            if e.code >= 500:
                time.sleep(5 * (attempt + 1))
                continue
            raise
        except urllib.error.URLError:
            time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"giving up on {url}")


def candidates(per_language):
    """Most-starred Go and Rust repos tagged `cli`, merged by stars."""
    seen = {}
    for lang in ("Go", "Rust"):
        got = 0
        for page in range(1, 11):
            res = get(
                "/search/repositories",
                {
                    "q": f"topic:cli language:{lang} stars:>=1000 archived:false fork:false",
                    "sort": "stars",
                    "order": "desc",
                    "per_page": 100,
                    "page": page,
                },
            )
            items = res.get("items", [])
            for it in items:
                seen[it["full_name"]] = it["stargazers_count"]
            got += len(items)
            time.sleep(2.5)  # search API: 30 requests/minute
            if len(items) < 100 or got >= per_language:
                break
    return sorted(seen, key=lambda n: -seen[n]), seen


def kind(name):
    if SIGNATURE.search(name):
        return "signature"
    if CHECKSUM.search(name):
        return "checksum"
    if METADATA.search(name):
        return "metadata"
    return "binary"


def scan_repo(full_name, max_age_days):
    rel = get(f"/repos/{full_name}/releases/latest", ok404=True)
    if not rel:
        return None, "no release"
    published = rel.get("published_at") or rel.get("created_at")
    age = (NOW - dt.datetime.fromisoformat(published.replace("Z", "+00:00"))).days
    if age > max_age_days:
        return None, f"latest release {age} days old"
    assets = rel.get("assets", [])
    kinds = {a["name"]: kind(a["name"]) for a in assets}
    binaries = sorted((a for a in assets if kinds[a["name"]] == "binary"), key=lambda a: a["name"])
    if not binaries:
        return None, "no binary assets"

    provenance = False
    checked = 0
    sums = sorted((a for a in assets if kinds[a["name"]] == "checksum"), key=lambda a: a["name"])
    # Some projects attest the checksum file instead of each binary.
    for a in binaries[:2] + sums[:1]:
        digest = a.get("digest")
        if not digest:
            continue
        checked += 1
        res = get(
            f"/repos/{full_name}/attestations/{digest}",
            {"predicate_type": "provenance", "per_page": 1},
            ok404=True,
        )
        if res and res.get("attestations"):
            provenance = True
            break

    row = {
        "repo": full_name,
        "tag": rel["tag_name"],
        "published": published[:10],
        "age_days": age,
        "assets": len(assets),
        "binaries": len(binaries),
        "immutable": bool(rel.get("immutable")),
        "provenance": provenance,
        "digests_checked": checked,
        "signed": any(k == "signature" for k in kinds.values()),
        "checksums": any(k == "checksum" for k in kinds.values()),
    }
    if row["immutable"]:
        row["verdict"] = "immutable"
    elif row["provenance"]:
        row["verdict"] = "provenance"
    elif row["signed"]:
        row["verdict"] = "signed"
    elif row["checksums"]:
        row["verdict"] = "checksums only"
    else:
        row["verdict"] = "nothing"
    return row, None


def summarize(rows, stars, skipped):
    n = len(rows)
    order = ["immutable", "provenance", "signed", "checksums only", "nothing"]
    counts = {v: sum(1 for r in rows if r["verdict"] == v) for v in order}
    swappable = counts["checksums only"] + counts["nothing"]
    out = [
        f"# Release integrity scan, {NOW.date().isoformat()}",
        "",
        f"{n} most-starred Go/Rust CLI repos (topic `cli`, >=1000 stars) whose latest",
        "release is under a year old and ships binaries. Latest release only.",
        "",
        "| Verdict (best protection found) | Repos | Share |",
        "|---|---|---|",
    ]
    for v in order:
        out.append(f"| {v} | {counts[v]} | {counts[v] / n:.0%} |")
    out += [
        "",
        f"**Swappable with no verifiable trace (checksums only or nothing): {swappable}/{n} ({swappable / n:.0%}).**",
        "",
        f"Immutable on: {sum(r['immutable'] for r in rows)}; build provenance: {sum(r['provenance'] for r in rows)};"
        f" signatures: {sum(r['signed'] for r in rows)}; checksum files: {sum(r['checksums'] for r in rows)}.",
        "",
        "Top 20 by stars:",
        "",
        "| Repo | Stars | Tag | Immutable | Provenance | Signed | Checksums |",
        "|---|---|---|---|---|---|---|",
    ]
    yn = lambda b: "yes" if b else "-"
    for r in rows[:20]:
        out.append(
            f"| {r['repo']} | {stars.get(r['repo'], '')} | {r['tag']} | {yn(r['immutable'])} | {yn(r['provenance'])} | {yn(r['signed'])} | {yn(r['checksums'])} |"
        )
    reasons = {}
    for why in skipped.values():
        key = why.split(" ")[0] if why.startswith("latest") else why
        reasons[key] = reasons.get(key, 0) + 1
    out += ["", f"Skipped candidates: {reasons}", ""]
    return "\n".join(out) + "\n"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repos", nargs="*")
    p.add_argument("--target", type=int, default=300)
    p.add_argument("--max-age-days", type=int, default=365)
    p.add_argument("--out", default=".")
    args = p.parse_args()

    if args.repos:
        names, stars = args.repos, {}
    else:
        names, stars = candidates(1000)
        print(f"{len(names)} candidates", flush=True)

    rows, skipped = [], {}
    for name in names:
        if len(rows) >= args.target:
            break
        try:
            row, why = scan_repo(name, args.max_age_days)
        except Exception as e:  # keep going; record it
            row, why = None, f"error {e}"
        if row:
            row["stars"] = stars.get(name)
            rows.append(row)
            print(f"{len(rows):3d} {name}: {row['verdict']}", flush=True)
        else:
            skipped[name] = why
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.json"), "w") as f:
        json.dump({"date": NOW.isoformat(), "rows": rows, "skipped": skipped, "api_calls": calls}, f, indent=1)
    with open(os.path.join(args.out, "results.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["repo"])
        w.writeheader()
        w.writerows(rows)
    summary = summarize(rows, stars, skipped) if rows else "no rows\n"
    with open(os.path.join(args.out, "summary.md"), "w") as f:
        f.write(summary)
    print(summary)
    print(f"API calls: {calls}")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(summary)


if __name__ == "__main__":
    sys.exit(main())

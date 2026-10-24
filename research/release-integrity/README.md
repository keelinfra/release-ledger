# Release integrity scan

Could someone with write access to a repository replace the files in its
latest GitHub release, and would a downloader be able to tell?

Once a month, [`scan.py`](scan.py) takes every Go and Rust repository tagged
`cli` with at least 1,000 stars, keeps those whose latest release is under a
year old and ships binaries, and records for that latest release:

| Column | Meaning |
|---|---|
| `immutable` | GitHub [immutable releases](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases) are on: files can't be replaced, the tag can't move |
| `provenance` | a GitHub build-provenance attestation exists for its binaries (up to two binaries and one checksum file are looked up) |
| `signed` | it ships signature files (cosign/Sigstore, GPG, minisign, SLSA `.intoto.jsonl`) |
| `checksums` | it ships a checksum file; on its own this doesn't help, since whoever can replace a binary can replace the checksum file next to it |
| `verdict` | the strongest of the above; `checksums only` and `nothing` count as swappable |

Results: one directory per run under [`results/`](results), and one line per
run in [`results/trend.csv`](results/trend.csv). The set of repositories is
re-queried each month, so it changes as projects cross 1,000 stars or stop
releasing.

Run it yourself with a token that can read public repositories:

```sh
GITHUB_TOKEN=... python3 scan.py --out /tmp/scan
python3 scan.py --repos owner/repo another/repo --out /tmp/scan
```

First write-up: [shenxianpeng.dev](https://shenxianpeng.dev/posts/2026/swappable-github-releases/).

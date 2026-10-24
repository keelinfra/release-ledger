# Release integrity scan, 2026-10-24

242 most-starred Go/Rust CLI repos (topic `cli`, >=1000 stars) whose latest
release is under a year old and ships binaries. Latest release only.

| Verdict (best protection found) | Repos | Share |
|---|---|---|
| immutable | 25 | 10% |
| provenance | 19 | 8% |
| signed | 19 | 8% |
| checksums only | 112 | 46% |
| nothing | 67 | 28% |

**Swappable with no verifiable trace (checksums only or nothing): 179/242 (74%).**

Immutable on: 25; build provenance: 31; signatures: 30; checksum files: 157.

Top 20 by stars:

| Repo | Stars | Tag | Immutable | Provenance | Signed | Checksums |
|---|---|---|---|---|---|---|
| rtk-ai/rtk | 84449 | v1.0.1 | - | - | - | yes |
| junegunn/fzf | 83753 | v0.74.5 | - | - | - | yes |
| jesseduffield/lazygit | 83401 | v0.66.2 | - | - | - | yes |
| BurntSushi/ripgrep | 69396 | 15.2.0 | - | - | - | yes |
| tw93/Pake | 62292 | V3.17.6 | - | - | - | - |
| sharkdp/bat | 60913 | v0.26.1 | - | - | - | - |
| cli/cli | 46728 | v2.103.2 | yes | yes | - | yes |
| herdrdev/herdr | 45650 | v0.9.5 | yes | - | - | - |
| sharkdp/fd | 44853 | v10.5.0 | - | yes | - | - |
| sxyazi/yazi | 42999 | v26.9.1 | - | - | - | - |
| codewhale-hq/Codewhale | 41115 | v0.10.1 | - | - | - | yes |
| ajeetdsouza/zoxide | 40274 | v0.10.0 | - | - | - | - |
| esengine/DeepSeek-Reasonix | 35955 | studio-v2.50.0 | - | - | yes | yes |
| googleworkspace/cli | 31847 | v0.22.5 | yes | yes | - | yes |
| gitleaks/gitleaks | 30293 | v8.30.1 | - | - | - | yes |
| sharkdp/hyperfine | 29146 | v2.0.0 | - | - | - | - |
| charmbracelet/glow | 27786 | v3.0.0 | - | - | yes | yes |
| t8y2/dbx | 27671 | v0.6.53 | - | - | yes | yes |
| asdf-vm/asdf | 25607 | v0.20.2 | - | - | - | yes |
| yorukot/superfile | 23913 | v1.6.0 | - | - | - | yes |

Skipped candidates: {'latest': 78, 'no binary assets': 22, 'no release': 11, 'error HTTP Error 403: Forbidden': 1}


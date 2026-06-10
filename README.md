# Shai-Hulud Supply Chain Attack Detector

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-Bash%205.0%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-Active-success)](../../)
[![Tests](https://img.shields.io/badge/tests-169%20passing-brightgreen)](#testing)
[![Packages](https://img.shields.io/badge/compromised%20packages-2%2C830%2B-red)](compromised-packages.txt)
[![Type](https://img.shields.io/badge/type-Security%20Tool-red)](#what-it-catches)
[![Contributions](https://img.shields.io/badge/contributions-Welcome-orange)](#contributing)
[![Last Commit](https://img.shields.io/github/last-commit/Cobenian/shai-hulud-detect)](https://github.com/Cobenian/shai-hulud-detect/commits/main)

<img src="shai_hulu_detector.jpg" alt="sshd" width="80%" />

A Bash script that scans a project — or many projects at once — for known traces of the September 2025 → June 2026 npm, PyPI, Composer, and Crates supply-chain attacks. Cross-checks 3,290+ confirmed bad package versions and a library of content-pattern IoCs (file hashes, C2 domains, dead-man's-switch artifacts, wipe-threat strings, AI-assistant config droppers, etc.).

## Quick Start

```bash
git clone https://github.com/Cobenian/shai-hulud-detect
cd shai-hulud-detect
chmod +x shai-hulud-detector.sh

# Scan one project
./shai-hulud-detector.sh /path/to/your/project

# Scan every project under one or more parent dirs and get one aggregate report
./shai-hulud-detector.sh --bulk ~/dev ~/work

# Save findings to a file (same format as CI-friendly logs)
./shai-hulud-detector.sh --save-log report.log /path/to/project
```

**Exit codes** (drop straight into CI): `0` clean · `1` high-risk · `2` medium-risk · `3` per-project scan errored (bulk mode only).

## What it catches

The detector looks for two kinds of evidence on disk:

1. **Compromised package versions** — every `package.json`, lockfile, `pyproject.toml`, `requirements.txt`, `Pipfile`, `poetry.lock`, `uv.lock`, etc. is parsed and the resolved versions are checked against the 3,290+-entry list in [`compromised-packages.txt`](compromised-packages.txt). Transitive deps inside `node_modules/` are checked too, not skipped.
2. **Content-pattern IoCs** — known-malicious file hashes, payload filenames, C2 domains, dead-man's-switch artifacts, marker repo names, malicious workflow files, forged orphan-commit references, suspicious lifecycle hooks, and threat-actor publisher fingerprints. These don't depend on the package list and fire even if the bad package has been uninstalled but the dropper traces remain.

| Wave | Date | Scope |
|---|---|---|
| Chalk/Debug crypto theft | 2025-09-08 | 18+ packages, ~2B weekly downloads |
| Shai-Hulud worm | 2025-09-14 | 517+ packages (@ctrl, @crowdstrike, …) |
| Shai-Hulud "Second Coming" (fake Bun) | 2025-11-24 | 1,100+ packages |
| Golden Path variant | 2025-12-28 | renamed Bun-attack files |
| SANDWORM_MODE workflow poisoning | 2026-02-17 | 19 packages + GitHub Action |
| Axios RAT compromise | 2026-03-31 | `axios@1.14.1`/`0.30.4` + `plain-crypto-js` |
| Mini Shai-Hulud / TanStack | 2026-05-11 | 400+ versions, dead-man's-switch |
| Megalodon (GitHub-repo backdooring) | 2026-05-18 | 5,561 repos via stolen PATs; `@tiledesk/tiledesk-server@2.18.6-2.18.12` as npm fallout |
| Mini Shai-Hulud / AntV (atool) | 2026-05-19 | 643 versions, 323 packages |
| Web3 / DeFi MCP-server typosquat | 2026-05-20 | 10 packages (`chain-key-validator`, `defi-threat-scanner`, …), exfiltrates SSH + wallet keys |
| Polymarket wallet drainer | 2026-05-21 | 9 packages from `polymarketdev` (`polymarket-bot`, `polymarket-trader`, …), fake wallet-onboarding prompt captures private keys |
| Bitwarden CLI ("Third Coming") | 2026-04-22 | `@bitwarden/cli@2026.4.0` via Checkmarx `ast-github-action` breach; `bw1.js` exfil to `audit.checkmarx.cx` |
| node-ipc backdoor | 2026-05-14 | `node-ipc@9.1.6/9.2.3/12.0.1`; IIFE in `node-ipc.cjs`, DNS exfil to `sh.azurestaticprovider.net` |
| Nx Console VS Code ext | 2026-05-18 | `nx-console@18.95.0`; payload from orphan commit `558b09d7` in `nrwl/nx`, targets `~/.claude/settings.json` (TeamPCP / GitHub breach) |
| TrapDoor (TeamPCP) | 2026-05-22→25 | 34 packages / 384+ versions across **npm + PyPI + Crates**; plants `.cursorrules`/`CLAUDE.md` AI-assistant droppers |
| Laravel-Lang tag-rewrite | 2026-05-22 | 700+ **Composer** tags force-rewritten (`laravel-lang/lang`, …); RCE on autoload, `DebugElevator` stealer |
| mouse5212 "Malware-Slop" | 2026-05-26 | `mouse5212-super-formatter` exfils Claude's `/mnt/user-data` via embedded GitHub PAT (`unplowed3584`) |
| art-template npm hijack | 2025-03 → 2026-05 | 4 versions (`art-template@4.13.3-4.13.6`), iOS browser exploit kit (UNC6691) |
| sl4x0 dependency confusion | 2025-06 → 2026-03 | 92+ packages across 32 `*poc` accounts, DNS exfil to `oob.sl4x0.xyz` (likely security research) |
| `durabletask` PyPI worm | 2026-05-19 | `pypi:durabletask:1.4.1-1.4.3`, multi-cloud credential stealer + AWS SSM / k8s lateral movement |
| PyPI cross-spread (TeamPCP) | 2026-03 → 05 | `litellm`, `telnyx`, `xinference`, `lightning`, `mistralai`, `guardrails-ai` |
| Miasma "Phantom Gyp" worm | 2026-06-03 | 57 packages / 286 versions (`@vapi-ai/server-sdk`, `ai-sdk-ollama`, `autotel-*`, `awaitly-*`, `executable-stories-*`); novel `binding.gyp` command-substitution trigger bypasses preinstall-script monitors |
| Miasma "Hades" PyPI wave | 2026-06-07 | 19 PyPI packages / 37 versions (`bramin`, `magique-ai`, `pantheon-agents`, `executor-engine`, `ufish`); novel `*-setup.pth` Python startup-hook execs an `_index.js` loader on plain `import`, no install hook needed; C2 camouflaged under `api.anthropic.com` |
| IronWorm ("rustier cousin") | 2026-06-03 | 37 npm packages from the `asteroiddao` account (`weavedb-*`, `arnext`, `cwao`, `wao`, `zkjson`); Rust infostealer + eBPF rootkit via `preinstall` ELF hook, Exodus-wallet theft, leaked operator wallet `0x7e28…a4d6` |

For per-wave IoC inventories, payload hashes, source advisories, and version-by-version lists, see [`CHANGELOG.md`](CHANGELOG.md).

> ### ⚠️ Dead-man's-switch warning
> Two waves (May 11 and May 19, 2026) install a persistence daemon (`gh-token-monitor` / `kitty-monitor`) that **wipes the host if its monitored GitHub token is revoked**. Run with `--check-host` to detect the persistence artifacts. If they're present, **stop and remove the service BEFORE rotating any tokens**. The console summary and aggregate report both print a safe remediation order.

## Ecosystems

| Ecosystem | Auto-detected via | Status |
|---|---|---|
| **npm** | `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml` | Full support |
| **PyPI** | `pyproject.toml`, `requirements*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg` | Full support (pure-bash awk parsers, no Python required) |
| **Composer** | `composer.json`, `composer.lock` | Full support (PHP / Packagist; added for the Laravel-Lang wave) |
| **Crates** | `Cargo.toml`, `Cargo.lock` | Full support (Rust / crates.io; added for the TrapDoor wave) |

Auto-detection looks for marker files in your tree, skipping `node_modules/`, `vendor/`, `.venv/`, `venv/`, `.tox/`, `site-packages/`, `dist/`, `build/`, and similar trees. **That exclusion only decides which checks to run** — content inside `node_modules/` is still fully scanned for compromised versions and malware indicators. Override auto-detection with `--ecosystem=npm`, `--ecosystem=pypi`, `--ecosystem=all`, or a comma-separated list.

## CI/CD

```yaml
- name: Shai-Hulud scan
  run: |
    chmod +x ./shai-hulud-detector.sh
    ./shai-hulud-detector.sh --save-log shai-hulud-report.log .
  # Job fails on exit 1 (high-risk) or 2 (medium-risk)
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: shai-hulud-report
    path: shai-hulud-report.log
```

For GitLab CI, Jenkins, and a custom exit-code handler in shell, see [`docs/ci-examples.md`](docs/ci-examples.md) — or just call the script and switch on `$?`, the exit-code contract is the same everywhere.

## Common scenarios

### Scan many projects at once (`--bulk`)

```bash
./shai-hulud-detector.sh --bulk ~/dev ~/work                 # auto-discover all projects
./shai-hulud-detector.sh --bulk --paranoid --bulk-output ./audit ~/dev
./shai-hulud-detector.sh --bulk --bulk-list ~/dev            # dry-run: print what would be scanned
```

Project discovery is content-aware: a directory with `.git`, a `package.json`, a `pyproject.toml`, `Cargo.toml`, `go.mod`, etc. is one scan unit (monorepos stay whole). "Bucket" folders like `~/dev/clients/<client>/<project>` are descended into. `node_modules`, `vendor`, `dist`, build dirs, and hidden dirs are never entered. The detector's own repo is skipped automatically. Unreadable directories are reported instead of silently skipped.

Output goes to `./shai-hulud-bulk-report-<timestamp>/` (or `--bulk-output DIR`):

```
shai-hulud-bulk-report-<timestamp>/
├── aggregate-report.md      # summary tables + per-project results + remediation
└── per-repo/
    ├── <project>.findings.log    # severity-grouped file paths
    └── <project>.console.txt     # full scan output, ANSI-stripped
```

### Paranoid mode (`--paranoid`)

Adds typosquatting detection and network-exfiltration heuristics on top of the core checks. These are general-purpose security signals, not Shai-Hulud-specific, and produce more false positives — useful for audits, not recommended for CI gating.

### Host-level persistence scan (`--check-host`)

Walks `$HOME` for the May 2026 dead-man's-switch artifacts (`gh-token-monitor`, `kitty-monitor`). Off by default. See the warning above before remediating any findings.

### Save findings to a log file (`--save-log FILE`)

Writes flagged file paths grouped by severity, in a format friendly to grep and CI artifact uploads:

```
# HIGH
/path/to/router_init.js
/path/to/package.json
# MEDIUM
/path/to/suspicious-content.js
# LOW
/path/to/namespace-warning.json
```

### Other flags

| Flag | Effect |
|---|---|
| `--check-semver-ranges` | Flag `^`/`~` ranges that could resolve to compromised versions (informational, LOW risk). |
| `--ecosystem LIST` | Restrict checks to `npm`, `pypi`, `all`, or a comma-separated list. Default: auto-detect. |
| `--parallelism N` | Threads for parallelisable steps. Defaults to your CPU count. |
| `--use-git-grep` / `--use-ripgrep` / `--use-grep` | Force a specific grep tool. Default: auto-select fastest available. |
| `--bulk-depth N` | Depth cap for bulk discovery (default 3). `--bulk-depth 1` = flat. |
| `--bulk-list` | With `--bulk`: print what would be scanned and exit. |
| `--bulk-output DIR` | Where to write the bulk report (default `./shai-hulud-bulk-report-<timestamp>/`). |

## How it works

1. **Collect** the file inventory (one `find` pass, categorized by extension).
2. **Detect** ecosystems from marker files, decide which package-level checks to run.
3. **Match** every resolved package version against `compromised-packages.txt` via a sorted set-intersection (`comm -12`).
4. **Hash** priority files (`bundle.js`, `setup_bun.js`, `router_init.js`, `tanstack_runner.js`, `cat.py`, `node-ipc.cjs`, etc.) and compare against 20 known-malicious SHA-256s.
5. **Grep** for content-pattern IoCs: C2 domains, threat-actor accounts, dead-man's-switch service names, wipe-threat strings, malicious commit SHAs, beacon strings, payload filenames, orphan-commit `optionalDependencies` patterns.
6. **(Opt-in)** scan `$HOME` for persistence artifacts (`--check-host`); run typosquatting + network-exfil heuristics (`--paranoid`); flag latent semver-range risk (`--check-semver-ranges`).
7. **Report** in three severity tiers (HIGH/MEDIUM/LOW), with remediation order for the safety-critical findings.

Detection is read-only. The script never modifies, deletes, or quarantines anything — manual review and remediation are on you.

## Output

```
✅ No indicators of Shai-Hulud compromise detected.   ← clean, exit 0
🚨 HIGH RISK: ...                                     ← exit 1, immediate action
⚠️  MEDIUM RISK: ...                                  ← exit 2, manual review
```

**HIGH**: definitive indicators — compromised package version, known-malicious file hash, malicious workflow, dead-man's-switch artifact. Stop and remediate.

**MEDIUM**: suspicious patterns that warrant a look — semver range that could match a compromised version, references to webhook redirector domains, suspicious git branches.

**LOW**: informational notes — namespace warnings (packages from affected namespaces at safe versions), legitimate-looking patterns that share shape with attack techniques.

## Requirements

- **Bash 5.0+** (associative arrays, `mapfile`). macOS ships 3.x; install with `brew install bash` and invoke via `/opt/homebrew/bin/bash`.
- Standard Unix tools: `find`, `grep`, `awk`, `sed`, `sort`, `comm`, `shasum` (or `sha256sum`), `xargs`. All POSIX-portable.
- Tested on macOS (Bash 5), Linux, and Git Bash for Windows.

The script auto-selects the fastest available grep tool (`git grep` > `ripgrep` > `grep`). No runtime dependencies on Python, Node, or anything else.

## Limitations

- Hash detection only catches exact SHA-256 matches against the 20 known-malicious hashes.
- Compromised-package detection requires the version to be in `compromised-packages.txt` — new variants need a list update.
- Paranoid-mode heuristics produce false positives on legitimate code.
- The detector reads filesystem state; it doesn't query npm/PyPI registries for live data.

## Updating the compromised-packages list

`compromised-packages.txt` is a flat text file:

```
# Comments start with #
axios:1.14.1                            # bare entry = npm (back-compat)
npm:@tanstack/react-router:1.169.5      # explicit npm prefix
pypi:mistralai:2.4.6                    # PyPI entry
composer:laravel-lang/lang:15.29.5      # Composer / Packagist entry
crates:sui-move-build-helper:0.1.0      # Crates.io / Cargo entry
```

For campaigns where **every** version of a package is malicious (e.g. TrapDoor, Laravel-Lang's tag rewrite), per-version entries can't keep up — detection is done version-agnostically by a dedicated `check_*_indicators` function that name-matches the dependency in any manifest.

To add new packages from a fresh advisory: append entries in that format, run `./run-tests.sh`, open a PR. Source the additions from a reputable security firm (Socket, StepSecurity, Aikido, Snyk, JFrog, Wiz, Semgrep, SafeDep, GitGuardian, OX Security) and cite them.

## Testing

```bash
./run-tests.sh                          # full suite, 188 checks
./shai-hulud-detector.sh test-cases/<fixture-name>   # run one fixture manually
```

Each subdirectory of `test-cases/` is a self-contained fixture (clean projects, infected projects with the various attack signatures, ecosystem-specific tests, paired clean/dirty pairs). Run `ls test-cases/` to see them all.

## Contributing

PRs welcome — especially new compromised-package entries as fresh waves are disclosed.

1. Fork, branch, edit.
2. For new packages: append to `compromised-packages.txt`, add a fixture under `test-cases/`, register it in `run-tests.sh`.
3. For new content-pattern IoCs: extend the relevant `check_*` function in `shai-hulud-detector.sh`, add an assertion in `run-tests.sh`.
4. `./run-tests.sh` must pass.
5. Cite your sources (security advisories, vendor blog posts) in the PR description.

Don't include actual malware in test fixtures — inert string constants and synthetic files only.

## Security note

Detection only. The script does not remove malicious code, downgrade packages, or block installs. Verify findings, then remediate manually.

For the dead-man's-switch waves (May 11 + May 19, 2026), follow the remediation order printed by `--check-host`: **stop the persistence service first, delete its files, then rotate credentials**. Revoking a monitored token before stopping the service is designed to trigger a destructive wipe.

## References

For per-wave source advisories with IoC enumerations, see the `### Security` section of each release entry in [`CHANGELOG.md`](CHANGELOG.md). The original Shai-Hulud disclosures live at:

- [StepSecurity — CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [JFrog — Largest npm attack in history](https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/)
- [Aikido — npm debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Semgrep — Secret-scanning-tool credential theft](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)

## License

MIT — see [LICENSE](LICENSE).

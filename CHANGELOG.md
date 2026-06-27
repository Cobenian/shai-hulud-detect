# Changelog

All notable changes to the Shai-Hulud NPM Supply Chain Attack Detector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.10.0] - 2026-06-26

### Added
- **June 17, 2026 — easy-day-js / Mastra AI wave (npm)**: detection for the supply-chain compromise of the `@mastra` npm organization, which Microsoft attributes to North Korea's **Sapphire Sleet / BlueNoroff**. In an 88-minute automated window the attacker republished the entire `@mastra/*` scope plus the top-level `mastra` / `create-mastra` packages, each with a single injected dependency: `easy-day-js`, a `dayjs` typosquat whose `easy-day-js@1.11.22` carries an obfuscated `postinstall` dropper (`setup.cjs`) that disables TLS verification, pulls a cross-platform infostealer from C2 `23.254.164.92:8000/update/49890878` (stage-2 beacon `23.254.164.123:443`), and runs it as a detached hidden process. `compromised-packages.txt` gains 145 version-pinned entries (141 `@mastra/*` packages + `mastra` + `create-mastra` + `easy-day-js@1.11.21`/`1.11.22`); a new `check_easy_day_js_indicators` function flags the near-zero-FP content IoCs (the injected dependency reference, both C2 IPs, the `/update/49890878` payload path, and the `node setup.cjs --no-warnings` hook). This is a DISTINCT campaign from the Miasma/Shai-Hulud lineage. Sources: [JFrog](https://research.jfrog.com/post/easy-day-js/), [StepSecurity](https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js), [Orca](https://orca.security/resources/blog/mastra-npm-supply-chain-attack/).
- **June 25, 2026 — Miasma "Mini Shai-Hulud" LeoPlatform / RStreams wave (npm)**: detection for the Miasma/Phantom-Gyp self-spreading worm reaching the LeoPlatform and RStreams (AWS data-streaming) npm ecosystems plus a handful of unrelated packages. `compromised-packages.txt` gains 23 version-pinned entries (15 `leo-*`, 2 `rstreams-*`, `hexo-deployer-wrangler`, `hexo-shoka-swiper`, `prism-silq`, `serverless-convention`, `serverless-leo`, `solo-nav`). 13 payload/loader SHA-256 hashes (malicious `binding.gyp`, the `leo-*` `index.js` payloads, the `.claude/` & `.vscode/` auto-run hooks, and the decrypted Bun-bootstrap/main payloads) were added to `MALICIOUS_HASHLIST`, and the wave's new near-zero-FP marker strings (`RevokeAndItGoesKaboom`, `Alright Lets See If This Works`, `thebeautifulmarchoftime`/`thebeautifulsnadsoftime`) were added to `check_hades_miasma_indicators`. The Go module `github.com/verana-labs/verana-blockchain@v0.10.1-dev.20` is named in the disclosure but not matchable (no Go ecosystem support). Source: [Socket](https://socket.dev/blog/miasma-mini-shai-hulud-hits-leoplatform-npm-packages-go-ecosystem).
- **Test fixtures** (all **inert** — version-pinned manifests + neutered marker strings in comments, no executable payload): `test-cases/easy-day-js-attack/` + `easy-day-js-clean/` and `test-cases/leoplatform-miasma-attack/` + `leoplatform-miasma-clean/`. Dedicated assertion blocks in `run-tests.sh` lock in the easy-day-js content IoCs (5) and the LeoPlatform package + marker IoCs (4).

### Changed
- **`compromised-packages.txt`**: header counter 3,290+ → 3,460+ (145 easy-day-js/Mastra + 23 LeoPlatform/RStreams entries).
- **`README.md`**: counters 3,290+ → 3,460+ and the packages badge 2,830+ → 3,460+; two new rows in the "what it catches" wave table (easy-day-js/Mastra, Miasma LeoPlatform/RStreams); added a "Sources we monitor for new waves" subsection to References (primary research teams + news aggregators).
- **`shai-hulud-detector.sh`**: `SCRIPT_VERSION` 3.9.0 → 3.10.0; added `check_easy_day_js_indicators` (wired into temp-file init, the file collector, the advanced-detection stage, the HIGH-risk report, and `--json`); extended `check_hades_miasma_indicators` with the June 25 LeoPlatform markers; added 13 LeoPlatform hashes to `MALICIOUS_HASHLIST`.
- **`run-tests.sh`**: registered four new `EXPECTED` fixtures plus the two content-IoC assertion blocks. Suite: 194 → 207 checks.

## [3.9.0] - 2026-06-26

### Added
- **`--json FILE` structured output mode**: a new machine-readable output for CI gates and downstream tooling (e.g. a hosted scanning service) that needs findings as data rather than parsed console text. It mirrors the exact HIGH/MEDIUM/LOW severity mapping of `--save-log`, but **preserves the per-finding reason** that `--save-log` discards (the latter keeps only file paths via `cut -d: -f1`). Schema (`schema_version` 1.0):
  ```json
  {
    "schema_version": "1.0", "tool": "shai-hulud-detector", "tool_version": "3.9.0",
    "generated_at": "2026-06-26T00:00:00Z", "scan_path": "/path/to/project",
    "summary": { "high": 7, "medium": 0, "low": 0 }, "risk_level": "high",
    "findings": [ { "severity": "HIGH", "file": "package.json", "line": 6, "message": "axios@1.14.1" } ]
  }
  ```
  - **Best-effort `line` number** for package-shaped findings (`name@version`, `@scope/name@version`): the manifest is grepped for the package name, preferring the quoted name (`"axios"` matches the dependency line, not `"axios-attack-test"`) and falling back to the bare name for non-JSON manifests (`requirements.txt`, `Cargo.toml`, …). `line` is `null` for prose findings or when no match is found. This lets a consumer place inline annotations (e.g. GitHub Checks API) on the offending dependency line.
  - **Correct escaping by construction**: findings are normalized to `severity<TAB>file<TAB>line<TAB>message` records and rendered through a single `jq` pass — JSON is never hand-concatenated in shell, so quotes/backslashes/Unicode in IoC strings cannot corrupt the output.
  - **Dependency boundary preserved**: `--json` is the only mode that requires `jq`; it fails fast with a clear message if `jq` is absent. The default offline text output keeps its zero-runtime-dependency guarantee. The exit-code contract (`0`/`1`/`2`) is unchanged and remains the authoritative CI signal; `--json` and `--save-log` can be used together.
- **`SHAI_HULUD_PACKAGES_FILE` environment override**: `load_compromised_packages` now reads its list from `$SHAI_HULUD_PACKAGES_FILE` when that variable is set and the file exists, instead of the default `compromised-packages.txt` next to the script. This lets a caller (e.g. a service syncing a live feed) point the scanner at a managed copy without overwriting the script's own directory. Unset by default and silently falls back to the bundled list if the override path is missing, so existing usage is completely unaffected.

### Changed
- **`shai-hulud-detector.sh`**: added a `SCRIPT_VERSION` constant (`3.9.0`, surfaced as `tool_version` in `--json`); added `write_json_file` plus the `_jf_emit` / `_jf_path` / `_jf_pathmsg` / `_jf_pathmsg_stdin` helpers (all reached only under `--json`, so the normal scan path is unaffected); wired the `--json` flag into argument parsing, `--help`, and the main scan flow; added the `SHAI_HULUD_PACKAGES_FILE` override in `load_compromised_packages`.
- **`README.md`**: documented `--json` in the flags table and added a "Machine-readable JSON output" section.
- **`run-tests.sh`**: added a `--json` test block (6 assertions: well-formed JSON, `risk_level`/`summary` on an infected fixture, per-finding message preservation, line-number accuracy, `--save-log`/`--json` path-set parity, and clean-project emptiness; skipped with a notice when `jq` is unavailable). Suite: 188 → 194 checks.

## [3.8.0] - 2026-06-08

### Added
- **Miasma "Hades" PyPI-branch coverage (June 7, 2026)**: Added 37 malicious version entries across 19 PyPI packages from the Socket-disclosed wave of 448 coordinated artifacts (411 npm + 37 PyPI) published by the same "Miasma: The Spreading Blight" campaign. The PyPI branch is tracked as "Hades - The End for the Damned". Packages: `bramin`, `cmd2func`, `coolbox`, `dynamo-release`, `executor-engine`, `executor-http`, `funcdesc`, `magique`, `magique-ai`, `mrbios`, `napari-ufish`, `nucbox`, `okite`, `pantheon-agents`, `pantheon-toolsets`, `spateo-release`, `synago`, `ufish`, `uprobe`.
  - **Novel PyPI delivery — Python startup-hook ("`.pth`") execution**: each wheel ships a tiny `<name>-setup.pth` file. Python auto-executes any line in a `.pth` file that begins with `import`, so the hook execs an obfuscated `_index.js` loader at interpreter startup — triggering on a plain `import` with NO `setup.py`/build step and NO `preinstall`/`postinstall` hook to monitor. This is the PyPI analog of the June 3 npm "Phantom Gyp" `binding.gyp` trick.
  - **Payload hashes (SHA-256)** — wired into `MALICIOUS_HASHLIST`: `c539766062555d47716f8432e73adbe3a0c0c954a0b6c4005017a668975e275c` (setup.pth hook, identical across all wheels), `dc48b09b2a5954f7ff79ab8a2fd80202bd3b59c08c7cdbc6025aa923cb4c0efe` (`_index.js` loader, 4.8 MB / 17 packages), `e1342a80d4b5e83d2c7c22e1e0aaa95f2d88e3dbf0d853a4994b180c93a4b17d` (`_index.js` loader variant, 4.7 MB / 2 packages).
  - **New content-pattern check `check_hades_miasma_indicators`** (near-zero-FP literal matches): the Hades dead-man's-switch token-nuke marker `IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully`, the exfil-repo beacon/description `Hades - The End for the Damned`, and the C2 camouflage path `api.anthropic.com/v1/api` (a path under the legitimate Anthropic API host that is not a real endpoint). Exfil repos use Greek-underworld names (stygian, tartarean, cerberus, charon, styx, lethe, thanatos, persephone); persistence via `gh-token-monitor`, `~/.local/share/updater/update.py`, `.claude/setup.mjs`, and a `.github/workflows/codeql.yml` injector ("Run Copilot").
  - **Backfill of June 1/3 Miasma markers** that were previously documented but never actively matched: added `Miasma - The Spreading Blight` to the malicious-repository-description list and the `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner` token-nuke marker to active content detection.
  - Source:
    - https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave
- **IronWorm ("Shai-Hulud's rustier cousin") coverage (June 3, 2026)**: Added 37 npm package versions from a distinct, concurrent campaign disclosed by JFrog — a Rust-based infostealer (with an eBPF kernel rootkit, Exodus-wallet seed-phrase theft, and Kubernetes/Vault targeting) pushed through packages all published by the npm account `asteroiddao` (operator `ocrybit`) across the weavedb / arnext / cwao / wdb Arweave-Web3 ecosystem (`weavedb-sdk`, `weavedb-sdk-node`, `arnext`, `cwao`, `wao`, `zkjson`, `aonote`, `fpjson-lang`, etc.). Delivery is a `preinstall: "./tools/setup"` ~976 KB ELF hook; the worm also rewrites existing GitHub Actions workflows for persistence. The operator leaked their own Ethereum address `0x7e28D9889f414B06c19a22A9Bd316f0AC279a4d6` (hardcoded BIP-39 seed in the exfil skip-list), which is now added to the known-attacker-wallet content check in `check_crypto_theft_patterns`. Fixtures: `test-cases/ironworm-attack/` (HIGH — 5 compromised versions plus an **inert** JS file carrying only the leaked wallet string) and `test-cases/ironworm-clean/`.
  - Source:
    - https://research.jfrog.com/post/iron-worm-shai-hulud-rustier-cousin/
- **Test fixtures**: `test-cases/hades-miasma-pypi-attack/` (HIGH-risk: 5 compromised PyPI versions plus an **inert** `.py` file carrying the token-nuke/beacon/C2 marker strings as comments — no executable payload) and `test-cases/hades-miasma-pypi-clean/` (last-known-good versions, one release below each compromised version). A dedicated assertion block in `run-tests.sh` locks in the four Hades content IoCs.

### Fixed
- **Digit-leading npm package names were silently dropped**: npm names may begin with a digit (e.g. `02-echo`), but the bare-entry branch of the package loader and the package.json lookup table both anchored on `^[@a-zA-Z]`, so such entries were neither loaded nor matched. Both now use `^[@a-zA-Z0-9]`. This restores the previously-uncounted `02-echo:0.0.7` entry (loader npm count 3200 → 3201) and is covered by the new `digit-name-package-attack` regression fixture.
- **Self-detection false positives when the detector is scanned (issue #146)**: when `shai-hulud-detector.sh` is vendored/cloned inside the directory tree being scanned, the scan no longer flags the detector's own files. Its `test-cases/` fixtures contain *real* attacker wallet addresses, fake Bun installers, and malicious workflow files by design, and its source / `CHANGELOG.md` / `compromised-packages.txt` carry IoC literals as data — so a plain project (e.g. a PHP app with the tool checked in alongside) was reported as HIGH RISK against the tool's own files. The collector now resolves the detector's own installation directory and excludes it from the file inventory and from the checks that run their own `find` (e.g. the GitHub Actions runner check), but only when the detector actually lives inside the scan root — so scanning an individual `test-cases/` fixture (as the test suite does) is unaffected. A regression test in `run-tests.sh` builds a project containing a working in-tree copy of the detector and asserts it stays clean.
- **Empty file list caused a current-working-directory scan (issue #148)**: when a scan target contained no files of a given category, the `fast_grep_files`, `fast_grep_files_i`, and `fast_grep_files_fixed` helpers piped an *empty* list into `xargs -0 <tool>`. GNU `xargs` (Linux) runs the command once on empty input with no path arguments, so `git grep --no-index` / `rg` fell through to recursively scanning the **current working directory** — producing false positives whose paths pointed at the launch directory (the detector's own `test-cases/`, `/tmp` contents, or, in `--bulk` mode, the report files it had just written). BSD `xargs` (macOS) does not run on empty input, so the bug was invisible on macOS. Each helper now reads its input first and returns early when empty, never invoking the grep tool with no paths. This is distinct from issue #146 (self-detection of a vendored copy): #148's fall-through scans the CWD regardless of the scan target. A cross-platform regression test in `run-tests.sh` shadows `xargs` with a sentinel stub, sources the real helpers out of the detector, and asserts empty input never reaches `xargs`.

### Changed
- **`compromised-packages.txt`**: backfilled two versions confirmed by authoritative enumerations but missing from the original imports — `@redhat-cloud-services/vulnerabilities-client:2.1.8` (completes JFrog's 96 versions / 32 packages for the June 1 wave) and `autotel-mcp:29.0.1` (present in Snyk's node-gyp zero-day listing for the June 3 Phantom Gyp wave). Header counter: 3,200+ → 3,290+ (37 Hades PyPI + 37 IronWorm npm entries + these backfills).
- **`README.md`** counter: 3,200+ → 3,290+; new campaign rows in the wave table (Hades + IronWorm).
- **`shai-hulud-detector.sh`**: registered `check_hades_miasma_indicators` in the advanced-detection stage; added the three Hades payload hashes to `MALICIOUS_HASHLIST`; added the two Miasma/Hades repo descriptions to `check_malicious_repo_descriptions`; and added the IronWorm operator wallet to the known-attacker-wallet list in `check_crypto_theft_patterns`.
- **`run-tests.sh`**: registered five new `EXPECTED` fixtures — `hades-miasma-pypi-attack`/`hades-miasma-pypi-clean`, `ironworm-attack`/`ironworm-clean`, and `digit-name-package-attack` — plus dedicated assertion blocks for the Hades content IoCs, the IronWorm package+wallet IoCs, the issue #146 self-exclusion regression, and the issue #148 empty-input/CWD-scan regression (one assertion per `fast_grep_files*` helper). Suite: 173 → 188 checks.

## [3.7.0] - 2026-06-03

### Added
- **Miasma: Phantom Gyp self-spreading worm wave coverage (June 3, 2026)**: Added 286 malicious version entries across 57 distinct npm packages published in a rolling 2-hour burst by the same "Miasma: The Spreading Blight" campaign that hit `@redhat-cloud-services` two days earlier. First victim was `@vapi-ai/server-sdk` (408K downloads/month) at 23:30 UTC; within an hour ~50 packages in the `jagreehal` ecosystem (`autotel-*`, `awaitly-*`, `executable-stories-*`, `node-env-resolver-*`) plus `ai-sdk-ollama` (120K downloads/month) were republished by the compromised maintainer accounts. Cross-ecosystem: the worm also injects into RubyGems via `extconf.rb`.
  - **Novel delivery mechanism — "Phantom Gyp"**: a 157-byte `binding.gyp` file with the GYP command-substitution syntax `<!(node index.js > /dev/null 2>&1 && echo stub.c)` triggers code execution during `npm install`'s `node-gyp rebuild` step **without** declaring any `preinstall`/`postinstall` script in `package.json`. This bypasses every install-script monitor that only watches the `package.json` scripts block. First observed in-the-wild abuse of `binding.gyp` for supply-chain execution. Detection in this PR is version-pinned via the `compromised-packages.txt` list; a future scanner enhancement may add a `binding.gyp` content-pattern check for the `<!(node ...)` invocation.
  - **Payload hashes (SHA-256)**: `ef641e956f91d501b748085996303c96a64d67f63bfeef0dda175e5aa19cca90` (binding.gyp, 157 bytes), `5926b86b642e00672252953eb30d8f75cfb7797fe3118bd6fa2cfbee92905d61` (4.5MB obfuscated index.js root loader), `da39146ef451d1b174a24d00b1e2a45cd38d54e849737f8f35333dcb22175707` (668KB decrypted main payload). Obfuscation stack: ROT-9 through ROT-20 Caesar + `eval`, AES-128-GCM self-decrypting blobs with embedded keys/IVs, a 907-byte Bun runtime loader that fetches `bun-v1.3.13` from `oven-sh/bun` releases, and obfuscator.io wrapping a 2,306-entry encrypted string table on the main payload.
  - **Credential targets (20+ types)**: GitHub PATs and Actions secrets via `/proc/<pid>/mem` reads of `Runner.Worker`, AWS (env + IMDSv2 + ECS), GCP (`GOOGLE_APPLICATION_CREDENTIALS`, service account keys), Azure (managed identity / IMDS), Kubernetes service accounts, HashiCorp Vault tokens, CircleCI, npm tokens, SSH keys, Docker socket creds (with host-socket container-escape attempt), 1Password, gopass, pass, and DB connection strings.
  - **Self-propagation**: validates each stolen npm token against the keyword `IfYouInvalidateThisTokenItWillNukeTheComputerOfTheOwner`, enumerates the victim's packages, injects the `binding.gyp` + `index.js` payload into fresh tarballs, and republishes — with Sigstore provenance forgery in CI environments. C2 beacon for channel checks: GitHub commit search for `thebeautifulmarchoftime` (unauthenticated). User-Agent spoofed as `python-requests/2.31.0` despite Bun runtime execution.
  - **Persistence (AI-assistant + editor poisoning via stolen GitHub tokens)**: `.claude/setup.mjs` (Anthropic Claude), `.cursor/rules/setup.mdc` (Cursor AI), `.vscode/tasks.json` with `runOn: folderOpen`, and `.github/setup.js` GitHub Actions workflow injector.
  - **Exfiltration**: HTTPS POST to GitHub Contents API `repos/liuende501/{repo}/contents/results/results-{timestamp}.json` with RSA-encrypted JSON envelopes. Repos under `github.com/liuende501` (236 at StepSecurity disclosure, 321+ at Snyk follow-up) are named after Dune (`atreides`/`fedaykin`/`sardaukar`) and mythology (`nemean`/`hydra`/`cerberus`/`chimera`) terms; 34 repo descriptions are tagged `Miasma - The Spreading Blight`; 195 carry the reversed beacon `niagA oG eW ereH :duluH-iahS`.
  - Sources:
    - https://www.stepsecurity.io/blog/binding-gyp-npm-supply-chain-attack-spreads-like-worm
    - https://snyk.io/blog/node-gyp-supply-chain-compromise-self-propagating-npm-worm-binding-gyp/
    - https://security.snyk.io/node-gyp-supply-chain-compromise-june-2026
    - https://securityboulevard.com/2026/06/new-shai-hulud-miasma-wave-hits-hundreds-of-npm-packages/
    - https://cybersecuritytimes.com/binding-gyp-attack/
- **Test fixtures**: `test-cases/miasma-binding-gyp-attack/` (HIGH-risk, 5 compromised versions spanning `@vapi-ai/server-sdk@1.2.2`, `ai-sdk-ollama@3.8.5`, `autotel-mcp@28.0.3`, `awaitly-postgres@23.0.1`, `wrangler-deploy@1.5.5`) and `test-cases/miasma-binding-gyp-clean/` (last-known-good versions of the same package families, verified absent from `compromised-packages.txt`).

### Changed
- **`compromised-packages.txt`** header counter: 2,900+ → 3,200+ (file now contains 3,219 entries; 286 new + 2,933 prior).
- **`README.md`** counter: 2,930+ → 3,200+ on the lead-paragraph and detection-coverage descriptions.
- **`run-tests.sh`**: registered `miasma-binding-gyp-attack` (HIGH) and `miasma-binding-gyp-clean` (clean) in the `EXPECTED` array.

## [3.6.0] - 2026-06-01

### Added
- **Miasma: @redhat-cloud-services npm scope compromise coverage**: Added 95 malicious version entries across 31 distinct npm packages published via the compromised `@redhat-cloud-services` scope on 2026-06-01. A compromised Red Hat employee GitHub account injected malicious code via orphan commits bypassing code review, then a malicious GitHub Actions workflow published backdoored versions with valid SLSA provenance attestations using OIDC `id-token:write`. The 4.2MB obfuscated `index.js` payload uses four layers of obfuscation (ROT-21 → AES-128-GCM → obfuscator.io → B5 cipher with PBKDF2 200k iterations) and operates as a multi-stage credential harvester targeting GitHub/CI tokens, AWS/GCP/Azure creds, Kubernetes, Vault, npm/PyPI tokens, SSH keys, Docker, and GPG. Novel technique: reads `/proc/<pid>/mem` targeting `Runner.Worker` process to extract live GitHub Actions secrets marked `isSecret: true`, bypassing log masking. Exfiltration via GitHub Contents API dead-drop (base64-encoded data written to victim-controlled repos). Persistence via `.claude/settings.json` `SessionStart` hooks and `.vscode/tasks.json` `folderOpen` tasks. Self-propagating worm capability uses harvested npm tokens with `bypass_2fa` to republish backdoored packages autonomously. Two waves at 10:53 UTC and 13:44-13:46 UTC. ~80,000 aggregate weekly downloads. Wiz Research names this campaign "Miasma: The Spreading Blight".
  - Sources:
    - https://www.wiz.io/blog/miasma-supply-chain-attack-targeting-redhat-npm-packages
    - https://www.stepsecurity.io/blog/multiple-redhat-cloud-services-npm-packages-compromised
    - https://github.com/RedHatInsights/javascript-clients/issues/492
- **Test fixtures**: `test-cases/redhat-miasma-attack/` (HIGH-risk, 5 compromised versions) and `test-cases/redhat-miasma-clean/` (safe prior versions).

### Changed
- **`compromised-packages.txt`** header updated: 2,800+ → 2,900+, date range extended to June 2026.
- **`README.md`** updated: version count 2,830+ → 2,930+, date range → June 2026.
- **`run-tests.sh`**: registered `redhat-miasma-attack` (HIGH) and `redhat-miasma-clean` (clean) in the EXPECTED array.

## [3.5.0] - 2026-05-27

### Added
- **Two new package ecosystems: Composer (PHP / Packagist) and Crates (Rust / crates.io).** Both are first-class members of the ecosystem abstraction — auto-detected from marker files (`composer.json`/`composer.lock`, `Cargo.toml`/`Cargo.lock`), selectable via `--ecosystem=composer` / `--ecosystem=crates`, and parsed by pure-bash awk parsers (`parse_composer_json`, `parse_composer_lock`, `parse_cargo_toml`, `parse_cargo_lock`) with no PHP or Rust toolchain required. New `composer:vendor/package:version` and `crates:name:version` prefixes are recognised in `compromised-packages.txt`; `check_composer_packages` / `check_crates_packages` do the same sorted `comm -12` set-intersection used for npm/PyPI. The Composer manifest/lockfile lists exclude vendored copies under `vendor/`; Crates excludes build output under `target/`.
- **TrapDoor coverage (May 22-25, 2026 — TeamPCP / UNC6780).** First multi-ecosystem campaign in the database: 34 packages / 384+ versions across npm + PyPI + Crates.io stealing wallets (Solana/Sui/Aptos), SSH keys, AWS creds, GitHub tokens, browser DBs and env vars. Because **all** published versions of the campaign packages are malicious, `check_trapdoor_indicators` detects them version-agnostically by name-matching the 32 distinct package names against the parsed dependency set of every ecosystem (chain-key-validator and defi-threat-scanner overlap with the May 20 Web3/DeFi MCP wave and stay attributed there). It also matches the `P-2024-001` campaign marker, the Crates `build.rs` XOR key `cargo-build-helper-2026`, the "Universal AI Agent Extraction Framework" string, the `trap-core.js` payload, the C2-hosted framework docs (`AUDIT-MATRIX.md`/`BYPASS.md`/`PAYLOAD.md`/`SWARM.md`), and the GitHub-Pages C2 path `ddjidd564.github.io/defi-security-best-practices` (same `ddjidd564` account as the May 20 wave). The one disclosed concrete version (`pypi:eth-security-auditor:0.1.0`) is also pinned in the package list. No SHA-256 hashes were published for this campaign, so none were invented.
- **Laravel-Lang Composer tag-rewrite coverage (May 22, 2026).** An attacker with push access force-rewrote 700+ git tags across four community packages (`laravel-lang/lang` ~502 tags, `/http-statuses`, `/attributes`, `/actions`) so that **every** version resolves to a malicious commit and RCE fires on Composer autoload — defeating version pinning entirely. `check_laravel_lang_indicators` flags any dependency on the four packages regardless of version, and matches the `flipboxstudio.info` C2 (+`/payload`, `/exfil`), the `DebugElevator`/`DebugChromium` Windows infostealer strings, the `Chromium-DebugElevator` PDB hint, and the three disclosed malicious commit SHAs (searched in `composer.lock` `reference` fields too). The disclosed malicious tags are pinned in the package list as `composer:` entries (`laravel-lang/lang:15.29.5`, `laravel-lang/http-statuses:3.4.5`/`3.4.0`).
- **node-ipc backdoor coverage (May 14, 2026).** Three versions (`node-ipc:9.1.6`/`9.2.3`/`12.0.1`, published by the hijacked `atiertant` account) added to the package list. An obfuscated IIFE appended to `node-ipc.cjs` fires on every `require('node-ipc')` and DNS-exfiltrates credential files to `sh.azurestaticprovider.net` (37.16.75.69, suffix `bt.node.js`). The real `node-ipc.cjs` SHA-256 (`96097e06…`) was added to `MALICIOUS_HASHLIST`; `check_node_ipc_indicators` matches the C2 host/IP and the unique `__ntRun` export marker + `qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi` key material. (Explicitly distinct from the unrelated 2022 node-ipc protestware.)
- **Bitwarden CLI coverage (April 22, 2026 — "Shai-Hulud: The Third Coming").** `@bitwarden/cli:2026.4.0` added to the package list; malicious for ~1.5h on npm as a downstream effect of the Checkmarx `ast-github-action` breach. `check_bitwarden_indicators` matches the `bw1.js` payload filename, the `audit.checkmarx.cx` C2 (94.154.172.43), and the beacon strings "Shai-Hulud: The Third Coming", "Would be executing butlerian jihad!", and "LongLiveTheResistanceAgainstMachines".
- **Nx Console 18.95.0 coverage (May 18, 2026 — TeamPCP; the GitHub-internal breach).** A trojan VS Code extension fetched a ~498KB payload from an orphan commit in the official `nrwl/nx` repo via `npx -y github:nrwl/nx#558b09d7`, stole developer + cloud secrets, and specifically targeted `~/.claude/settings.json`. `check_nx_console_indicators` matches the orphan-commit SHA `558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2`, its tree `ba642fe2…`, the `github:nrwl/nx#558b09d7` npx ref, and the unique `__DAEMONIZED=1` / `install-mcp-extension` / `nxConsole.mcpExtensionInstalledSha` / `firedalazer` markers. The three payload SHA-256s (VSIX, `index.js`, `main.js`) were added to `MALICIOUS_HASHLIST`. Its `kitty-monitor`/`cat.py`/`.gh_update_state` persistence is the **same** as the May 19 Mini Shai-Hulud wave and is already caught by `--check-host`.
- **Generic AI-assistant config-dropper check (`check_ai_assistant_dropper`).** New cross-cutting detection for the May 2026 theme of weaponising AI coding assistants: (a) malicious `.cursorrules` / `CLAUDE.md` / `AGENTS.md` droppers carrying the TrapDoor extraction-framework markers; (b) the `mouse5212-super-formatter` "Malware-Slop" npm package (May 26, 2026) that abuses Claude's `/mnt/user-data` upload directory and ships the attacker's own hard-coded GitHub PAT (account `unplowed3584`); and (c) with `--check-host`, inspection of `~/.claude/settings.json` for the Nx Console payload's persistence markers.
- **New SHA-256 hashes** in `MALICIOUS_HASHLIST` (16 → 20): `node-ipc.cjs` backdoor (Datadog), and the Nx Console `index.js` / `main.js` / VSIX payloads (Ox Security).
- **`collect_all_files`** now also collects `*.cjs` (into `code_files`), `*.php` (into `script_files`), `composer.json`/`composer.lock`, `Cargo.toml`/`Cargo.lock`, the AI-config filenames (`.cursorrules`/`CLAUDE.md`/`AGENTS.md`), and the new payload filenames (`node-ipc.cjs`, `bw1.js`, `trap-core.js`, `AUDIT-MATRIX.md`, `SWARM.md`). `node-ipc.cjs`, `bw1.js`, and `trap-core.js` were added to the hash-priority filter so they're hashed even inside dependency trees.
- **Seven new test fixtures**: `trapdoor-attack` (npm+PyPI+Crates name match + content markers + `.cursorrules` dropper), `laravel-lang-attack` (Composer name match + exact version + C2/payload/commit-SHA), `node-ipc-attack`, `bitwarden-attack`, `nx-console-attack`, `malware-slop-attack`, and `composer-crates-clean` (negative test that the two new ecosystems are detected and produce zero findings on safe versions).

### Changed
- **Package count**: `compromised-packages.txt` expanded by 8 exact-version entries (`@bitwarden/cli`, `node-ipc` ×3, `eth-security-auditor`, `laravel-lang/*` ×3). The bulk of the new coverage (TrapDoor's 32 names, Laravel-Lang's 4 packages across all tags) is version-agnostic by design and lives in the dedicated `check_*_indicators` functions rather than per-version entries.
- **`SUPPORTED_ECOSYSTEMS`**: `npm pypi` → `npm pypi composer crates`. The loader's startup summary now reports composer/crates counts.
- **Stage 5/6 banner** now lists `trapdoor`, `laravel-lang`, `node-ipc`, `bitwarden`, `nx-console`, and `ai-droppers`.
- **Test count**: 122 → 169 (+7 fixtures registered in the EXPECTED table, +40 new content-IoC / negative / regression assertions across the six campaigns, the clean ecosystem fixture, and the `--ecosystem=all` set-e regression).

### Fixed
- **`--ecosystem=all` (and explicit `--ecosystem=<eco>` for an ecosystem with no marker files) aborted after Stage 1** under `set -eo pipefail`: `ecosystem_banner`'s per-ecosystem marker count ran a `grep | grep -v | wc -l` pipeline whose leading `grep` exits non-zero on no match, tripping `set -e`. Pre-existing, but newly prominent now that `--ecosystem=all` activates four ecosystems (most projects use one or two). The count is now guarded with `|| true` + a default so the banner — and the full scan — always completes.

### Security
- Added high-confidence detection for six newly disclosed campaigns and two new ecosystems, documented in:
  - https://socket.dev/blog/trapdoor-crypto-stealer-npm-pypi-crates
  - https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack
  - https://socket.dev/blog/laravel-lang-compromise
  - https://securitylabs.datadoghq.com/articles/node-ipc-npm-malware-analysis/
  - https://socket.dev/blog/bitwarden-cli-compromised
  - https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w
  - https://www.ox.security/blog/teampcp-strikes-again-how-a-trojan-vs-code-extension-brought-down-github/
  - https://thehackernews.com/2026/05/malicious-npm-package-stole-files-from.html

## [3.4.3] - 2026-05-21

### Fixed
- **Paranoid-mode `rn` confusable-substring false positive**: `check_typosquatting`'s confusable-character check used a bare substring match — any package name containing `rn`, `vv`, `cl`, `ii`, `nn`, or `oo` was flagged as a potential typosquat. That correctly catches real typosquats like `rnodule` (which substitutes `rn` for `m` to impersonate `module`), but also produced a flood of false positives on every legitimate name that happens to contain one of those bigrams: `yarn`, `intern`, `return`, `learn`, `barn`, `modern`, and dozens of others. The intent of the check has always been to detect character substitutions that produce known popular package names, but the original implementation parsed the substitution target (e.g. `:m` in `rn:m`) without ever using it. The check now actually applies the substitution and only flags the name if the result matches a popular package — so `cornrnander` still triggers a warning ("resembles popular package `commander`") but `yarn` (substituted form `yam`) does not.
- **Regression test**: New `test-cases/paranoid-confusable-fp/` fixture mixes four legitimate names containing confusable bigrams (`yarn`, `intern`, `return`, `modern`) with one synthetic typosquat (`cornrnander`). A new paranoid-mode assertion block in `run-tests.sh` verifies that `cornrnander` is flagged ("resembles popular package commander") and that none of the four legitimate names are flagged. Six new assertions in total.

### Changed
- **Test count**: 116 → 122 (+1 fixture entry + 5 paranoid-mode assertions: 1 positive + 4 negative).
- **Confusable check finding text**: now includes the substituted form and the popular package it resembles, e.g. `Potential typosquatting via 'rn'->'m' substitution: 'cornrnander' resembles popular package 'commander'`, so users can immediately judge whether the finding is a real typosquat or a false positive.

## [3.4.2] - 2026-05-21

### Added
- **sl4x0 dependency-confusion campaign coverage (June 2025 → March 2026)**: SafeDep documented a sustained dependency-confusion operation targeting Fortune 500 companies. 92+ packages published across 32 throwaway accounts (all under `*@sl4x0.xyz` email domain; account names follow `<target>poc` convention). Payload is DNS-only reconnaissance — reads OS username + hostname + cwd basename + timestamp and exfils via DNS query to `oob.sl4x0.xyz`. No persistence, no file or credential theft. Likely security research / bug bounty given the explicit "poc" naming, but the code DID execute on install and leak developer identity to a third party.
  - **22 still-live `name:version` entries** added to `compromised-packages.txt` (the 70+ already-removed packages are caught by the publisher-fingerprint check below): `oc-aa-module-client@9.9.10`, `oc-navbar-module-client@9.9.10`, `oc-ccp-module-client@9.9.10`, `oc-pdc-module-client@9.9.0`, `oc-conversation-history-module-client@9.9.0`, `oc-ecm-module-client@9.9.0`, `oc-cip-module-client@9.9.0`, `oc-recommendedupgrade-module-client@9.9.0`, `oc-agent-toolbar-module-client@9.9.0`, `oc-pico-module-client@9.9.0`, `@phonos/types@9.9.10`, `@wame/ngx-frf-utilities@9.9.11`, `@wame/ngx-adfs@9.9.11`, `cclr-component-resources@9.9.10`, `@ceeferenderer/itg-renderer-sdk@99.9.9`, `@ceeferenderer/fe-renderer-sdk@99.9.9`, `cr-static-shared-components@9.9.9`, `@the-coca-cola-company/ngps-global-common-utils@9.9.9`, `@the-coca-cola-company/receipt-scanner-admin-lib@9.9.9`, `@cloudsop/hmoment@9.9.9`, `tombac-chronos@9.9.9`, `ftapi-core@99.9.9`.
  - **New `check_sl4x0_indicators` function** matches: C2 domain `oob.sl4x0.xyz` (bare and defanged), publisher email-domain fingerprint `@sl4x0.xyz` (catches every package the campaign has ever published, including the 70+ removed ones, as long as the cached package.json is on disk), fabricated GitHub org `slaxorg`, and the two unique hex-named payload helpers `lib/b02e30.js` and `lib/6ad264.js`.
  - **New `test-cases/sl4x0-attack/`** fixture with a synthetic `node_modules/oc-aa-module-client/` layout exercising every IoC class.
  - Source: https://safedep.io/sl4x0-dependency-confusion-campaign/
- **art-template npm hijack coverage (March 2025 → May 2026)**: Compromised maintainer account (`daughtrymom` on npm, `goofychris` on GitHub — renamed from `aui` in late November 2024) injected a stage-1 loader into the package's browser bundle (`lib/template-web.js`). Payload chain-loads an iOS browser exploit kit attributed by Google TAG to the Chinese financially-motivated threat actor UNC6691. Distinct from TeamPCP / Mini Shai-Hulud / Megalodon / Polymarket / sl4x0 — no actor or infrastructure overlap.
  - **4 versions** added to `compromised-packages.txt`: `art-template@4.13.3`, `art-template@4.13.4`, `art-template@4.13.5`, `art-template@4.13.6`.
  - **2 stage-2/4 payload SHA-256 hashes** added to `MALICIOUS_HASHLIST`: `d8e3973a…` (stage-2 jia.js/art.js loader) and `f31bdd06…` (stage-4 loader `49554fde7424c31c.js`). Priority-files filter extended so these are hashed even inside `node_modules/`.
  - **New `check_art_template_indicators` function** matches: C2 domains `v3.jiathis.com`, `git.youzzjizz.com`, `utaq.cfww.shop`, `l1ewsu3yjkqeroy.xyz` (all with defanged variants), API endpoint `/api/ip-sync/sync`, threat-actor publisher fingerprints (`v4v5qc`, `npmpacketmaintainmember7`, `daughtrymom` in `_npmUser` metadata; `goofychris` in GitHub URL references; `eb8org@gmail.com`, `npmpacketmaintainmember7@proton.me` email addresses), and the obfuscation seed `cecd08aa6ff548c2`.
  - **New `test-cases/art-template-attack/`** fixture with a synthetic `node_modules/art-template/` layout (minified-JSON `_npmUser` to match npm's post-install cache format).
  - Important note: payload activates ONLY in browser context (no preinstall/postinstall). Node.js server-side consumers are unaffected unless they explicitly load the browser bundle.
  - Source: https://safedep.io/art-template-npm-supply-chain-compromise
- **durabletask PyPI compromise coverage (May 19, 2026)**: Three malicious `durabletask` versions published within 35 minutes by a compromised maintainer. Runtime dropper injected at module import time downloads stage-2 payload (`rope.pyz`) from `check.git-service.com` and exfiltrates multi-cloud credentials (AWS / Azure / GCP across all profiles + regions, Kubernetes secrets across all contexts/namespaces, HashiCorp Vault KV, password-manager vaults including 1Password / Bitwarden / pass / gopass, SSH keys, Docker creds, npm/PyPI/Cargo tokens, kubeconfig, Terraform state, VPN configs Tailscale + WireGuard, MCP server configs, `.env` files, shell history, GitHub tokens). Worm capabilities: lateral movement via AWS SSM `SendCommand` (up to 5 EC2 instances) and Kubernetes `kubectl exec` (up to 5 pods). Slavic-folklore beacon strings (FIRESCALE, BABA-YAGA-KOSCHEI, "PUSH UR T3MPRR") in commit messages and exfil repos.
  - **Notable**: secondary C2 is `t.m-kosche.com` — **the same C2 as the May 19 Mini Shai-Hulud atool/AntV wave** (already covered by `check_mini_shai_hulud_indicators`). Strong toolkit overlap with TeamPCP suspected but not asserted in the disclosure.
  - **3 PyPI versions** added to `compromised-packages.txt`: `pypi:durabletask:1.4.1`, `pypi:durabletask:1.4.2`, `pypi:durabletask:1.4.3`.
  - **1 stage-2 payload SHA-256** added to `MALICIOUS_HASHLIST`: `069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce` (the `rope.pyz` downloaded from C2). Priority-files filter extended so it's hashed even inside virtualenvs / site-packages.
  - **New `check_durabletask_indicators` function** matches: primary C2 `check.git-service.com` (and defanged), C2 endpoints `/api/public/version`, `/v1/models`, `/rope.pyz`, `/audio.mp3`, the three beacon strings, the `rope.pyz` filename anywhere in the tree, and the persistence artifacts `pgsql-monitor.service` + `pgmonitor.py` + `~/.cache/.sys-update-check{,-k8s}` markers (both as direct path lookups and as anywhere-in-tree filename matches). The check scans code, script, AND yaml file lists so Python `__init__.py` injection points get caught.
  - **New `test-cases/durabletask-attack/`** fixture with `pyproject.toml` + synthetic `site-packages/durabletask/__init__.py` + `pgsql-monitor.service` exercising every IoC class.
  - Source: https://safedep.io/malicious-durabletask-pypi-supply-chain-attack
- **`run-tests.sh` content-IoC assertion blocks** for all three new campaigns: 6 assertions for sl4x0, 9 for art-template, 10 for durabletask. Total: 25 new positive assertions plus 3 new EXPECTED-table fixtures (`sl4x0-attack`, `art-template-attack`, `durabletask-attack`).

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 2,800 to 2,829 confirmed package versions (+22 sl4x0 + 4 art-template + 3 durabletask).
- **`MALICIOUS_HASHLIST`**: 11 → 14 hashes (+ art-template stage-2 + art-template stage-4 + durabletask rope.pyz).
- **`collect_all_files`**: extended with `b02e30.js`, `6ad264.js`, `49554fde7424c31c.js`, `rope.pyz`, `pgmonitor.py`, `pgsql-monitor.service`, `template-web.js` so the new filename-based artifact matches have something to find.
- **`check_file_hashes` priority filter**: now also covers `49554fde7424c31c.js`, `rope.pyz`, `template-web.js`, `pgmonitor.py` — so they're hashed even inside `node_modules/` / site-packages.
- **Stage 5/6 banner**: now lists `sl4x0`, `art-template`, and `durabletask` alongside the existing campaign checks.
- **Test count**: 88 → 116 (+3 fixtures, +25 content-IoC assertions).

### Security
- Added high-confidence detection for three additional campaigns documented in:
  - https://safedep.io/sl4x0-dependency-confusion-campaign/
  - https://safedep.io/art-template-npm-supply-chain-compromise
  - https://safedep.io/malicious-durabletask-pypi-supply-chain-attack

## [3.4.1] - 2026-05-21

### Added
- **Polymarket wallet-drainer typosquat coverage (May 21, 2026)**: Nine npm packages from the attacker-controlled `polymarketdev` account impersonate legitimate Polymarket trading tools. The postinstall hook prompts the user through a fake "wallet onboarding" UI, captures raw private keys, and exfiltrates them (plus env vars and `.env` files) to a Cloudflare Workers C2. Distinct from Megalodon and Mini Shai-Hulud — no shared attribution or infrastructure.
  - **18 compromised version artifacts** across 9 packages added to `compromised-packages.txt` (each package has exactly two published versions, `0.1.0` and `0.1.1`, verified against npm's registry on 2026-05-21):
    - `polymarket-trading-cli:0.1.0/0.1.1`
    - `polymarket-terminal:0.1.0/0.1.1`
    - `polymarket-trade:0.1.0/0.1.1`
    - `polymarket-auto-trade:0.1.0/0.1.1`
    - `polymarket-copy-trading:0.1.0/0.1.1`
    - `polymarket-bot:0.1.0/0.1.1`
    - `polymarket-claude-code:0.1.0/0.1.1`
    - `polymarket-ai-agent:0.1.0/0.1.1`
    - `polymarket-trader:0.1.0/0.1.1`
  - **New `check_polymarket_indicators` function** in `shai-hulud-detector.sh` matches:
    - C2 host `polymarketbot.polymarketdev.workers.dev` (and defanged form `polymarketbot.polymarketdev[.]workers[.]dev`)
    - Exfiltration endpoint path `/v1/wallets/keys`
    - Payload SHA-256 `e01b85c1437085a519217338fe4ee5ed7858c28a10f8c1477b2f1857c3386edb` as a literal-string reference (incident-response notes, advisories checked into the repo)
    - Threat-actor publisher fingerprint `"_npmUser":{"name":"polymarketdev"` matched in JSON context (mirrors the `atool`-publisher detection approach from the May 19 wave to avoid bare-name false positives)
    - Attacker GitHub source repo reference `texsellix/polymarket-trading-bot`
    - Local-artifact paths `~/.polybot/device.json` and `~/.polybot/wallets.json` (the dropper's staging files for harvested wallet keys), both as direct path lookups under the scan root and as anywhere-in-tree regex matches against `/\.polybot/(device|wallets)\.json$`
  - **New `test-cases/polymarket-attack/` fixture** pins `polymarket-bot@0.1.0`, includes a `postinstall-trace.js` carrying every content IoC as inert string constants, and includes a synthetic `.polybot/wallets.json` to exercise the staging-artifact match end-to-end.
- **`run-tests.sh` content-IoC assertion block for Polymarket**: 7 new positive assertions covering every IoC class added above. Layout mirrors the existing Megalodon and atool/AntV assertion blocks.

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 2,782 to 2,800 confirmed package versions (+18 Polymarket entries).
- **Stage 5/6 banner**: Now also lists `polymarket` alongside the existing campaign checks.
- **Test count**: 80 → 88 (+1 new fixture, +7 new content-IoC assertions).

### Security
- Added high-confidence detection for the May 21, 2026 Polymarket wallet-drainer typosquat campaign documented in:
  - https://safedep.io/malicious-polymarket-npm-crypto-wallet-drainer

## [3.4.0] - 2026-05-21

### Added
- **Megalodon GitHub-repo backdooring campaign coverage (May 18, 2026)**: Megalodon is a distinct campaign — no asserted attribution, different infrastructure from Mini Shai-Hulud — that injected malicious CI workflow files into 5,561 GitHub repositories over a six-hour window via stolen GitHub PATs and deploy keys. The mass variant injects `.github/workflows/ci.yml` named `SysDiag`; the Tiledesk-targeted variant injects `.github/workflows/docker-community-worker-push-latest.yml` named `Optimize-Build`. Both base64-decode a bash payload that exfiltrates CI secrets, AWS/GCP/Azure/Kubernetes/Vault/Terraform/Docker credentials, SSH keys, and OIDC tokens to `216.126.225.129:8443`. Primary attack surface is server-side (GitHub repo and Actions runtime), but the workflow files become locally visible when contaminated repos are checked out, and one npm package picked up the contamination as fallout.
  - **`@tiledesk/tiledesk-server`** versions `2.18.6`, `2.18.7`, `2.18.8`, `2.18.9`, `2.18.10`, `2.18.11`, `2.18.12` added to `compromised-packages.txt` (Tiledesk maintainer published from their backdoored repo, bundling the malicious workflow into the npm tarball).
  - New `check_megalodon_indicators` function in `shai-hulud-detector.sh` matches:
    - `name: SysDiag` and `name: Optimize-Build` in any `.github/workflows/*.yml` (both are unique-enough names that a literal match is HIGH-confidence)
    - C2 IP literal `216.126.225.129` (bare, with `:8443` port, and defanged `216.126.225[.]129` form) across code + YAML + script files
    - Known malicious commit SHA `acac5a9854650c4ae2883c4740bf87d34120c038` (Tiledesk variant) across the same file set
  - New `test-cases/megalodon-attack/` fixture combining the contaminated Tiledesk version + a synthetic `SysDiag` workflow file carrying all four content IoCs (inert; the actual base64-bash execution is replaced with a harmless `echo`)
  - Source: https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
- **Web3/DeFi MCP-server typosquatting campaign coverage (May 20, 2026)**: 10 npm packages masquerading as Web3/DeFi developer security tools (MCP servers). Distinct from Megalodon and Mini Shai-Hulud — no shared attribution or infrastructure. The payload runs on install AND on every MCP tool invocation, exfiltrating `~/.ssh`, `~/.ethereum`, `~/.bitcoin`, `~/.env`, `~/.bash_history`, `~/.zsh_history`, `~/.git-credentials` to a GitHub Pages dynamic-webhook C2 with a `webhook.site` fallback.
  - Ten compromised versions added to `compromised-packages.txt`: `chain-key-validator:0.2.3`, `defi-env-auditor:0.3.2`, `wallet-security-checker:1.0.3`, `crypto-credential-scanner:2.0.2`, `web3-secrets-detector:1.2.6`, `solidity-deploy-guard:0.4.4`, `mnemonic-safety-check:0.5.2`, `eth-wallet-sentinel:1.0.9`, `deployment-key-auditor:0.7.3`, `defi-threat-scanner:2.1.2`.
  - New `check_web3_mcp_indicators` function matches the primary C2 (`ddjidd564.github.io/defi-security-best-practices/config.json`, including defanged form `ddjidd564[.]github[.]io`) and the fallback webhook (`webhook.site/8d334534-1c63-4f4f-a0d7-95c446c8b233` and the bare UUID) across code files.
  - New `test-cases/web3-mcp-attack/` fixture pins `chain-key-validator@0.2.3` and includes a `postinstall-trace.js` file carrying the C2 / fallback URLs as inert string constants.
  - Source: SafeDep X post 2026-05-21 01:00 UTC (@safedepio) — no long-form blog post yet; package names + versions + C2 endpoints verified from the disclosure screenshot.
- **`run-tests.sh` content-IoC assertion block for Megalodon + Web3-MCP**: 7 new positive assertions that each new IoC produces a specific finding-line substring in the detector output. Layout mirrors the existing May 19 atool/AntV assertion block.

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 2,765 to 2,782 confirmed package versions (+7 Tiledesk + 10 Web3 MCP typosquats).
- **Stage 5/6 banner**: Now lists `megalodon` and `web3-mcp` alongside the existing campaign checks.
- **Test count**: 71 → 80 (+2 new fixtures, +7 new content-IoC assertions).

### Security
- Added high-confidence detection for the May 18, 2026 Megalodon and May 20, 2026 Web3/DeFi MCP-server typosquat campaigns documented in:
  - https://safedep.io/megalodon-mass-github-repo-backdooring-ci-workflows/
  - SafeDep X post 2026-05-21 (@safedepio) — package + IoC inventory for the 10-MCP-server wave

## [3.3.1] - 2026-05-19

### Added
- **Mini Shai-Hulud AntV/atool wave content-pattern IoCs**: PR #136 added the 643 compromised `package:version` entries for the May 19 wave but left the detector script unchanged, which meant a host where the dropper had landed but the compromised npm package had already been uninstalled would still slip past detection. This release extends `check_mini_shai_hulud_indicators` with the May 19 IoCs that don't depend on the package list:
  - **New C2 domain**: `t.m-kosche.com` (the OpenTelemetry-disguised exfiltration endpoint at `/api/public/otel/v1/traces`)
  - **Exfil-repo beacon string**: `niagA oG eW ereH :duluH-iahS` (character-reversed "Shai-Hulud: Here We Go Again", stamped on every fallback exfiltration repo)
  - **Threat-actor publisher fingerprint**: `"_npmUser":{"name":"atool"` — matched in JSON publisher-metadata context (quoted) to avoid false positives on bare `atool` text
  - **Forged commit-author email**: `huiyu.zjt@ant.com` (impostor identity used on the malicious `antvis/G2` commits)
  - **C2 dead-drop trigger keyword**: `firedalazer` (the payload polls GitHub's commit-search API for commits matching this exact word to receive RSA-PSS-signed C2 commands)
  - **Three malicious orphan-commit SHAs in `antvis/G2`**: `1916faa365f2788b6e193514872d51a242876569`, `7cb42f57561c321ecb09b4552802ae0ac55b3a7a`, `dc3d62a2181beb9f326952a2d212900c94f2e13d`
  - **New structural manifest signal**: `"preinstall": "bun run index.js"` in a `package.json` script value (the May 19 install vector), and `github:antvis/G2#<sha>` in any dependency-section value where `<sha>` matches one of the three known orphan commits
  - **New payload SHA-256**: `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c` (the 498KB obfuscated Bun bundle); added to `MALICIOUS_HASHLIST` and to the priority-files filter in `check_file_hashes` so the hash is computed even inside `node_modules`
- **Dead-man's-switch detection extended to the `kitty-monitor` variant**: The May 19 wave renames the persistence daemon from `gh-token-monitor` (May 11) to `kitty-monitor` and adds a GitHub dead-drop fetcher at `~/.local/share/kitty/cat.py`. The same wipe-on-token-revocation trigger semantics apply. The detector now recognises:
  - `~/Library/LaunchAgents/com.user.kitty-monitor.plist` (macOS LaunchAgent)
  - `~/.config/systemd/user/kitty-monitor.service` (Linux systemd user unit)
  - `~/.local/bin/kitty-monitor.sh` (the daemon script)
  - `~/.config/kitty-monitor/` and `~/.config/kitty-monitor/token`
  - `~/.local/share/kitty/cat.py` (the dead-drop fetcher)
  - `/var/tmp/.gh_update_state` (execution-state tracker)
  - The same artifacts inside the scan tree (covers staged install kits and backups of compromised home directories), via an extended in-tree-artifact regex
  - `--check-host` now warns about the kitty-monitor variant with the same CRITICAL "stop service before rotating tokens" remediation order
- **Test fixtures**:
  - `test-cases/atool-attack/index.js` (new): synthetic payload file carrying every May 19 content IoC as inert string constants (C2 domain, beacon, forged-author email, three orphan-commit SHAs, `firedalazer`, `kitty-monitor` reference, `/var/tmp/.gh_update_state`, the `atool` publisher fingerprint). Inert by construction — string assignments only.
  - `test-cases/atool-attack/package.json` (extended): now also carries an `optionalDependencies` entry pointing at `github:antvis/G2#1916faa365…` to exercise the orphan-commit structural check
  - `test-cases/mini-shai-hulud-dead-mans-switch/kitty-monitor.sh`, `com.user.kitty-monitor.plist`, `kitty/cat.py` (new): inert filename-match fixtures for the kitty-monitor variant
- **`run-tests.sh` content-IoC assertion block**: 13 new tests that lock in each May 19 IoC's detection (10 against `atool-attack`, 3 against `mini-shai-hulud-dead-mans-switch`). Each test runs the detector on the relevant fixture and asserts a specific substring appears in the output, so any regression that silently breaks one of the new content checks fails CI.

### Changed
- **`MALICIOUS_HASHLIST`** size: 10 → 11 (added the May 19 payload hash).
- **`collect_all_files`** file collection: added `kitty-monitor.sh`, `com.user.kitty-monitor.plist`, `kitty-monitor.service`, `cat.py` to the `find` clause so the in-tree artifact regex can pick them up.
- **`check_file_hashes`** priority-files regex: extended with `kitty-monitor\.sh` and `cat\.py` so the new payload is hashed even when buried inside `node_modules`.
- **Test count**: 58 → 71 (+13 new content-IoC assertions; package-list and dead-man's-switch fixture exit-code expectations unchanged).

### Security
- Added high-confidence content-pattern detection for the May 19, 2026 Mini Shai-Hulud AntV/atool wave documented in:
  - https://socket.dev/blog/antv-packages-compromised
  - https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem
  - https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
  - https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/
  - https://www.aikido.dev/blog/mini-shai-hulud-antv-npm-supply-chain-attack
  - https://www.ox.security/blog/the-antv-ecosystem-was-compromised-with-shai-hulud-malware-300-packages-affected
  - https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html

## [3.3.0] - 2026-05-19

### Added
- **Mini Shai-Hulud AntV/atool wave coverage**: Added 643 malicious version artifacts across 323 distinct npm packages published by the compromised `atool` npm account on 2026-05-19. This is a new supply chain attack campaign distinct from prior waves and warrants a minor version bump. Vendors describe the timing slightly differently — SafeDep observed two automated waves at 01:39-01:56 UTC and 02:05-02:06 UTC; Socket and StepSecurity describe a single 22-minute burst beginning ~01:56 UTC and continuing through ~02:56 UTC. The campaign hit the `@antv/*` ecosystem hardest (~177 scoped packages), also pulled in `@openclaw-cn`, `@starmind`, and `@lint-md` namespaces, and the high-traffic standalone libraries `size-sensor` (4.2M downloads/month), `echarts-for-react` (3.8M downloads/month), `@antv/scale` (2.2M downloads/month), `timeago.js` (1.15M downloads/month), and `canvas-nest.js`. Aggregate impact ~16M weekly downloads. The payload is a 498KB single-line obfuscated Bun bundle delivered via a `preinstall: bun run index.js` hook (one observed SHA256: `a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c`) that steals 20+ credential types — GitHub/CI tokens, AWS keys, GCP, Azure, Kubernetes service accounts, Vault tokens, SSH keys, Docker creds, DB connection strings — and attempts Docker container escape via the host socket. Primary exfiltration is HTTPS POST to `t.m-kosche.com:443/api/public/otel/v1/traces` with AES-256-GCM payload encryption and RSA-OAEP key wrapping; the GitHub-repo-creation channel (`{dune-word}-{dune-word}-{0-999}`) is a fallback that writes stolen data to `results/results-<timestamp>-<counter>.json`. Every exfil repo is tagged with the beacon string `niagA oG eW ereH :duluH-iahS` (character-reversed "Shai-Hulud: Here We Go Again"). Persistence via `.claude/settings.json` `SessionStart` hooks, `.vscode/tasks.json` `folderOpen` tasks, and a `kitty-monitor` systemd/LaunchAgent unit running `~/.local/share/kitty/cat.py`. Imposter commits planted in `antvis/G2` were forged to appear as `huiyu.zjt <huiyu.zjt@ant.com>` (a real maintainer). Some vendors attribute to TeamPCP (the actor behind the May 12 TanStack wave); Socket and StepSecurity have not asserted attribution.
  - Sources:
    - https://socket.dev/blog/antv-packages-compromised
    - https://www.stepsecurity.io/blog/shai-hulud-here-we-go-again-mass-npm-supply-chain-attack-hits-the-antv-ecosystem
    - https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/
    - https://snyk.io/blog/mini-shai-hulud-antv-npm-supply-chain-attack/
    - https://www.aikido.dev/blog/mini-shai-hulud-antv-npm-supply-chain-attack
    - https://www.ox.security/blog/the-antv-ecosystem-was-compromised-with-shai-hulud-malware-300-packages-affected
    - https://thehackernews.com/2026/05/mini-shai-hulud-pushes-malicious-antv.html
- **Test fixtures** (`test-cases/atool-attack/`, `test-cases/atool-clean/`): An attack fixture containing 5 compromised versions from the wave (`size-sensor@1.0.4`, `echarts-for-react@3.0.7`, `@antv/scale@0.6.2`, `timeago.js@4.1.2`, `@antv/g2@5.5.8`) plus the malicious `preinstall: bun run index.js` script, and a paired clean fixture using the last-known-good versions of the same packages (`size-sensor@1.0.3`, `echarts-for-react@3.0.6`, `@antv/scale@0.5.2`, `timeago.js@4.0.2`) to lock in that the detector flags the attack as HIGH and leaves legitimate consumers untouched.
- **`run-tests.sh` expected results**: Registered `atool-attack` (HIGH) and `atool-clean` (clean) in the `EXPECTED` table so regressions to either side of the new coverage will fail CI.

## [3.2.1] - 2026-05-12

### Added
- **Bulk-mode unreadable-directory reporting**: `--bulk` discovery now records directories it could not read (chmod-000 / chmod-700-owned-by-someone-else / find permission errors) instead of silently dropping them. The unreadable paths are surfaced in three places: on stderr from `--bulk-list`, in the on-console `BULK SCAN SUMMARY` section under "Unreadable (permission denied)", and in a new "Unreadable directories" section of `aggregate-report.md`. The scan exit code is unaffected — this is informational only — but a real audit now sees which directories were invisible to it instead of falsely concluding nothing was missed.
- **Bulk-mode regression tests**: Two new tests in `run-tests.sh` lock in the hardenings: one builds a tree with a chmod-000 project and asserts that the path appears in `--bulk-list` (stderr) and in the aggregate report; the other points `--bulk-output` at a directory inside the scan root with leftover prior-run content and asserts that the output directory is excluded from discovery (so previous-run report files are never re-scanned as fake projects).

### Fixed
- **`--bulk-output` self-reference when placed inside a scan root**: if `--bulk-output` resolved to a path inside one of the `--bulk` scan roots, the output directory itself was treated as a scan target. On first run this just inflated the scanned count; on repeat runs the prior run's `aggregate-report.md` and `per-repo/*.console.txt` files (which legitimately quote attack indicator strings) could trigger content-pattern false positives. The output directory is now resolved to an absolute path before discovery starts and excluded from candidate consideration, both at the top-level discovery loop and inside `_bulk_discover`'s recursive descent.
- **Bulk-mode silent permission-denied skips**: `find` errors during discovery were redirected to `/dev/null`, and the discovery loop's `cd "$child" && pwd` step silently dropped any directory whose read or execute bit was unset. These paths are now captured into a per-run accumulator (`find` stderr lines parsed for the macOS and GNU "Permission denied" formats, plus a parallel record of directories that fail our subsequent readability check) and merged into a sorted, de-duplicated list that is shown to the user.

## [3.2.0] - 2026-05-12

### Added
- **`--bulk` mode**: Scan every project under one or more parent directories in a single invocation and write one aggregate report instead of running the detector by hand for each project. Each project is scanned as an isolated subprocess (one fresh process per project, re-invoked through the same Bash interpreter), so per-project global state never bleeds across scans and the existing `--save-log` contract and exit codes are reused verbatim. `--bulk` is purely additive — single-directory invocations behave exactly as before.
  - **Project discovery**: The positional arguments to `--bulk` are treated as *parent* directories. Under each, the detector descends to find the actual projects: a directory that contains a `.git` directory/worktree file or a recognised manifest/lockfile (`package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock`, `uv.lock`, `requirements*.txt`, `Cargo.toml`, `go.mod`, `composer.json`, `Gemfile`, `pom.xml`, `build.gradle`, `Package.swift`) is taken as one scan unit (so **monorepos are scanned whole**, never split per workspace package); a directory with no marker of its own but with projects beneath it (a "bucket" folder like `~/dev/apps/<project>` or `~/work/clients/<client>/<project>`) is descended into recursively; a folder with no projects anywhere beneath it is scanned as-is so content-pattern checks still run. `node_modules`, `vendor`, `dist`, `build`, `target`, `coverage`, `.venv`, `__pycache__`, `site-packages`, hidden directories, etc. are never descended into. The detector's own repository is skipped automatically (its `test-cases/` fixtures are intentionally malicious).
  - **`--bulk-depth N`** (default `3`): caps how many directory levels below each parent the bucket-descent goes. A directory that already looks like a project is taken whole regardless of depth; the cap only limits descent through nested bucket folders. `--bulk-depth 1` reproduces a flat "one entry per immediate subdirectory" scan.
  - **`--bulk-list`**: with `--bulk`, prints the projects that would be scanned (one absolute path per line) and exits without scanning or writing a report — useful as a dry run before a long bulk scan.
  - **`--bulk-output DIR`** (default `./shai-hulud-bulk-report-<timestamp>/`): where the report is written. The directory is created only once at least one project has been discovered, so a `--bulk` run that finds nothing (e.g. a missing parent directory) leaves no stray output directory behind.
  - **Aggregate report**: `aggregate-report.md` (header metadata, a result-summary table, a per-project results table, per-project findings detail with the flagged paths and a collapsible console excerpt, a clean-projects list, a skipped list, and the exact command to re-run) plus `per-repo/<project>.findings.log` (flagged paths grouped by severity, same format as `--save-log`) and `per-repo/<project>.console.txt` (the full plain-text per-project scan output, ANSI-stripped) for every project. `--paranoid`, `--check-semver-ranges`, `--ecosystem`, `--parallelism`, and the grep-tool flags are passed through to every per-project scan.
  - **Exit code**: `--bulk` aggregates the per-project results — `1` if any project is high-risk, else `2` if any is medium-risk, else `3` if any per-project scan failed to complete, else `0`.
- **`run-tests.sh` bulk-mode tests**: project-discovery assertions via `--bulk --bulk-list` (bucket expansion, monorepos kept whole, `node_modules` / nested non-projects skipped), the `--bulk-depth 1` flat behaviour, an end-to-end `--bulk` run on a synthetic project tree (aggregate report structure, per-project logs, HIGH finding recorded, exit-code aggregation), and the "no stray output directory on a missing parent" behaviour.

### Changed
- **`run-tests.sh` `timeout` dependency is now optional**: the suite uses `timeout` / `gtimeout` when available and runs without a per-test time limit (with a note) when neither is installed, so the full suite passes on macOS without GNU coreutils.

## [3.1.0] - 2026-05-12

### Added
- **PyPI Ecosystem Support**: The detector now scans Python projects in addition to npm. PyPI manifests and lockfiles are parsed for compromised packages using the same set-intersection lookup the npm path uses. PyPI support is purely additive: npm-only projects scan exactly as before with no new findings, flags, or output changes that affect existing CI/CD pipelines.
- **Pure-Bash Python Parsers** (no runtime dependencies; awk-based, cross-platform):
  - `requirements.txt` and `requirements-*.txt` exact pins (`==X.Y.Z`)
  - `pyproject.toml` PEP 621 `[project] dependencies = [...]` arrays
  - `pyproject.toml` Poetry `[tool.poetry.dependencies]` and `[tool.poetry.group.*.dependencies]` tables
  - `Pipfile` `[packages]` / `[dev-packages]` sections
  - `Pipfile.lock` (JSON) `default` / `develop` sections
  - `poetry.lock` `[[package]]` blocks
  - `uv.lock` `[[package]]` blocks
  - PEP 503 name normalization (lowercase, `-`/`_`/`.` collapsed to `-`) applied before lookup
- **Ecosystem Auto-Detection**: New `detect_ecosystems` function scans the file inventory for ecosystem marker files (`package.json` / lockfiles for npm; `pyproject.toml`, `requirements*.txt`, `Pipfile`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg` for PyPI) and runs only the relevant ecosystem-specific checks. Marker discovery excludes `node_modules`, `.venv`, `venv`, `.tox`, and `site-packages` directories.
- **Ecosystem Banner**: A new informational line at scan start prints which ecosystems were detected (for example: `Detected ecosystems: npm (12 marker file(s)), pypi (2 marker file(s))`). When neither ecosystem is detected, content-pattern checks still run.
- **`--ecosystem` CLI Flag**: Optional override. Accepts `npm`, `pypi`, `all`, or a comma-separated list. Default is auto-detect; the flag is purely opt-in and existing invocations continue to work unchanged.
- **Ecosystem Dispatch Table**: New `ECOSYSTEM_CHECK_FUNCTIONS` associative array maps each ecosystem to its check function(s). The dispatcher in `main()` walks `ACTIVE_ECOSYSTEMS` and invokes whatever the table lists, so adding a new ecosystem (Hex, Go, Cargo, RubyGems, etc.) requires zero changes to `main()` — only a row in the marker tables, a row in the dispatch table, a parser, a check function, and a loader-prefix branch. Order of execution honors the order of `ACTIVE_ECOSYSTEMS` (auto-detect mode preserves the prior npm-before-pypi order; `--ecosystem=pypi,npm` lets the user override execution order if needed).
- **PyPI Compromised Packages**: Added 11 confirmed malicious PyPI version artifacts across 6 distinct projects attributed to the TeamPCP threat actor:
  - May 2026 Mini Shai-Hulud cross-ecosystem spread: `pypi:mistralai:2.4.6`, `pypi:guardrails-ai:0.10.1` (Socket-confirmed)
  - April 2026 Mini Shai-Hulud PyPI sub-wave: `pypi:lightning:2.6.2`, `pypi:lightning:2.6.3` (Aikido / Socket / Semgrep / StepSecurity / Sonatype / Lightning AI official postmortem; note: only the `lightning` PyPI dist was affected — the legacy `pytorch-lightning` dist has no 2.6.2/2.6.3 release)
  - April 2026 TeamPCP Xinference compromise: `pypi:xinference:2.6.0`, `pypi:xinference:2.6.1`, `pypi:xinference:2.6.2` (three consecutive releases April 22, 2026; GitGuardian / JFrog)
  - March 2026 TeamPCP Telnyx compromise: `pypi:telnyx:4.87.1`, `pypi:telnyx:4.87.2` (Akamai / The Hacker News / official team-telnyx/telnyx-python issue #235)
  - March 2026 TeamPCP LiteLLM compromise: `pypi:litellm:1.82.7`, `pypi:litellm:1.82.8` (Datadog Security Labs / Sonatype / Truesec / Snyk)
- **Compromised Packages File Format**: The `compromised-packages.txt` format now accepts an optional `ecosystem:` prefix (`npm:` or `pypi:`). Bare entries continue to be interpreted as `npm` for full backward compatibility with external tools that consume this file.
- **PyPI Test Cases**:
  - Added `test-cases/pypi-attack-requirements/` to validate detection of `mistralai==2.4.6` in `requirements.txt`
  - Added `test-cases/pypi-attack-poetry/` to validate detection of `guardrails-ai==0.10.1` in both `pyproject.toml` (Poetry) and `poetry.lock`
  - Added `test-cases/polyglot-attack/` to validate auto-detection of both ecosystems and combined npm + PyPI compromise reporting in a single project
  - Added `test-cases/pypi-clean/` to confirm safe versions of campaign-targeted PyPI packages are not flagged

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 2,111 to 2,122 confirmed package versions (added 11 PyPI entries spanning four TeamPCP-attributed PyPI campaigns from March through May 2026).
- **Internal Map Keys**: `COMPROMISED_PACKAGES_MAP` keys are now ecosystem-prefixed internally (`npm:axios:1.14.1`, `pypi:mistralai:2.4.6`). The `is_compromised_package` helper accepts an optional second argument for ecosystem (default `npm`). External behavior is unchanged.
- **Test Suite Size**: 39 test cases (up from 35 before the 3.0.9 entry counted them; net of 4 new PyPI fixtures).
- **Documentation**: Updated `README.md` to describe ecosystem support, the `--ecosystem` flag, and the PyPI parsers.

### Security
- Added high-confidence detection for the May 2026 PyPI cross-ecosystem spread of the Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime campaign and the earlier TeamPCP-attributed PyPI campaigns documented in:
  - https://x.com/SocketSecurity/status/2054048025081737446
  - https://socket.dev/blog/lightning-pypi-package-compromised
  - https://www.aikido.dev/blog/pytorch-lightning-pypi-compromise-mini-shai-hulud
  - https://www.stepsecurity.io/blog/lightning-obfuscated-javascript-credential-stealer-bundled-in-pypi-wheel
  - https://lightning.ai/blog/pytorch-lightning-supply-chain-attack
  - https://semgrep.dev/blog/2026/malicious-dependency-in-pytorch-lightning-used-for-ai-training/
  - https://blog.gitguardian.com/three-supply-chain-campaigns-hit-npm-pypi-and-docker-hub-in-48-hours/
  - https://research.jfrog.com/post/xinference-compromise/
  - https://www.akamai.com/blog/security-research/telnyx-sdk-pypi-2026-teampcp-supply-chain-attacks
  - https://thehackernews.com/2026/03/teampcp-pushes-malicious-telnyx.html
  - https://github.com/team-telnyx/telnyx-python/issues/235
  - https://securitylabs.datadoghq.com/articles/litellm-compromised-pypi-teampcp-supply-chain-campaign/

### Fixed
- **Paranoid-mode hang on large projects with `node_modules`**: `check_typosquatting` and `check_network_exfiltration` previously iterated over every file in the inventory (including `node_modules`/`vendor`/build-output trees), spawning hundreds of thousands of `git grep` subprocesses on projects with bundled dependencies. Both functions now pre-filter their target lists to exclude `node_modules`, `vendor`, `.git`, `dist`, `build`, `_build`, `deps`, `.next`, `coverage`, `site-packages`, `.venv`, and `venv` before iterating. Each function also now prints a scan-count banner so the effective workload is visible (e.g. `Scanning 49 files for network exfiltration (filtered from 14054 total)`). Result on a 42k-file Phoenix LiveView project with bundled `node_modules`: paranoid mode now completes in ~50 seconds; previously it ran past 2 minutes without exiting. The semantic for these heuristics matches industry convention (`npm audit`, Socket.dev): typosquatting and network-exfil checks examine *your* declared dependencies and code, not transitive deps already resolved inside `node_modules`.
- **`check_network_exfiltration` suspicious-domain regex false positives**: domain strings from the `suspicious_domains` array were interpolated into the grep regex without escaping their literal `.` characters. As a result, `t.me` matched `time`, `theme`, `tame`; `ix.io` matched any `ix<x>io`; `mega.nz` matched any `mega<x>nz`; etc. — producing false positives on common English words, HTML element names (`<time>`), and JSON descriptions. The fix introduces a `domain_esc` local that replaces every `.` with `\.` before interpolating into the regex, while preserving the unescaped `$domain` for the human-readable error message. Verified: legitimate `t.me` URLs (e.g. `https://t.me/abcd1234`, `const ENDPOINT = 't.me';`) still trigger the finding; bare words like `time`/`theme` no longer do.

### Compatibility
- Exit-code contract preserved: `0=clean`, `1=high-risk`, `2=medium-risk`. No new exit codes introduced.
- All existing CLI flags work identically. The new `--ecosystem` flag is optional with an auto-detect default; bare invocations (`./shai-hulud-detector.sh /path`) behave exactly as in 3.0.9.
- npm detection paths run unconditionally regardless of ecosystem detection. PyPI checks are the only ones gated on detection, ensuring zero behavior change for npm-only projects.
- `--save-log` output format unchanged (`# HIGH` / `# MEDIUM` / `# LOW` sections with file paths). PyPI findings are written into the same `# HIGH` section as npm compromised-package findings.
- Compromised-packages.txt format is backward-compatible: bare entries are still parsed as npm. Only new entries are prefixed.
- Pure Bash 5.x + POSIX shell tools; no new runtime dependencies. Tested on macOS Bash 5; same tool surface (awk, grep, find, sort, comm, cut, uniq, tr, xargs) as prior versions, ensuring continued support on Linux and Git Bash for Windows.

## [3.0.9] - 2026-05-12

### Added
- **May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime Coverage**: Added detection for the self-spreading TeamPCP campaign that compromised the TanStack release pipeline on May 11, 2026 and propagated to multiple other namespaces.
- **New Compromised Package Versions**: Added 408 confirmed malicious package versions across the affected namespaces:
  - 84 versions across 42 `@tanstack/*` packages (two versions per package, published roughly six minutes apart)
  - 9 versions across `@mistralai/mistralai`, `@mistralai/mistralai-azure`, `@mistralai/mistralai-gcp`
  - 4 versions of `@opensearch-project/opensearch` (3.5.3, 3.6.2, 3.7.0, 3.8.0)
  - 80 versions across the `@uipath/*` namespace
  - 109 versions across the `@squawk/*` namespace
  - 24 versions across `@tallyui/*`
  - 18 versions of `@beproduct/nestjs-auth`
  - 6 versions of `@taskflow-corp/cli` and 5 of `@tolka/cli`
  - 12 versions across `@supersurkhet/*`
  - 8 versions across `@draftauth/*` and `@draftlab/*`
  - 3 versions across `@cap-js/*`, 2 of `@dirigible-ai/sdk`, 3 of `@mesadev/*`, 4 of `@ml-toolkit-ts/*`
  - Standalone packages: `agentwork-cli` (2), `cmux-agent-mcp` (6), `cross-stitch` (5), `git-branch-selector` (5), `git-git-git` (5), `mbt` (1), `ml-toolkit-ts` (2), `nextmove-mcp` (5), `safe-action` (2), `ts-dna` (5), `wot-api` (4)
- **Mini Shai-Hulud IOC Detection**:
  - Detects payload file names `router_init.js` and `tanstack_runner.js` anywhere in the scan tree
  - Detects SHA-256 hash matches for `router_init.js` (`ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`), `tanstack_runner.js` (`2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`), and the malicious `@tanstack/setup` `package.json` (`7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b`)
  - Detects the wipe-threat token description string `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`
  - Detects marker exfiltration repo names `siridar-ghola-567` and `tleilaxu-ornithopter-43` and the repo description `A Mini Shai-Hulud has Appeared`
  - Detects C2 domains `api.masscan.cloud`, `git-tanstack.com`, `filev2.getsession.org`, `seed1.getsession.org`
  - Detects threat-actor account reference `voicproducoes`
  - Detects malicious orphan-commit SHA `79ac49eedf774dd4b0cfa308722bc463cfe5885c`
  - Detects campaign-specific PBKDF2 master key (`0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa`) and salt (`svksjrhjkcejg`)
  - Detects structural `package.json` signals: malicious `optionalDependencies` referencing `github:tanstack/router#79ac49ee`, `prepare` script invoking `bun run tanstack_runner.js`, and references to the fake `@tanstack/setup` package
- **Dead-Man's-Switch Detection (`--check-host` flag, off by default)**:
  - When enabled, scans `$HOME` for `gh-token-monitor` persistence artifacts: `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`, `~/.config/systemd/user/gh-token-monitor.service`, `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/token`
  - Always detects these artifacts when they appear inside the scan directory, regardless of `--check-host`
  - Findings include a CRITICAL warning that revoking the monitored GitHub token while the service is active is designed to trigger a destructive wipe; a safe remediation order is printed (stop service, delete files, verify no monitor process, then rotate tokens)
- **Mini Shai-Hulud Test Cases**:
  - Added `test-cases/tanstack-attack/` to validate Mini Shai-Hulud IOC detection (compromised package versions, orphan-commit `optionalDependencies`, prepare hook, in-content IOCs)
  - Added `test-cases/mini-shai-hulud-dead-mans-switch/` to validate in-tree dead-man's-switch artifact detection
  - Added `test-cases/tanstack-clean/` to confirm last-known-good `@tanstack/*` versions (1.169.4) are not flagged

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 1,703 to 2,111 confirmed package versions.
- **Malicious Hash List**: Expanded `MALICIOUS_HASHLIST` from 7 to 10 known SHA-256 hashes.
- **Data Freshness**: Updated `compromised-packages.txt` metadata from "Last updated: March 2026" to "Last updated: May 2026".
- **Documentation**: Updated `README.md` campaign scope, detection capabilities, test suite count (now 39 cases), and references to include the May 2026 Mini Shai-Hulud campaign and the new `--check-host` flag.

### Security
- Added high-confidence detection for the May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime campaign documented in:
  - https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
  - https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
  - https://semgrep.dev/blog/2026/tanstack-router-packages-hit-by-coordinated-supply-chain-attack/
  - https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised
  - https://snyk.io/blog/tanstack-npm-packages-compromised/
  - https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
  - https://www.endorlabs.com/learn/shai-hulud-compromises-the-tanstack-ecosystem-80-packages-compromised
  - https://tanstack.com/blog/npm-supply-chain-compromise-postmortem

## [3.0.8] - 2026-03-31

### Added
- **March 2026 Axios Supply Chain Attack Coverage**: Added detection for the compromised axios npm packages:
  - `axios:1.14.1`
  - `axios:0.30.4`
  - `plain-crypto-js:4.2.1` (malicious injected dependency - cross-platform RAT dropper)
- **Axios Attack IoC Detection**:
  - Detects C2 domain `sfrclak.com` and IP `142.11.206.73`
  - Detects XOR key `OrDeR_7077` used in obfuscated dropper
  - Detects distinctive RAT beaconing User-Agent string
  - Detects `plain-crypto-js` as a dependency (any version - entirely an attack package)
  - Detects filesystem artifacts: `com.apple.act.mond` (macOS), `ld.py` (Linux)
  - Detects attacker account references (`nrwise@proton.me`, `ifstap@proton.me`)
- **Axios Attack Test Case**: Added `test-cases/axios-attack/` to validate axios attack IoC detection.

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 1,700 to 1,703 confirmed package versions.
- **Data Freshness**: Updated `compromised-packages.txt` metadata from "Last updated: February 2026" to "Last updated: March 2026".

### Security
- Added high-confidence detection for the axios supply chain attack documented in:
  - https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan

## [3.0.7] - 2026-02-23

### Added
- **February 2026 SANDWORM_MODE Coverage**: Added 19 confirmed malicious package versions from Socket's SANDWORM_MODE campaign report:
  - `claud-code:0.2.1`
  - `cloude-code:0.2.1`
  - `cloude:0.3.0`
  - `crypto-locale:1.0.0`
  - `crypto-reader-info:1.0.0`
  - `detect-cache:1.0.0`
  - `format-defaults:1.0.0`
  - `hardhta:1.0.0`
  - `locale-loader-pro:1.0.0`
  - `naniod:1.0.0`
  - `node-native-bridge:1.0.0`
  - `opencraw:2026.2.17`
  - `parse-compat:1.0.0`
  - `rimarf:1.0.0`
  - `scan-store:1.0.0`
  - `secp256:1.0.0`
  - `suport-color:1.0.1`
  - `veim:2.46.2`
  - `yarsg:18.0.1`
- **SANDWORM_MODE Workflow IOC Detection**:
  - Detects malicious GitHub Action usage of `ci-quality/code-quality-check@v1`
  - Detects workflow IOC references tied to threat actor aliases (`official334`, `javaorg`) and `dist/propagate-core.js`
  - Detects poisoned `quality.yml`/`quality.yaml` workflows when campaign IoCs are present
- **SANDWORM_MODE Test Case**: Added `test-cases/sandworm-mode-workflow/` to validate workflow IOC detection.

### Changed
- **Package Count**: Expanded `compromised-packages.txt` from 1,681 to 1,700 confirmed package versions.
- **Data Freshness**: Updated `compromised-packages.txt` metadata from "Last updated: November 2025" to "Last updated: February 2026".
- **Documentation**: Updated `README.md` campaign scope and detection capabilities to include February 2026 SANDWORM_MODE indicators.

### Security
- Added high-confidence detection for the workflow propagation vector documented in:
  - https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning

## [3.0.6] - 2026-01-09

### Added
- **Golden Path Variant Detection**: Added comprehensive detection for December 2025 "Shai-Hulud: Golden Path" attack variant
  - Detection for renamed attack files: `bun_installer.js` and `environment_source.js`
  - Detection for obfuscated exfiltration JSON files: `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json`
  - Detection for new malicious repo description: "Goldox-T3chs: Only Happy Girl"
- **New Compromised Packages**: Added 3 compromised package versions from Golden Path attack:
  - `@vietmoney/react-big-calendar:0.26.0`
  - `@vietmoney/react-big-calendar:0.26.1`
  - `@vietmoney/react-big-calendar:0.26.2`
- **December 2025 Test Case**: Added `test-cases/december-2025-attack/` with complete Golden Path attack simulation

### Changed
- **Package Count**: Expanded compromised-packages.txt from 1,679 to 1,682 package versions
- **File Detection**: Extended November 2025 Bun attack file detection to include renamed Golden Path variants
- **Repository Description Detection**: Added "Goldox-T3chs: Only Happy Girl" pattern to malicious repo detection

### Security
- **Complete Golden Path Coverage**: Detection of all known Golden Path attack indicators from Aikido security research
- **Obfuscated File Detection**: New HIGH RISK detection for stolen credentials staged in leetspeak-named JSON files
- **Attack Evolution Coverage**: Detection patterns now cover the full Shai-Hulud attack family including original, Second Coming, and Golden Path variants

### Technical Details
- Added `obfuscated_exfil_files.txt` temp file for tracking obfuscated exfiltration JSON findings
- Extended `find_files()` to collect `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json`
- Added grep categorization for obfuscated exfil files to `obfuscated_exfil_found.txt`
- Extended `check_new_workflow_patterns()` to process obfuscated exfiltration files
- Added HIGH RISK reporting section for obfuscated exfiltration file detection
- Source: [Aikido Golden Path Analysis](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)

## [3.0.5] - 2025-12-21

### Added
- **--check-semver-ranges flag**: Opt-in check for package.json semver ranges that could resolve to compromised versions (resolves GitHub issue #109)
  - Reports LOW risk as informational warning about latent risk (packages largely unpublished from npm)
  - Uses reverse lookup by package name for O(1) performance instead of O(n*packages)
  - Reuses dependency extraction from check_packages() - no additional file scanning

### Technical Details
- Added `COMPROMISED_VERSIONS_BY_NAME` associative array for efficient semver range checking
- Added `check_semver_ranges()` function that only runs when flag is passed
- Leverages existing `semver_match()` function that was previously unused

## [3.0.4] - 2025-12-03

### Changed
- **Default Grep Tool**: Changed default from ripgrep to git-grep for ~40% faster scanning on large codebases
- **Grep Tool Priority**: Auto-selection now follows: git-grep > ripgrep > grep (based on availability)

### Added
- **--use-git-grep flag**: Force use of git grep (DFA-based, no backtracking)
- **--use-ripgrep flag**: Force use of ripgrep
- **--use-grep flag**: Force use of standard grep
- **Grep Tool Documentation**: Added explanation of why git-grep is fastest in README.md

### Fixed
- **PR #110 pipefail bug**: Fixed `--save-log` returning exit code 1 on clean projects with comprehensive `|| true` fixes

### Technical Details
- Replaced `USE_GIT_GREP` boolean with `GREP_TOOL` string ("git-grep", "ripgrep", "grep")
- Added `select_grep_tool()` function for auto-detection after argument parsing
- Flag overrides take priority over auto-detection
- Script exits with error if user-specified tool is not installed
- Updated `fast_grep_files()`, `fast_grep_files_i()`, `fast_grep_files_fixed()`, and `fast_grep_quiet()` to use case statements

## [3.0.3] - 2025-12-02

### Added
- **Log File Output**: New `--save-log FILE` argument saves all detected file paths to a structured log file grouped by severity (resolves GitHub issue #104)
  - Output format: `# HIGH`, `# MEDIUM`, `# LOW` section headers followed by absolute file paths
  - No truncation - includes ALL findings regardless of display limits
  - Designed for CI/CD artifacts and programmatic parsing

### Changed
- **Usage Documentation**: Updated `--help` output and README.md with `--save-log` examples

### Technical Details
- Added `write_log_file()` function (lines 2098-2204) to generate structured log output
- Added `--save-log` argument parsing in `main()` (lines 2648-2655)
- Test suite expanded to 37 tests (34 original + 3 new `--save-log` tests)

## [3.0.2] - 2025-12-02

### Fixed
- **TypeScript/Minified JS False Positives**: Replaced overly broad conditional patterns (`if.{1,200}credential...`) with tight Shai-Hulud 2.0 wiper signatures based on actual Koi Security malware disclosure (resolves GitHub issue #105)
- **Comment/Documentation False Positives**: Removed standalone glob patterns (`$HOME/*`, `~/*`) from `basic_destructive_regex` that were matching path examples in comments (e.g., TypeScript ESLint's `describeFilePath.js`)
- **Catastrophic Backtracking**: Simplified JS/Python destructive pattern matching to single-pass search, eliminating two-stage grep that caused script hangs on minified files (also resolves GitHub issue #99)

### Changed
- **Destructive Pattern Detection**: Now uses specific Shai-Hulud 2.0 wiper signatures:
  - `Bun.spawnSync` with `cmd.exe`/`bash` and destructive commands (`del /F`, `shred`, `cipher /W`)
  - `shred` with secure delete flags targeting `$HOME`
  - `cipher /W:%USERPROFILE%` (Windows secure wipe)
  - `del /F /Q /S` + `%USERPROFILE%`
  - `find $HOME ... shred`
  - `rd /S /Q` + `%USERPROFILE%`
- **Basic Destructive Patterns**: Retained command-context patterns (`rm -rf $HOME`, `find $HOME -delete`) while removing context-free glob patterns

### Security
- **Maintained Detection Efficacy**: All actual Shai-Hulud wiper code patterns still detected
- **Reduced False Positive Noise**: Projects with TypeScript, minified JS, or path documentation no longer trigger false CRITICAL alerts
- **Improved User Trust**: Clean scans on legitimate projects like Vue + TypeScript and highcharts

### Technical Details
- Replaced `js_py_conditional_regex` with `shai_hulud_wiper_regex` at line 773
- Removed `|\$HOME/[*]|~/[*]|/home/[^/]+/[*]` from `basic_destructive_regex` at line 769
- Simplified JS/Python pattern matching from two-stage grep to single-pass (lines 794-801)
- Updated test cases: `destructive-patterns/malicious_fallback.js` and `minified-false-positives/legitimate-destructive.js` to use actual wiper signatures
- Test suite remains at 34 passing tests

## [3.0.1] - 2025-12-01

### Added
- **Ripgrep Support**: Optional ripgrep (`rg`) integration for faster pattern matching when available (resolves GitHub issue #80)
- **Two-Phase Destructive Pattern Check**: Implemented two-phase detection with quick pre-filter followed by detailed analysis

### Fixed
- **Large Repository Crash**: Fixed xargs "argument list too long" crash on repositories with 77,531+ files by batching hash computation with `-n 100` (resolves GitHub issue #94)
- **Spaces in Filenames**: Fixed xargs crash when scanning files with spaces in their names by using null-delimited input throughout the script (resolves GitHub issue #92)
- **Cross-Platform Compatibility**: Fixed Git Bash and WSL/Linux compatibility issues (merged PR #88)
- **Network Exfiltration Comment Filtering**: Fixed comment filtering in network exfiltration detection (merged PR #81)

### Changed
- **Null-Delimited File Processing**: Updated `fast_grep_files()`, `fast_grep_files_i()`, `fast_grep_files_fixed()`, `check_file_hashes()`, `check_workflows()`, and `check_packages()` to use `tr '\n' '\0' | xargs -0` pattern for robust filename handling
- **Batched Hash Computation**: Hash checking now processes files in batches of 100 to avoid shell argument limits on large codebases
- **Ripgrep Detection**: Script automatically detects and uses ripgrep if installed, falling back to grep otherwise

### Technical Details
- All file processing pipelines now use null-delimited input (`-0` flag) for xargs
- Hash computation uses `-n 100` batching combined with `-P "$PARALLELISM"` for efficient parallel processing
- Added `HAS_RIPGREP` detection with `command -v rg` for optional performance optimization
- Added test case `spaces-in-filenames` with files containing spaces to validate fix
- Test suite expanded to 34 test cases

## [3.0.0] - 2025-11-29

### Breaking Changes
- **Bash 5.0+ Required**: The script now requires Bash 5.0 or newer. On macOS, install via `brew install bash` and run with `/opt/homebrew/bin/bash ./shai-hulud-detector.sh`. Clear error message displayed when running on older Bash versions.

### Added
- **Automated Test Suite**: New `run-tests.sh` script validates all 32 test cases with expected exit codes and risk level detection (HIGH/MEDIUM/LOW)
- **O(1) Package Lookups**: Replaced linear array searches with associative arrays for compromised package detection, dramatically improving performance on large projects
- **Robust Error Handling**: Added `set -eo pipefail` with proper `|| true` guards on all commands that may legitimately fail (grep, find, etc.)

### Changed
- **Lockfile Detection Rewrite**: Completely rewrote `check_package_integrity()` with AWK block-based JSON parsing instead of broken grep patterns. Now correctly detects compromised packages in lockfiles where package name and version are on different lines.
- **Modern Bash Features**: Leverages associative arrays (`declare -A`) and `mapfile` for improved performance and reliability
- **Cross-Platform Stat Abstraction**: Added `get_file_size()` and `get_file_mtime()` helper functions for macOS/Linux compatibility

### Fixed
- **Lockfile False Negatives**: Fixed critical bug where `chalk@5.6.1` and other compromised packages in lockfiles were not detected due to grep pattern assuming name and version on same line
- **Script Crashes Mid-Execution**: Fixed multiple grep pipeline failures that caused the script to exit with code 1 without completing the scan or showing results
- **Missing Ethereum Wallet Detection**: Restored Ethereum wallet address pattern detection (`0x[a-fA-F0-9]{40}`) that was lost during refactoring
- **Missing LOW RISK for Framework XMLHttpRequest**: Fixed detection to properly report LOW RISK for legitimate XMLHttpRequest modifications in React Native and Next.js framework code
- **Duplicate Lockfile Warnings**: Fixed AWK parser that was outputting duplicate findings for packages appearing in both node_modules and dependencies sections
- **Reduced False Positives for Destructive Patterns**: Standalone `rimraf`, `fs.unlinkSync`, and `fs.rmSync` no longer flagged as CRITICAL. Now only flags deletion commands that target user directories (`$HOME`, `~`, `/home/`) or are combined with credential/auth failure patterns. Fixed regex escaping for literal asterisk matching and excluded `~/path` patterns (Vue.js import aliases). Tightened `exec.*rm` pattern span to prevent false matches on minified code. (GitHub issue #74)

### Performance
- **Associative Array Lookups**: O(1) package lookups instead of O(n) linear searches
- **Reduced Subprocess Spawning**: Consolidated multiple grep calls into single AWK passes where possible
- **Parallel Processing**: Enhanced xargs parallelism for hash checking and content scanning

### Security
- **Complete Test Coverage**: All 32 test cases now pass, validating detection of all known attack patterns
- **No Detection Regressions**: All previously detected threats continue to be detected at correct risk levels

## [2.7.6] - 2025-11-26

### Fixed
- **False Positive Elimination**: Refined destructive pattern detection to eliminate false positives on minified JavaScript files (resolves GitHub issue #74)
- **Permission Error Resilience**: Added comprehensive permission denied error handling for all find commands (resolves GitHub issue #76)
- **SemVer Wildcard Case Sensitivity**: Fixed crash when encountering uppercase wildcard patterns like "3.X" instead of "3.x" (resolves GitHub issue #73)
- **Cross-Platform Robustness**: Script now gracefully handles restricted directories and permission variations common in enterprise environments

### Changed
- **Pattern Specificity**: Enhanced destructive pattern regex to require actual command context rather than isolated keywords
- **File Type Awareness**: Different pattern strictness for shell scripts vs. JavaScript files to reduce false positives
- **Error Handling**: All 26+ find commands now use `|| true` to prevent script abortion on permission denied errors

### Technical Details
- **Regex Improvements**:
  - Changed `find.*-delete` to `find[[:space:]]+[^[:space:]]+.*[[:space:]]+-delete` (requires proper command structure)
  - Limited conditional patterns to `.{1,200}` spans instead of unlimited `.*` to prevent false positives across minified files
  - Added command-specific contexts for JavaScript patterns (requires `rm -`, `fs.`, `rimraf`, etc.)
- **Permission Handling**: Modified `count_files()` function and all direct find usages to handle permission denied gracefully
- **SemVer Case Insensitive**: Changed wildcard pattern from `*x*` to `*[xX]*` and updated skip logic to handle both "x" and "X"
- **Test Coverage**: Added test case for minified file false positives and validated fix against AutoNumeric.js patterns

### Security
- **Maintained Detection Accuracy**: All real threats still detected while eliminating false positives from legitimate minified libraries
- **Production Ready**: Enhanced robustness for enterprise environments with mixed file permissions
- **CI/CD Compatibility**: Script no longer aborts in automated environments due to permission restrictions

## [2.7.5] - 2025-11-25

### Added
- **Critical Gap Coverage**: Added detection for previously undetected Shai-Hulud attack techniques from Koi.ai incident analysis
- **Discussion Workflow Detection**: New `check_discussion_workflows()` function detects malicious GitHub Actions with discussion triggers
- **Self-Hosted Runner Detection**: New `check_github_runners()` function detects malicious runner installations in `.dev-env/` and other directories
- **File Hash Verification**: Enhanced `check_bun_attack_files()` with SHA256 hash verification against known malicious files from Koi.ai IOCs
- **Destructive Payload Detection**: New `check_destructive_patterns()` function detects data destruction capabilities that activate when credential theft fails

### Fixed
- **Major Attack Vector Gap**: Previously missing detection for discussion-triggered workflows (`on: discussion`) that enable arbitrary command execution
- **Persistent Backdoor Gap**: Previously missing detection for self-hosted GitHub Actions runners used as persistent backdoors
- **Data Loss Risk**: Previously missing detection for destructive patterns that can delete all user files when exfiltration fails

### Changed
- **Detection Accuracy**: File hash verification now confirms exact malicious file matches instead of just filename detection
- **Risk Classification**: Added CRITICAL level for destructive patterns and hash-confirmed malicious files
- **Comprehensive Coverage**: Expanded from filename-based detection to behavior and hash-based detection

### Security
- **Complete Attack Chain Detection**: Now detects the full "Shai-Hulud: The Second Coming" attack lifecycle:
  - Initial compromise (existing package detection)
  - Persistence establishment (new runner detection)
  - Backdoor activation (new discussion workflow detection)
  - Fallback destruction (new destructive pattern detection)
- **Hash-Confirmed Threats**: Exact SHA256 hash matching for known malicious files from security incident reports
- **Persistent Backdoor Protection**: Detection of self-hosted runners that enable long-term access via GitHub infrastructure

### Technical Details
- **New Detection Functions Added**:
  - `check_discussion_workflows()` - Detects `on: discussion` triggers, `runs-on: self-hosted`, and dynamic payload execution
  - `check_github_runners()` - Scans for runner config files (.runner, .credentials), executables, and .dev-env directories
  - Enhanced `check_bun_attack_files()` - Added hash verification for 4 known malicious file hashes from Koi.ai report
  - `check_destructive_patterns()` - Detects file deletion patterns (rm -rf $HOME, fs.rmSync, etc.) and conditional destruction
- **New Temp Files**: discussion_workflows.txt, github_runners.txt, malicious_hashes.txt, destructive_patterns.txt
- **Cross-Platform Hash Support**: Uses sha256sum (Linux) or shasum (macOS) for file hash verification
- **Performance Optimized**: Destructive pattern scanning limited to 100 files per extension to avoid performance issues

### Threat Intelligence Integration
- **Koi.ai IOC Integration**: Incorporated specific indicators from https://www.koi.ai/incident/live-updates-sha1-hulud-the-second-coming
- **Known Malicious Hashes**:
  - `setup_bun.js`: a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a
  - `bun_environment.js`: 62ee164b..., f099c5d9..., cbb9bc5a... (3 variants)
- **Attack Pattern Coverage**: Detection patterns based on confirmed attack behaviors from incident response reports

## [2.7.4] - 2025-11-25

### Fixed
- **Critical Bug: Network Exfiltration Detection**: Fixed network exfiltration warnings not appearing in report due to array vs temp file mismatch (resolves GitHub issue #55)
- **Error Handling**: Added proper error handling for directory path conversion to prevent script failure on inaccessible directories
- **Security Improvement**: Replaced eval usage in semverParseInto() function with safer printf -v alternatives
- **Cross-Platform Compatibility**: Added timeout command detection with macOS fallback for better platform support

### Changed
- **Network Exfiltration Function**: Updated check_network_exfiltration() to write findings to temp file instead of global array
- **Function Documentation**: Updated comments to reflect temp file usage instead of array operations
- **Path Handling**: Enhanced directory access validation with proper error messages

### Security
- **Paranoid Mode Restored**: Network exfiltration detection now properly functions in paranoid mode
- **Code Injection Prevention**: Eliminated eval usage that could pose security risks
- **Robust Error Handling**: Improved script reliability by handling edge cases in directory operations

### Technical Details
- **Array to File Conversion**: Replaced 13 instances of NETWORK_EXFILTRATION_WARNINGS+= with echo >> temp file
- **Safe Variable Assignment**: Changed eval $var= to printf -v "$var" for dynamic variable setting
- **Platform Detection**: Added command -v timeout check with graceful fallback for systems without GNU timeout
- **Directory Validation**: Enhanced cd command with proper error handling: if ! scan_dir=$(cd "$scan_dir" && pwd)
- **Comment Corrections**: Fixed typo in semverParseInto function comments (#MINO) → #PATCH)

## [2.7.3] - 2025-11-25

### Added
- **Comprehensive Package List Update**: Added 953 missing compromised packages from Koi.ai incident report (resolves GitHub issue #61)
- **Complete "Second Coming" Coverage**: Now includes all 1,055 packages from the November 2025 Shai-Hulud attack

### Changed
- **Package Detection Coverage**: Expanded from 980 to 1,677 compromised package versions (+71% increase)
- **Supply Chain Protection**: Comprehensive coverage of "Shai-Hulud: The Second Coming" attack packages

### Security
- **Critical Detection Gap Closed**: Previously missing 90% of compromised packages from November 2025 attack
- **Enhanced Security Coverage**: Added extensive missing packages from major compromised organizations:
  - Voiceflow (100+ packages): @voiceflow/anthropic, @voiceflow/api-sdk, @voiceflow/chat-types, etc.
  - Zapier packages: @zapier/ai-actions-react, @zapier/mcp-integration, zapier-platform-cli, etc.
  - PostHog packages: Multiple @posthog/* scoped packages from security incident
  - AsyncAPI packages: @asyncapi/cli, @asyncapi/converter, @asyncapi/generator, etc.
  - AccordProject, Oku-UI, BrowserBase, ENS Domains, and hundreds more

### Technical Details
- **Source Integration**: Incorporated complete Koi.ai incident list covering 1,055 confirmed compromised packages
- **Data Processing**: Merged and deduplicated package lists maintaining alphabetical sorting
- **Coverage Metrics**: Increased detection from ~10% to 100% of known "Second Coming" attack packages
- **Package Validation**: Cross-referenced with GitHub issue #61 missing package analysis

## [2.7.2] - 2025-11-25

### Fixed
- **Semver Wildcard Parsing**: Fixed syntax error when processing wildcard version patterns like "4.x" in package.json files (resolves GitHub issue #56)
- **PostHog Package Detection**: Added missing posthog-js:1.297.3 to compromised packages list - was confirmed affected in "Shai-Hulud: The Second Coming" attack (resolves GitHub issue #60)

### Changed
- **Semver Pattern Matching**: Enhanced semver_match() function to handle npm-style wildcard version ranges (4.x, 1.2.x, x.x.x patterns)
- **Package Detection Coverage**: Improved detection accuracy by including previously missing PostHog packages from November 2025 supply chain attack

### Security
- **Enhanced Package Detection**: Wildcard version patterns no longer cause script crashes, ensuring comprehensive package scanning continues
- **Supply Chain Coverage**: Added detection for PostHog security incident affecting posthog-js 1.297.3 that was part of major npm compromise

### Technical Details
- **Wildcard Pattern Logic**: Added new `*x*` case in semver_match() function to parse and compare version components while skipping 'x' wildcards
- **Arithmetic Error Prevention**: Replaced problematic arithmetic comparisons with string parsing for wildcard version components
- **Backwards Compatibility**: All existing semver patterns (exact, caret ^, tilde ~) continue to work unchanged
- **Test Coverage**: Added comprehensive test suite with 20 test cases validating wildcard patterns and existing functionality
- **Package List Update**: Added posthog-js:1.297.3 to compromised-packages.txt in alphabetical order for proper detection

## [2.7.1] - 2025-11-24

### Fixed
- **Critical Performance Issue**: Fixed script hanging on large projects (23,420+ files) due to bash array memory limits in report generation
- **Git Command Timeout**: Fixed indefinite hanging in `check_second_coming_repos()` when git commands stall on problematic repositories
- **Report Generation Failure**: Fixed issue where script would complete all scanning phases but never display final report on large codebases
- **Memory Efficiency**: Resolved bash array size limitations that prevented proper report output after extensive file scanning

### Changed
- **File-Based Storage Architecture**: Replaced all in-memory bash arrays with temporary file-based storage for unlimited scalability
- **Cross-Platform Temp Directory**: Enhanced temp directory creation with robust fallback mechanisms for macOS, Linux, and Windows compatibility
- **Git Command Safety**: Added 5-second timeout to git operations to prevent hanging on corrupted or slow repositories
- **Cleanup Handling**: Improved temporary file cleanup with proper trap handlers for script termination scenarios

### Security
- **Enhanced Reliability**: Large project scans now complete successfully, ensuring comprehensive security coverage regardless of project size
- **Scan Completion Guarantee**: File-based storage ensures report generation completes even with massive finding datasets
- **Repository Safety**: Git timeout prevents script lockup when scanning projects with problematic git repositories

### Technical Details
- **File-Based Finding Storage**: Converted 20+ global arrays to temporary files (workflow_files.txt, trufflehog_activity.txt, compromised_found.txt, etc.)
- **Cross-Platform Temp Creation**: Implemented `create_temp_dir()` with mktemp primary method and fallback to manual creation using PID and timestamp
- **Temp Directory Naming**: Uses `shai-hulud-detect-XXXXXX` pattern to clearly identify detection tool vs. malware artifacts
- **Memory Footprint**: Eliminated bash array memory limits - now handles unlimited findings from any project size
- **Git Operation Safety**: Added `timeout 5s` to git config commands in repository description checking
- **Automatic Cleanup**: Trap handlers ensure temp directory removal on EXIT, INT, and TERM signals
- **Report Generation Conversion**: Updated all report sections to use `while IFS= read -r` loops reading from temp files instead of array iterations
- **Risk Categorization**: Maintained full functionality for crypto pattern and trufflehog activity risk-level categorization using temporary files

### Performance Impact
- **Scalability**: Now handles projects with unlimited file counts without performance degradation
- **Large Project Support**: Successfully processes 23,420+ file projects that previously timed out after 2+ hours
- **Memory Usage**: Dramatically reduced memory footprint by eliminating large in-memory arrays
- **Execution Time**: Large projects now complete in expected timeframes (~10 minutes) with proper report display

## [2.7.0] - 2025-11-24

### Added
- **November 2025 "Shai-Hulud: The Second Coming" Attack Coverage**: Added comprehensive detection for the fake Bun runtime attack that affected 300+ packages with millions of weekly downloads
- **setup_bun.js Detection**: New detection function `check_bun_attack_files()` identifies fake Bun runtime installation scripts used as malware entry points
- **bun_environment.js Detection**: Detects 10MB+ obfuscated credential harvesting payloads with TruffleHog automation
- **New Workflow Pattern Detection**: `check_new_workflow_patterns()` detects `formatter_*.yml` malicious GitHub Actions workflows in `.github/workflows/` directories
- **actionsSecrets.json Detection**: Identifies double Base64 encoded secrets exfiltration files used for credential theft
- **SHA1HULUD GitHub Actions Runner Detection**: `check_github_actions_runner()` detects workflows using malicious SHA1HULUD runners for credential theft
- **Fake Bun Preinstall Pattern Detection**: `check_preinstall_bun_patterns()` identifies malicious `"preinstall": "node setup_bun.js"` patterns in package.json files
- **Repository Description Pattern Detection**: `check_second_coming_repos()` detects repositories with "Sha1-Hulud: The Second Coming" descriptions
- **Enhanced TruffleHog Detection**: Added November 2025 specific patterns for automated TruffleHog download, credential scanning, and GitHub Actions integration
- **Comprehensive Test Suite**: Added `test-cases/november-2025-attack/` with complete attack simulation including all new file types and patterns
- **300+ New Compromised Packages**: Expanded compromised-packages.txt from 571+ to 979+ packages including major namespaces:
  - @zapier/* (zapier-sdk, secret-scrubber, platform-core, ai-actions)
  - @posthog/* (core, cli, nextjs-config, rrweb variants, plugins)
  - @asyncapi/* (specs, parser, generator, templates, tools)
  - @postman/* (tunnel-agent, csv-parse, icons, keytar, mcp-server)
  - @ensdomains/* (address-encoder, content-hash, test-utils, contracts)
  - posthog-node, posthog-react-native variants
  - MCP ecosystem packages (mcp-use, create-mcp-use-app)
  - React Native and development tools

### Changed
- **Expanded Attack Coverage**: Updated script description and documentation to cover both September 2025 and November 2025 attack campaigns
- **Enhanced Package Detection**: Package count increased from 571+ to 979+ confirmed compromised package versions across 18+ affected namespaces
- **Script Header Update**: Modified opening comments to reflect detection of "Shai-Hulud: The Second Coming" (fake Bun runtime attack)
- **Detection Workflow Enhancement**: Added 5 new detection functions to main scanning routine covering all November 2025 attack vectors
- **Risk Reporting Expansion**: Enhanced `generate_report()` function with 6 new HIGH RISK reporting sections for November 2025 patterns
- **Documentation Updates**: Comprehensive README.md updates including new attack overview, detection capabilities, test cases, and technical details

### Security
- **Multi-Campaign Protection**: Now provides comprehensive protection against both original September 2025 Shai-Hulud worm (517+ packages) and November 2025 "Second Coming" fake Bun attack (300+ packages)
- **Advanced Credential Theft Detection**: Enhanced TruffleHog detection specifically targets November 2025 automated credential harvesting techniques
- **GitHub Actions Security**: Detects malicious SHA1HULUD runners and workflow files used for secrets exfiltration via GitHub Actions
- **Repository Compromise Detection**: Identifies repositories created with specific "Shai-Hulud: The Second Coming" descriptions for data exfiltration
- **Supply Chain Attack Evolution Coverage**: Addresses evolved attack techniques using legitimate-looking Bun runtime installation as infection vector

### Technical Details
- **New Global Arrays**: Added 8 new detection arrays (BUN_SETUP_FILES, BUN_ENVIRONMENT_FILES, NEW_WORKFLOW_FILES, GITHUB_SHA1HULUD_RUNNERS, PREINSTALL_BUN_PATTERNS, SECOND_COMING_REPOS, ACTIONS_SECRETS_FILES, TRUFFLEHOG_PATTERNS)
- **Enhanced Function Integration**: All new detection functions integrated into main scanning workflow with proper error handling and progress display
- **Test Coverage Validation**: Created comprehensive test case demonstrating 18 HIGH RISK and 8 MEDIUM RISK detections for all November 2025 patterns
- **Backward Compatibility**: All existing September 2025 detection capabilities preserved and enhanced
- **Cross-Platform Support**: New detection patterns work consistently across macOS, Linux, and Windows/Git Bash environments
- **Performance Optimization**: New detection functions use efficient file searching and pattern matching without impacting scan performance

### Package Database
- **Major Namespace Expansion**: Added comprehensive coverage of newly compromised namespaces targeting popular development tools and services
- **High-Impact Package Coverage**: Includes packages with millions of weekly downloads (zapier-sdk: 2.6M, posthog-core: 2M, asyncapi/specs: 1.4M)
- **Organized Database Structure**: Enhanced compromised-packages.txt with clear categorization by attack campaign and package ecosystem
- **Source Attribution**: All new packages sourced from HelixGuard security research on November 24, 2025 attack analysis

## [2.6.3] - 2025-10-03

### Fixed
- **Critical Security Vulnerability**: Fixed lockfile upward search that could access parent directories outside scan boundary, preventing potential malicious lockfile attacks
- **Directory Boundary Enforcement**: Added security boundary checking to prevent upward search from accessing lockfiles above the original scan directory
- **Information Leakage Prevention**: Blocked potential access to unrelated project lockfiles in parent directories

### Security Impact
- **Prevents Malicious Parent Lockfile Attacks**: Attackers can no longer place malicious lockfiles in parent directories to influence scan results
- **Blocks Information Leakage**: Upward search now respects project boundaries and won't access unrelated parent directory lockfiles
- **Maintains User Privacy**: Scanner no longer accesses lockfiles outside the intended project scope

### Changed
- **Lockfile Search Boundary**: Enhanced `get_lockfile_version()` function with scan directory boundary parameter to limit upward search scope
- **Security-First Design**: Added boundary validation using regex pattern matching to ensure search stays within project boundaries

### Technical Details
- Added `scan_boundary` parameter to `get_lockfile_version()` function signature
- Implemented boundary check: `if [[ ! "$current_dir/" =~ ^"$scan_boundary"/ && "$current_dir" != "$scan_boundary" ]]; then break; fi`
- Updated call sites to pass scan directory as boundary parameter
- Preserves all existing functionality within proper security boundaries

## [2.6.2] - 2025-10-03

### Fixed
- **GitHub Issue #42 Node Modules Lockfile Detection**: Fixed remaining lockfile detection issue where packages in node_modules subdirectories were not properly checked against root lockfiles
- **Upward Lockfile Search**: Enhanced `get_lockfile_version()` function to search parent directories for lockfiles instead of only checking same directory as package.json
- **Node Modules Package Protection**: Packages found in `node_modules/*/package.json` now correctly show LOW RISK when root lockfile pins them to safe versions

### Changed
- **Lockfile Detection Logic**: Modified lockfile search to traverse upward through directory tree until finding lockfile or reaching filesystem root
- **Cross-Directory Lockfile Support**: Lockfile detection now works for packages at any directory depth within a project

### Technical Details
- Searches upward from package.json directory using `dirname` traversal until lockfile found or root reached
- Supports all lockfile types (package-lock.json, yarn.lock, pnpm-lock.yaml) at any parent directory level
- Maintains backward compatibility for root-level packages
- Zero performance impact for projects without nested package.json files

## [2.6.1] - 2025-10-03

### Fixed
- **GitHub Issue #44 Critical Security Vulnerability**: Fixed homoglyph detection bypass where Unicode characters were filtered out before detection could run
- **AWK Filter Security Flaw**: Replaced restrictive ASCII-only regex filter with minimal length check to allow Unicode homoglyphs through to detection logic
- **Duplicate Warning Deduplication**: Eliminated confusing duplicate warnings where same malicious package was flagged by multiple detection methods
- **Risk Count Accuracy**: Fixed inflated risk counts where 1 malicious package could generate 2+ warnings, providing accurate threat metrics

### Added
- **Cross-Platform Unicode Detection**: Enhanced typosquatting detection to work reliably across macOS, Linux, and Windows/Git Bash environments
- **Warning Deduplication System**: Added `already_warned()` helper function and tracking array to prevent redundant warnings for same packages
- **Comprehensive Issue #44 Test Coverage**: Verified Unicode homoglyph detection works for packages like `reаct` (Cyrillic 'а') and `@typеs/node`

### Changed
- **AWK Package Name Filter**: Modified line 1045 from strict ASCII regex to `if (length($0) > 1)` for cross-platform Unicode compatibility
- **Typosquatting Warning Logic**: All 6 warning addition points now check for duplicates before adding to TYPOSQUATTING_WARNINGS array
- **User Experience**: Cleaner output with single warning per malicious package instead of multiple redundant alerts

### Security Impact
- **Critical Vulnerability Closed**: Attackers can no longer bypass detection using Unicode lookalike characters (e.g., Cyrillic letters)
- **Enhanced Threat Detection**: Now properly detects sophisticated homoglyph attacks that were previously missed
- **Accurate Risk Assessment**: Users get correct threat counts and cleaner, more trustworthy output

### Technical Details
- Uses standard AWK `length()` function available on all platforms (gawk, mawk, nawk, BSD awk)
- Maintains existing cross-platform Unicode detection using `LC_ALL=C` + `grep`
- Deduplication uses bash arrays and functions for maximum compatibility
- Zero performance impact, preserves all existing detection capabilities

## [2.6.0] - 2025-10-03

### Fixed
- **GitHub Issue #42 False Positives**: Resolved user confusion about MEDIUM RISK warnings for packages with safe lockfile versions
- **Semver Range Detection Accuracy**: Fixed misleading warnings for old projects with lockfiles that pin to safe package versions
- **User Experience for Legacy Projects**: Eliminated false positive confusion for users scanning older codebases with established lockfiles

### Added
- **Lockfile-Aware Package Detection**: New intelligent detection logic that checks actual installed versions from lockfiles before flagging semver range matches
- **get_lockfile_version() Function**: New helper function that extracts actual installed package versions from package-lock.json, yarn.lock, and pnpm-lock.yaml files
- **LOCKFILE_SAFE_VERSIONS Array**: New global array to track packages that have semver ranges that could match compromised versions but are locked to safe versions
- **LOW RISK Lockfile Protection Category**: New report section showing packages protected by lockfiles with clear, actionable messaging
- **Comprehensive Test Suite**: Added 3 new test cases covering all lockfile detection scenarios
  - `lockfile-safe-versions`: Tests packages with safe lockfile versions (shows LOW RISK)
  - `lockfile-comprehensive-test`: Tests mixed scenario (safe + compromised lockfile versions)
  - `no-lockfile-test`: Tests packages without lockfiles (shows MEDIUM RISK as expected)

### Changed
- **Package Detection Logic**: Enhanced `check_packages()` function to check lockfiles when semver patterns match potentially compromised versions
- **Risk Stratification**: Packages with semver ranges now categorized based on actual lockfile contents:
  - **HIGH RISK**: Lockfile contains exact compromised version
  - **LOW RISK**: Lockfile contains safe version (new category)
  - **MEDIUM RISK**: No lockfile found (potential update risk)
- **Report Generation**: Updated `generate_report()` to display lockfile-safe packages with informative messaging
- **User Messaging**: Clear explanation that current installation is safe but updates should be reviewed

### Technical Details
- Lockfile detection supports all major package managers (npm, yarn, pnpm)
- Uses block-based JSON parsing for accuracy (reuses existing logic from `check_package_integrity`)
- Maintains backward compatibility - all existing functionality unchanged
- Zero performance impact for projects without lockfiles
- Preserves all security detection capabilities while improving user experience

### Security Impact
- **No reduction in security**: All actual threats still detected with HIGH RISK warnings
- **Improved accuracy**: Users can now distinguish between actual risks and potential future risks
- **Better user compliance**: Reduces alert fatigue from false positives, increasing trust in real warnings

## [2.5.2] - 2025-10-03

### Fixed
- **Cross-Platform Network Exfiltration Detection**: Fixed GitHub issue #43 where network exfiltration regex pattern failed on Windows/Git Bash/MINGW64 environments
- **POSIX Character Class Compatibility**: Replaced basic regex with extended regex (`grep -E`) to ensure consistent behavior across all platforms
- **Regex Pattern Portability**: Changed from `grep -q "https\?://[^[:space:]]*$domain\|..."` to `grep -qE "https?://[^[:space:]]*$domain|..."` for cross-platform reliability

### Added
- **Paranoid Mode Test Documentation**: Added comprehensive test cases and documentation for paranoid mode features in README.md
- **Network Exfiltration Testing**: Documented positive and negative test cases for network exfiltration detection
- **Typosquatting Testing**: Documented test cases demonstrating typosquatting detection with paranoid mode
- **Enhanced Test Coverage**: Verified all paranoid mode features have both positive (detection) and negative (no false positives) test coverage

### Changed
- **Network Exfiltration Regex**: Updated 3 grep calls in `check_network_exfiltration()` function (lines 1119, 1122, 1126)
- **Regex Syntax**: Removed backslash escaping from `\?` and `\|` patterns, using extended regex syntax instead
- **Testing Documentation**: Added paranoid mode testing section to README.md with examples and expected outputs

### Technical Details
- Extended regex (`-E` flag) is POSIX-compliant and works consistently across macOS (BSD grep), Linux (GNU grep), and Windows (MINGW64 grep)
- Maintains identical matching logic while ensuring cross-platform compatibility
- All existing tests pass with identical output (verified on macOS, pending Windows verification)
- Pattern now correctly detects webhook.site, pastebin.com, and other suspicious domains on all platforms

## [2.5.1] - 2025-09-29

### Fixed
- **Windows CRLF Compatibility**: Merged PR #36 to fix Windows line ending handling in compromised package loading
- **Cross-platform Package Detection**: Ensures consistent package detection across Windows (CRLF) and Unix (LF) systems
- **Undercounting Prevention**: Fixes issue where Windows users were missing compromised package detections due to trailing carriage returns

### Changed
- **Package Loading Robustness**: Added carriage return trimming to `load_compromised_packages()` function
- **Cross-platform Reliability**: Improved handling of mixed line endings from different development environments

### Technical Details
- Added `line="${line%$'\r'}"` to strip trailing carriage returns before package processing
- Maintains full compatibility with all platforms while fixing Windows-specific detection issues
- Zero impact on Unix/Linux/macOS systems, where no carriage returns are present

## [2.5.0] - 2025-09-29

### Fixed
- **Lockfile False Positives**: Addresses GitHub issue #37 where `color-convert@1.9.3` was incorrectly flagged as compromised version `3.1.1`
- **Improved Package Version Extraction**: Replaced proximity-based grep with block-based JSON parsing to accurately extract package versions from lockfiles
- **Robust Lockfile Parsing**: Now correctly identifies package versions within specific `node_modules/$package_name` blocks instead of grabbing nearby version fields

### Added
- **Enhanced Test Coverage**: Added test cases for lockfile false positives and proper compromised package detection
- **Block-based JSON Parsing**: Implemented AWK-based parsing with brace counting to ensure version extraction from correct package context

### Changed
- **Lockfile Processing Logic**: Updated `check_package_integrity()` function to use structured parsing instead of line-proximity heuristics
- **Version Extraction Method**: Now looks for `"node_modules/$package_name"` blocks and extracts versions only from within that specific context
- **Fallback Handling**: Improved fallback logic for older lockfile formats while maintaining accuracy

### Technical Details
- Fixed bug where `grep -A5` would incorrectly associate versions from different packages that happened to be within 5 lines
- Implemented proper JSON block parsing with brace counting to maintain context boundaries
- Added comprehensive test cases covering both false positive prevention and actual threat detection
- Maintains backward compatibility with different lockfile formats (npm, yarn, pnpm)

## [2.4.0] - 2025-09-29

### Added
- **Context-aware XMLHttpRequest Detection**: Added intelligent detection that distinguishes between legitimate framework code and malicious crypto theft patterns
- **New Test Cases**: Added comprehensive test scenarios for XMLHttpRequest modifications covering both legitimate (React Native, Next.js) and malicious patterns
- **Enhanced Risk Stratification**: XMLHttpRequest modifications now properly classified based on file path context and associated crypto patterns

### Changed
- **Reduced False Positives**: XMLHttpRequest modifications in React Native (`/react-native/Libraries/Network/`) and Next.js (`/next/dist/compiled/`) paths now flagged as LOW RISK instead of HIGH RISK
- **Improved Detection Logic**: XMLHttpRequest modifications combined with wallet addresses or malicious functions correctly flagged as HIGH RISK
- **Package Database Cleanup**: Removed 17 duplicate entries from compromised-packages.txt, reducing from 621 to 604 unique package versions
- **Updated Documentation**: Package count updated from 571+ to 600+ to reflect accurate database size

### Fixed
- **False Positive Resolution**: Addresses GitHub issue #35 regarding false positives for legitimate XMLHttpRequest usage in React Native and Next.js applications
- **Risk Classification Logic**: Fixed automatic HIGH RISK classification for all XMLHttpRequest modifications regardless of context
- **Duplicate Package Entries**: Removed duplicate compromised package entries that were causing inflated detection counts

### Security
- **Maintained Detection Efficacy**: Continues to detect actual crypto theft malware that hijacks XMLHttpRequest for wallet address replacement
- **Enhanced Context Awareness**: Provides appropriate risk levels based on file location and associated patterns
- **Comprehensive Coverage**: Maintains protection against all known attack vectors while reducing false positive noise

### Technical Details
- Updated XMLHttpRequest detection to check for crypto patterns (wallet addresses, malicious functions) in combination with prototype modifications
- Added LOW RISK reporting for crypto patterns to global LOW_RISK_FINDINGS array
- Implemented file path-based context checking for known legitimate framework locations
- Created test cases demonstrating proper risk classification for various XMLHttpRequest usage scenarios

## [2.3.0] - 2025-09-24

### Added
- **Semver Pattern Matching**: Merged PR #28 adding intelligent semver pattern matching to detect packages that could become compromised on `npm update`
- **Parallel Processing**: Merged PR #27 adding parallel hash scanning with ~20% performance improvement using `xargs -P`
- **Enhanced Test Coverage**: Added new test cases for semver matching and namespace warning scenarios
- **Cross-platform Compatibility**: Fixed macOS compatibility issues by removing `-readable` flag from find commands

### Changed
- **Risk Level Adjustment**: Changed namespace warnings from MEDIUM to LOW risk to reduce false positive alarm fatigue
- **Test Case Improvements**: Updated clean-project test to use `color` package instead of `@ctrl/tinycolor` to ensure truly clean test results
- Improved semver matching algorithm to detect packages at risk during dependency updates using caret (^) and tilde (~) patterns
- Enhanced parallel processing for faster malicious file hash detection across large codebases

### Fixed
- Fixed test case expectations to match actual script output in README documentation
- Resolved false positive namespace warnings in clean test environments
- Fixed macOS compatibility issues with BSD vs GNU command differences

### Security
- Improved detection of packages that could become compromised during routine dependency updates
- Enhanced early warning system for packages matching compromised version patterns
- Better risk stratification with LOW/MEDIUM/HIGH risk classifications

### Technical Details
- Added `semver_match()` function with intentional argument ordering to check if malicious versions could match package.json patterns
- Implemented parallel hash scanning using `xargs -P $(nproc || echo 4)` for optimal CPU utilization
- Created comprehensive test cases covering both namespace warnings and semver pattern matching scenarios
- Updated documentation to reflect new test cases and expected outputs

## [2.2.2] - 2025-09-21

### Added
- **Progress Display**: Merged PR #19 for real-time file scanning progress with percentage completion and file counts
- **Multi-Hash Detection Testing**: Merged PR #26 adding comprehensive test cases for all 7 Shai-Hulud worm variant hash detection
- **Enhanced Error Handling**: Merged PR #13 for robust error handling in grep pipelines to prevent script hangs
- **pnpm Lockfile Support**: Added comprehensive pnpm-lock.yaml support with YAML-to-JSON transformation capability
- **Cross-platform Compatibility**: Merged PR #25 for improved file age detection using portable `date -r` command instead of BSD-specific `stat -f`

### Changed
- Improved user experience with real-time progress feedback during file scanning operations
- Enhanced test coverage for malicious hash detection across all worm variants
- Improved script reliability across different shell configurations and package manager environments
- Enhanced lockfile detection to support npm (package-lock.json), yarn (yarn.lock), and pnpm (pnpm-lock.yaml) formats
- Better error handling prevents silent failures that could cause script hangs
- Minor UI cleanup and formatting improvements

### Fixed
- Progress display issues with line clearing and whitespace handling in file counts
- Script hanging issues when grep commands fail in strict shell environments with `set -eo pipefail`
- Silent pipeline failures that could prevent complete package detection
- File age detection compatibility between macOS (BSD) and Linux (GNU) systems

### Technical Details
- Added progress tracking with ANSI escape sequences for clean display updates
- Implemented arithmetic context wrapping for `wc -l` output to eliminate whitespace issues
- Added comprehensive test cases covering all 7 SHA-256 hash variants from Socket.dev analysis
- Added `transform_pnpm_yaml()` function to convert YAML lockfiles to pseudo-JSON for unified processing
- Implemented temporary file management for pnpm lockfile transformation
- Enhanced find command to detect all three major lockfile formats simultaneously
- Replaced BSD-specific `stat -f "%m"` with portable `date -r FILE +%s` for cross-platform compatibility

## [2.2.1] - 2025-09-19

### Added
- **Missing Socket.dev Packages**: Added 34 additional compromised packages from Socket.dev analysis that were previously missed
- @ctrl packages: Added 9 additional package versions
- @nativescript-community packages: Added 8 missing package versions  
- @rxap packages: Added 2 package versions
- Standalone packages: Added 15 additional packages

### Changed
- Updated compromised-packages.txt with comprehensive Socket.dev package list for complete coverage
- Enhanced package organization with clear section headers for different package groups
- Improved documentation to reflect complete coverage of all known compromised packages

### Security
- Ensures detection of all compromised packages identified across multiple security research sources
- Provides comprehensive protection against packages that may have been missed in previous analyses
- Complete coverage of Socket.dev's authoritative package analysis

## [2.2.0] - 2025-09-19

### Added
- **Multi-Hash Detection**: Added detection for all 7 Shai-Hulud worm variants (V1-V7) using comprehensive SHA-256 hash analysis
- Enhanced malicious file detection from single hash to complete attack timeline covering September 14-16, 2025
- Support for detecting evolved worm variants with different bundle.js signatures from Socket.dev's research
- MALICIOUS_HASHLIST array implementation for efficient multi-hash verification

### Changed
- Upgraded hash detection from single malicious file to comprehensive worm variant coverage
- Enhanced file scanning to detect all documented Shai-Hulud bundle.js evolution stages
- Improved detection accuracy for self-replicating worm variants that emerged during the campaign

### Security
- Complete coverage of all known Shai-Hulud worm variants based on Socket.dev's authoritative timeline analysis
- Detection of worm evolution from initial deployment through final stealth improvements
- Enhanced protection against missed variants that could evade single-hash detection

### Technical Details
- Implemented MALICIOUS_HASHLIST array containing 7 verified SHA-256 hashes from Socket.dev analysis
- Added iterative hash checking loop for efficient variant detection
- Source reference: https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages
- Hash variants cover complete worm evolution: V1 (de0e25a3...) through V7 (b74caeaa...)

## [2.1.0] - 2025-09-19

### Added
- **Enhanced Error Handling**: Added robust error handling for grep pipelines to prevent script hangs (merged PR #13)
- **pnpm Support**: Added comprehensive pnpm-lock.yaml support with YAML-to-JSON transformation capability
- Shell reliability improvements with `|| true` operators and `2>/dev/null` redirections
- Error prevention for strict `set -eo pipefail` environments

### Changed
- Improved script reliability across different shell configurations and package manager environments
- Enhanced lockfile detection to support npm (package-lock.json), yarn (yarn.lock), and pnpm (pnpm-lock.yaml) formats
- Better error handling prevents silent failures that could cause script hangs

### Fixed
- Script hanging issues when grep commands fail in strict shell environments
- Silent pipeline failures that could prevent complete package detection
- Compatibility issues with different bash configurations and `pipefail` settings

### Technical Details
- Added `transform_pnpm_yaml()` function to convert YAML lockfiles to pseudo-JSON for unified processing
- Implemented temporary file management for pnpm lockfile transformation
- Enhanced find command to detect all three major lockfile formats simultaneously

## [2.0.0] - 2025-09-18

### Added
- **Multi-Attack Coverage**: Now covers ALL September 2025 npm supply chain attacks
- Added 26 packages from Chalk/Debug crypto theft attack (September 8, 2025)
- New cryptocurrency theft detection function with multiple pattern checks:
  - Ethereum wallet address replacement patterns
  - XMLHttpRequest prototype hijacking detection
  - Known malicious function names (checkethereumw, runmask, etc.)
  - Known attacker wallet addresses from the September 8 attack
  - Phishing domain detection (npmjs.help)
  - JavaScript obfuscation pattern detection
- Attack-specific organization in compromised-packages.txt with clear sections
- Enhanced documentation explaining multiple attack types and timeline

### Changed
- Expanded scope from Shai-Hulud only to comprehensive September 2025 attack coverage
- Updated package count from 545 to 571+ compromised package versions
- Enhanced README with detailed attack timeline and characteristics
- Added cryptocurrency theft detection to core feature set

### Fixed
- Removed false positive: @ctrl/tinycolor:4.1.0 was never compromised (only 4.1.1 and 4.1.2 were malicious)
- Corrected package count references throughout documentation

## [1.3.0] - 2025-09-17

### Added
- **Complete JFrog integration**: Added comprehensive package list from JFrog security analysis
- Added 273 additional compromised package versions (540+ total)
- 6 new compromised namespaces: @basic-ui-components-stc, @nexe, @thangved, @tnf-dev, @ui-ux-gang, @yoobic
- Expanded coverage includes packages missed in previous analyses

### Changed
- Updated package detection from 270+ to 540+ compromised package versions
- Achieved comprehensive coverage of the complete JFrog 517-package analysis
- Updated all documentation references to reflect true attack scope (517+ packages)
- Enhanced namespace detection with 6 additional namespace patterns

### Security
- Includes all packages identified in comprehensive security research
- Provides industry-leading coverage against this supply chain attack

## [1.2.0] - 2025-09-17

### Added
- **Major package expansion**: Added 200+ additional compromised package versions
- @operato namespace: 87+ package versions (9.0.x series)
- @things-factory namespace: 25+ package versions (9.0.x series)
- @teselagen namespace: 18+ packages with correct versions (0.x.x series)
- @nstudio namespace: 20+ package versions (20.0.x and others)
- @crowdstrike namespace: 15+ additional packages
- @ctrl namespace: Additional golang-template and magnet-link packages
- Enhanced documentation with supply chain context

### Changed
- Updated package detection from 75+ to 270+ compromised package versions
- Fixed incorrect version numbers for multiple namespaces
- Improved coverage documentation with honest representation of detection scope
- Added Quick Start section for easier onboarding

### Fixed
- Corrected @teselagen package versions from 15.1.x to 0.x.x series
- Fixed @operato and @things-factory versions from 1.0.x to 9.0.x series
- Updated @nstudio versions from 18.1.x to 20.0.x series

## [1.1.0] - 2025-09-16

### Added
- External package list: Created `compromised-packages.txt` for easier maintenance
- Dynamic package loading functionality in main script
- Paranoid mode (`--paranoid` flag) for additional security checks
- Typosquatting detection with homoglyph pattern analysis
- Network exfiltration pattern detection
- Enhanced namespace detection for broader coverage
- Comprehensive test cases for validation

### Changed
- Externalized compromised package list from hardcoded array to external file
- Improved false positive handling with context-aware detection
- Enhanced output formatting and verbosity controls
- Updated documentation structure and maintenance instructions

### Fixed
- Reduced false positives from legitimate framework code
- Improved detection accuracy with risk level classification
- Fixed output formatting issues with ANSI codes

## [1.0.1] - 2025-09-16

### Added
- MIT License for open source distribution
- Enhanced detection capabilities for additional attack patterns
- Improved context-aware analysis to reduce false positives

### Fixed
- False positive detection in legitimate framework code
- Output formatting and clarity improvements

## [1.0.0] - 2025-09-16

### Added
- Initial release of Shai-Hulud NPM Supply Chain Attack Detector
- Core detection for malicious workflow files (`shai-hulud-workflow.yml`)
- SHA-256 hash verification for known malicious files
- Package.json analysis for compromised package versions
- Postinstall hook detection for suspicious scripts
- Content scanning for webhook.site and malicious endpoints
- Trufflehog activity detection for credential scanning
- Git branch analysis for suspicious branches
- Repository detection for "Shai-Hulud" data exfiltration repos
- Package integrity checking for lockfiles
- Comprehensive test cases with clean/infected/mixed projects
- Cross-platform support for macOS and Unix-like systems
- Detailed output with risk level classification
- Initial compromised package database covering major affected namespaces

### Security
- Detection of 75+ initially confirmed compromised packages
- Support for @ctrl, @crowdstrike, @art-ws, @ngx, @nativescript-community namespaces
- Hash-based detection of known malicious payloads
- Comprehensive IoC detection for the Shai-Hulud worm attack

---

## Legend

- **Added** for new features
- **Changed** for changes in existing functionality
- **Deprecated** for soon-to-be removed features
- **Removed** for now removed features
- **Fixed** for any bug fixes
- **Security** for vulnerability fixes and security improvements

# Shai-Hulud Supply Chain Attack Detector (npm + PyPI)

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-Bash%205.0%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-Active-success)](../../)
[![Contributions](https://img.shields.io/badge/contributions-Welcome-orange)](CONTRIBUTING.md)
[![Last Commit](https://img.shields.io/github/last-commit/Cobenian/shai-hulud-detect)](https://github.com/Cobenian/shai-hulud-detect/commits/main)
[![Security Tool](https://img.shields.io/badge/type-Security%20Tool-red)](#overview)


<img src="shai_hulu_detector.jpg" alt="sshd" width="80%" />

A Bash tool that helps you spot known traces of the September 2025 through May 2026 npm and PyPI supply-chain attacks—including the Shai-Hulud self-replicating worm, the chalk/debug crypto-theft incident, the "Shai-Hulud: The Second Coming" fake Bun runtime attack, the February 2026 SANDWORM_MODE campaign, the March 2026 axios supply chain compromise, and the May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime campaign (now confirmed crossing into PyPI). It cross-checks 2,100+ confirmed bad package versions across multiple campaigns and checks for the most relevant red flags in your project.

## Supported Ecosystems

The detector auto-detects which package ecosystems your project uses and runs the relevant checks for each. Ecosystem-specific checks (manifest parsing, lockfile analysis) only fire when the relevant marker files are present; content-pattern checks (file hashes, C2 domains, dead-man's-switch artifacts, wipe-threat strings, etc.) always run.

- **npm**: detected via `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- **PyPI**: detected via `pyproject.toml`, `requirements.txt`, `requirements-*.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg`

Marker discovery excludes `node_modules/`, `.venv/`, `venv/`, `.tox/`, and `site-packages/`. Override with `--ecosystem=npm`, `--ecosystem=pypi`, `--ecosystem=all`, or a comma-separated list. PyPI parsers are pure-bash awk (no Python required) and support exact version pins; range specifiers (`>=`, `^`, `~=`) are intentionally skipped in manifests since lockfiles always carry exact versions.

## Overview

Covers multiple npm supply chain attacks from September 2025 through May 2026:

### **Chalk/Debug Crypto Theft Attack** (September 8, 2025)
- **Scope**: 18+ packages with 2+ billion weekly downloads
- **Attack**: Cryptocurrency wallet address replacement in browsers
- **Duration**: ~2 hours before detection
- **Packages**: chalk, debug, ansi-styles, color-*, supports-*, and others
- **Method**: XMLHttpRequest hijacking to steal crypto transactions

### **Shai-Hulud Self-Replicating Worm** (September 14-16, 2025)
- **Scope**: 517+ packages across multiple namespaces
- **Attack**: Credential harvesting and self-propagation
- **Method**: Uses Trufflehog to scan for secrets, publishes stolen data to GitHub
- **Propagation**: Self-replicates using stolen npm tokens
- **Packages**: @ctrl/*, @crowdstrike/*, @operato/*, and many others

### **Shai-Hulud: The Second Coming** (November 24, 2025)
- **Scope**: 300+ packages with millions of weekly downloads
- **Attack**: Fake Bun runtime installation with credential harvesting
- **Method**: Uses fake `setup_bun.js` preinstall hook to download and execute TruffleHog
- **Exfiltration**: Creates GitHub Actions runners named "SHA1HULUD" and repositories with "Sha1-Hulud: The Second Coming" descriptions
- **Packages**: @zapier/*, @posthog/*, @asyncapi/*, @postman/*, @ensdomains/*, and many others
- **Files**: `setup_bun.js`, `bun_environment.js` (10MB+ obfuscated payload), `actionsSecrets.json` (double Base64 encoded)
- **Workflow**: `.github/workflows/formatter_*.yml` files using SHA1HULUD runners

### **Shai-Hulud: Golden Path Variant** (December 28, 2025)
- **Scope**: Continuation of Second Coming attack with renamed files
- **Attack**: Same fake Bun runtime technique with obfuscated file names
- **Method**: Uses `bun_installer.js` and `environment_source.js` (renamed from `setup_bun.js` and `bun_environment.js`)
- **Exfiltration**: Obfuscated JSON files for staging stolen credentials: `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json`
- **Packages**: @vietmoney/react-big-calendar (versions 0.26.0-0.26.2)
- **Repo Description**: "Goldox-T3chs: Only Happy Girl"

### **SANDWORM_MODE AI Toolchain Poisoning** (February 17, 2026)
- **Scope**: 19 confirmed malicious npm packages + workflow propagation IoCs
- **Attack**: Typosquatted AI toolchain packages and poisoned CI workflow distribution
- **Method**: Malicious GitHub Action `ci-quality/code-quality-check@v1` injects `.github/workflows/quality.yml`
- **Threat actor aliases**: `official334`, `javaorg`
- **Packages**: `claud-code`, `cloude-code`, `cloude`, `opencraw`, `veim`, `yarsg`, and others
- **Source**: [Socket.dev analysis](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning)

### **Axios Supply Chain Attack** (March 31, 2026)
- **Scope**: Compromised axios maintainer account publishes malicious versions with RAT dropper
- **Attack**: Injected `plain-crypto-js` dependency delivers cross-platform Remote Access Trojan
- **Method**: Postinstall hook runs obfuscated `setup.js` that drops platform-specific RAT; beacons every 60s
- **C2**: `sfrclak.com` (142.11.206.73:8000)
- **Packages**: `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`
- **Attacker accounts**: `nrwise` (`nrwise@proton.me`), hijacked `jasonsaayman` (`ifstap@proton.me`)
- **Anti-forensics**: Dropper overwrites its own package.json version from 4.2.1 to 4.2.0
- **Source**: [StepSecurity analysis](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)

### **Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime** (May 11, 2026)
- **Scope**: 400+ compromised package versions across @tanstack (84 versions / 42 packages), @mistralai, @opensearch-project, @uipath, @squawk, @draftlab, @draftauth, @tallyui, @beproduct, and many others
- **Attack**: Self-spreading worm with a dead-man's-switch — hijacks legitimate release pipelines via `pull_request_target` "Pwn Request" + GitHub Actions cache poisoning + runtime OIDC token extraction; first known case of a malicious npm package shipped with valid SLSA provenance
- **Method**: A `2.3MB` obfuscated `router_init.js` / `tanstack_runner.js` is smuggled into each tarball and triggered through an `optionalDependencies` entry pointing at an orphan commit in an attacker-owned fork; the payload installs a `gh-token-monitor` service (LaunchAgent on macOS, systemd `--user` on Linux) that polls `api.github.com/user` every 60 s and is designed to **wipe the host if the monitored GitHub token is revoked**
- **C2**: `api.masscan.cloud`, `git-tanstack.com`, `filev2.getsession.org`, `seed1.getsession.org`
- **Threat actor**: TeamPCP (npm/GitHub account `voicproducoes`)
- **Wipe-threat marker**: npm token description literally reads `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`
- **Marker repos**: `siridar-ghola-567`, `tleilaxu-ornithopter-43` (description: "A Mini Shai-Hulud has Appeared")
- **Remediation caveat**: **Stop and remove the `gh-token-monitor` service BEFORE rotating tokens.** Run with `--check-host` to detect persistence artifacts.
- **Sources**: [StepSecurity](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem) · [Socket](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack) · [Semgrep](https://semgrep.dev/blog/2026/tanstack-router-packages-hit-by-coordinated-supply-chain-attack/) · [Wiz](https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised) · [Snyk](https://snyk.io/blog/tanstack-npm-packages-compromised/) · [Aikido](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) · [TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Cobenian/shai-hulud-detect
cd shai-hulud-detect

# Make the script executable
chmod +x shai-hulud-detector.sh

# Scan your project for Shai-Hulud indicators
./shai-hulud-detector.sh /path/to/your/project

# For comprehensive security scanning
./shai-hulud-detector.sh --paranoid /path/to/your/project

# Save findings to a log file for review or CI/CD artifacts
./shai-hulud-detector.sh --save-log report.log /path/to/your/project

# Check exit code for CI/CD integration
./shai-hulud-detector.sh /path/to/your/project
echo "Exit code: $?"  # 0=clean, 1=high-risk, 2=medium-risk
```

**CI/CD Integration**: The script returns appropriate exit codes (0=clean, 1=high-risk, 2=medium-risk) for seamless integration into automated security pipelines.

## What it Detects

### High Risk Indicators
- **Malicious workflow files**: `shai-hulud-workflow.yml` files in `.github/workflows/` (September 2025), `formatter_*.yml` files using SHA1HULUD runners (November 2025), and SANDWORM_MODE workflow IoCs including `ci-quality/code-quality-check@v1` and poisoned `quality.yml` workflow references (February 2026)
- **Known malicious file hashes**: Files matching any of 10 SHA-256 hashes spanning the Shai-Hulud worm variants (V1-V7), the Mini Shai-Hulud `router_init.js` / `tanstack_runner.js` payloads, and the malicious `@tanstack/setup` package.json — sourced from [Socket.dev's comprehensive attack analysis](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages) and [StepSecurity's Mini Shai-Hulud disclosure](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
- **November 2025 Bun attack files**: `setup_bun.js`/`bun_installer.js` (fake Bun runtime installer) and `bun_environment.js`/`environment_source.js` (10MB+ obfuscated credential harvesting payload)
- **Obfuscated exfiltration files**: `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json` (Golden Path variant - stolen credentials staged for exfiltration)
- **Compromised package versions**: Specific versions of 2,100+ packages from multiple attacks (September 2025 through May 2026)
- **Suspicious postinstall hooks**: Package.json files with postinstall scripts containing curl, wget, eval commands, or fake Bun installation (`"preinstall": "node setup_bun.js"`)
- **Trufflehog activity**: Files containing trufflehog references, credential scanning patterns, or November 2025 enhanced patterns (automated TruffleHog download and execution)
- **Shai-Hulud repositories**: Git repositories named "Shai-Hulud" (used for data exfiltration) or with "Sha1-Hulud: The Second Coming" or "Goldox-T3chs: Only Happy Girl" descriptions
- **Secrets exfiltration files**: `actionsSecrets.json` files with double Base64 encoded credentials (November 2025)
- **SHA1HULUD GitHub Actions runners**: GitHub Actions workflows using malicious runners for credential theft
- **SANDWORM_MODE workflow IoCs**: Workflow files containing `ci-quality/code-quality-check@v1`, actor aliases (`official334`, `javaorg`), or related propagation module references
- **Axios supply chain attack IoCs**: C2 domain `sfrclak.com` / IP `142.11.206.73`, XOR key `OrDeR_7077`, `plain-crypto-js` dependency (malicious RAT dropper), and filesystem persistence artifacts (March 2026)
- **Mini Shai-Hulud / TanStack IoCs**: `router_init.js` / `tanstack_runner.js` payload files (May 2026); wipe-threat token-description string `IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`; marker repos `siridar-ghola-567` / `tleilaxu-ornithopter-43`; C2 domains `api.masscan.cloud`, `git-tanstack.com`, `filev2.getsession.org`, `seed1.getsession.org`; threat-actor reference `voicproducoes`; malicious orphan-commit SHA `79ac49eedf774dd4b0cfa308722bc463cfe5885c`; campaign-specific PBKDF2 constants; structural `package.json` signals (orphan-commit `optionalDependencies`, `bun run tanstack_runner.js` prepare hook, fake `@tanstack/setup` reference)
- **PyPI cross-ecosystem spread (TeamPCP threat actor, March-May 2026)**: 11 malicious version artifacts across 6 projects — `pypi:mistralai:2.4.6`, `pypi:guardrails-ai:0.10.1` (May 2026 Mini Shai-Hulud); `pypi:lightning:2.6.2`, `pypi:lightning:2.6.3` (April 2026 sub-wave); `pypi:xinference:2.6.0`/`:2.6.1`/`:2.6.2` (April 2026); `pypi:telnyx:4.87.1`/`:4.87.2` (March 2026); `pypi:litellm:1.82.7`/`:1.82.8` (March 2026)
- **Mini Shai-Hulud dead-man's-switch artifacts** (opt-in via `--check-host`): `~/Library/LaunchAgents/com.user.gh-token-monitor.plist`, `~/.config/systemd/user/gh-token-monitor.service`, `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/token` — reported with a CRITICAL warning that revoking a monitored GitHub token before stopping the service is designed to trigger a destructive wipe

### Medium Risk Indicators
- **Suspicious content patterns**: References to `webhook.site` and the malicious endpoint `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Suspicious git branches**: Branches named "shai-hulud"
- **Semver pattern matching**: Packages that could become compromised during `npm update` due to caret (^) or tilde (~) version patterns

### Low Risk Indicators
- **Namespace warnings**: Packages from namespaces known to be affected (@ctrl, @crowdstrike, @art-ws, @ngx, @nativescript-community) but at safe versions

### Package Detection Method

The script loads a list of the compromised packages from an external file (`compromised-packages.txt`) which contains:
- **2,100+ confirmed compromised package versions** with exact version numbers (September 2025 through May 2026 campaigns)
- **30+ affected namespaces** for broader detection of packages from compromised maintainer accounts
- **Multi-ecosystem entries**: bare lines (e.g. `axios:1.14.1`) are interpreted as npm for backward compatibility; PyPI entries use the `pypi:` prefix (e.g. `pypi:mistralai:2.4.6`); npm entries may use the explicit `npm:` prefix.

### Maintaining and Updating the Package List

**Important**: The Shai-Hulud attack was self-replicating, meaning new compromised packages may still be discovered. The compromised packages list is stored in `compromised-packages.txt` for easy maintenance:

- **Format**: `package_name:version` (one per line)
- **Comments**: Lines starting with `#` are ignored
- **Updates**: The file can be updated as new compromised packages are discovered
- **Fallback**: If the file is missing, the script uses a core embedded list

### Staying Updated on New Compromised Packages

Check these security advisories regularly for newly discovered compromised packages:

- **[StepSecurity Blog](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)** - Original comprehensive analysis
- **[Semgrep Security Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)** - Detailed technical analysis
- **[JFrog Security Research](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)** - Ongoing detection of new packages
- **[Wiz Security Blog](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)** - Attack analysis with package appendix
- **[Socket.dev Blog](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)** - CrowdStrike package analysis
- **[Socket.dev Blog](https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning)** - SANDWORM_MODE AI toolchain poisoning campaign
- **[HelixGuard](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)** - Second Coming analysis
- **[StepSecurity Blog](https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan)** - March 2026 axios supply chain compromise
- **[StepSecurity Blog](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)** - May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime campaign
- **[Socket.dev Blog](https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack)** - Mini Shai-Hulud TanStack package inventory
- **[Semgrep Blog](https://semgrep.dev/blog/2026/tanstack-router-packages-hit-by-coordinated-supply-chain-attack/)** - Mini Shai-Hulud full IoC list
- **[TanStack Postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)** - Authoritative incident postmortem

### How to Add Newly Discovered Packages

1. Check the security advisories above for new compromised packages
2. Add them to `compromised-packages.txt` in the format `package_name:version`
3. Test the script to ensure detection works
4. Consider contributing updates back to this repository

**Coverage Note**: Multiple campaigns from September 2025 through May 2026 affected 2,100+ packages total. Our detection aims to provide **comprehensive coverage** across the Shai-Hulud worm (517+ packages), Chalk/Debug crypto theft (26+ packages), "Shai-Hulud: The Second Coming" fake Bun runtime attack (1,100+ packages), the Golden Path variant, the February 2026 SANDWORM_MODE campaign, the March 2026 axios supply chain compromise, and the May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime campaign (400+ packages).

### Core vs Paranoid Mode

**Core Mode (Default)**
- Focuses specifically on Shai-Hulud attack indicators
- Recommended for most users checking for this specific threat
- Clean, focused output with minimal false positives

**Paranoid Mode (`--paranoid`)**
- Includes all core Shai-Hulud detection PLUS additional security checks
- Adds typosquatting detection and network exfiltration pattern analysis
- **Important**: Paranoid features are general security tools, not specific to Shai-Hulud
- May produce more false positives from legitimate code
- Useful for comprehensive security auditing

**Semver Range Checking (`--check-semver-ranges`)**
- Checks if package.json semver ranges (^, ~) could resolve to compromised versions
- Reports LOW risk in both cases (informational warning about latent risk)
- Useful for identifying latent risk in private npm caches that may still have malicious versions

## Requirements

- macOS or Unix-like system
- **Bash 5.0 or newer** (required for associative arrays and performance features)
  - macOS: `brew install bash` then run with `/opt/homebrew/bin/bash ./shai-hulud-detector.sh`
  - Linux: Most modern distributions include Bash 5.x by default
  - Check your version: `bash --version`
- Standard Unix tools: `find`, `grep`, `shasum`

### Grep Tool Selection

The script automatically selects the fastest available grep tool in this priority order:
1. **git grep** (default) - Uses a DFA-based regex engine with no backtracking, fastest for our patterns (~40% faster than ripgrep)
2. **ripgrep** (fallback) - Also DFA-based, excellent performance
3. **grep** (last resort) - May experience catastrophic backtracking on complex patterns

You can override the auto-selection with flags:
- `--use-git-grep` - Force git grep
- `--use-ripgrep` - Force ripgrep
- `--use-grep` - Force standard grep

**Why git grep is default**: Our testing shows git grep is ~40% faster than ripgrep on large codebases. Both use DFA-based regex engines that avoid the catastrophic backtracking that causes standard grep to hang on complex patterns.

## Output Interpretation

### Clean System
```
✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

### Compromised System
The script will show:
- **🚨 HIGH RISK**: Definitive indicators of compromise
- **⚠️ MEDIUM RISK**: Suspicious patterns requiring manual review
- **Summary**: Count of issues found

### What to Do if Issues are Found

#### High Risk Issues
- **Immediate action required**
- Update or remove compromised packages
- Review and remove malicious workflow files
- Scan for credential theft
- Consider full system audit

#### Medium Risk Issues
- **Manual investigation needed**
- Review flagged files for legitimacy
- Check if webhook.site usage is intentional
- Verify git branch purposes

## Exit Codes for CI/CD Integration

The script returns specific exit codes to enable proper CI/CD pipeline integration:

- **Exit Code 0**: Clean system - no significant security findings
- **Exit Code 1**: High-risk findings detected - immediate action required
- **Exit Code 2**: Medium-risk findings detected - manual investigation needed

### CI/CD Pipeline Examples

#### GitHub Actions
```yaml
- name: Security Scan with Shai-Hulud Detector
  run: |
    chmod +x ./shai-hulud-detector.sh
    ./shai-hulud-detector.sh .
  # Pipeline will automatically fail on exit codes 1 or 2
```

#### GitLab CI
```yaml
security_scan:
  script:
    - chmod +x ./shai-hulud-detector.sh
    - ./shai-hulud-detector.sh .
  # Job fails automatically on non-zero exit codes
```

#### Jenkins
```groovy
stage('Security Scan') {
  steps {
    sh '''
      chmod +x ./shai-hulud-detector.sh
      ./shai-hulud-detector.sh .
    '''
  }
  // Build fails automatically on non-zero exit codes
}
```

#### Custom Handling by Exit Code
```bash
#!/bin/bash
./shai-hulud-detector.sh .
exit_code=$?

case $exit_code in
    0) echo "✅ Security scan passed - no issues found" ;;
    1) echo "🚨 CRITICAL: High-risk security issues found - blocking deployment"
       exit 1 ;;
    2) echo "⚠️ WARNING: Medium-risk issues found - review required"
       # Could choose to continue with warnings
       ;;
esac
```

### Saving Findings to a Log File

Use `--save-log FILE` to save all detected file paths to a structured log file:

```bash
./shai-hulud-detector.sh --save-log findings.log /path/to/project
```

The log file contains file paths grouped by severity level:

```
# HIGH
/path/to/malicious-workflow.yml
/path/to/compromised-package.json
# MEDIUM
/path/to/suspicious-content.js
# LOW
/path/to/namespace-warning.json
```

This format is designed for:
- **CI/CD artifacts**: Store scan results as build artifacts for review
- **Programmatic parsing**: Easy to parse with simple scripts
- **Full coverage**: Includes ALL findings without display truncation

## Testing

The repository includes a comprehensive test suite with 43 test cases. Use the automated test runner to validate all cases:

```bash
# Run the full test suite (recommended)
./run-tests.sh

# The test suite validates expected exit codes and risk levels for all test cases
# Exit codes: 0=clean, 1=high-risk, 2=medium-risk
```

You can also run individual test cases manually:

```bash
# Test on clean project (should show no issues)
./shai-hulud-detector.sh test-cases/clean-project

# Test on infected project (should show multiple issues)
./shai-hulud-detector.sh test-cases/infected-project

# Test November 2025 "Shai-Hulud: The Second Coming" attack (should show HIGH risk for all new patterns)
./shai-hulud-detector.sh test-cases/november-2025-attack

# Test on mixed project (should show medium risk issues)
./shai-hulud-detector.sh test-cases/mixed-project

# Test namespace warnings (should show LOW risk namespace warnings only)
./shai-hulud-detector.sh test-cases/namespace-warning

# Test semver matching (should show MEDIUM risk for packages that could match compromised versions)
./shai-hulud-detector.sh test-cases/semver-matching

# Test legitimate crypto libraries (should show MEDIUM risk only)
./shai-hulud-detector.sh test-cases/legitimate-crypto

# Test chalk/debug attack patterns (should show HIGH risk compromised packages + MEDIUM risk crypto patterns)
./shai-hulud-detector.sh test-cases/chalk-debug-attack

# Test common crypto libraries (should not trigger HIGH risk false positives)
./shai-hulud-detector.sh test-cases/common-crypto-libs

# Test legitimate XMLHttpRequest modifications (should show LOW risk only)
./shai-hulud-detector.sh test-cases/xmlhttp-legitimate

# Test malicious XMLHttpRequest with crypto patterns (should show HIGH risk crypto theft + MEDIUM risk XMLHttpRequest patterns)
./shai-hulud-detector.sh test-cases/xmlhttp-malicious

# Test lockfile false positive (should show no issues despite other package having compromised version)
./shai-hulud-detector.sh test-cases/lockfile-false-positive

# Test actual compromised package in lockfile (should show HIGH risk)
./shai-hulud-detector.sh test-cases/lockfile-compromised

# Test packages with safe lockfile versions (should show LOW risk with lockfile protection message)
./shai-hulud-detector.sh test-cases/lockfile-safe-versions

# Test mixed lockfile scenario (should show HIGH risk for compromised + LOW risk for safe)
./shai-hulud-detector.sh test-cases/lockfile-comprehensive-test

# Test packages without lockfile (should show MEDIUM risk for potential update risks)
./shai-hulud-detector.sh test-cases/no-lockfile-test

# Test typosquatting detection with paranoid mode (should show MEDIUM risk typosquatting warnings)
./shai-hulud-detector.sh --paranoid test-cases/typosquatting-project

# Test network exfiltration detection with paranoid mode (should show HIGH risk credential harvesting + MEDIUM risk network patterns)
./shai-hulud-detector.sh --paranoid test-cases/network-exfiltration-project

# Test clean project with paranoid mode (should show no issues - verifies no false positives)
./shai-hulud-detector.sh --paranoid test-cases/clean-project

# Test semver wildcard parsing (should correctly handle 4.x, 1.2.x patterns without errors)
./shai-hulud-detector.sh test-cases/semver-wildcards

# Test discussion workflow detection (should show CRITICAL risk for malicious discussion-triggered workflows)
./shai-hulud-detector.sh test-cases/discussion-workflows

# Test SANDWORM_MODE workflow IOC detection (should show HIGH risk for poisoned ci-quality action usage)
./shai-hulud-detector.sh test-cases/sandworm-mode-workflow

# Test axios supply chain attack IOC detection (should show HIGH risk for C2, XOR key, plain-crypto-js)
./shai-hulud-detector.sh test-cases/axios-attack

# Test Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime IOC detection (May 2026; should show HIGH risk)
./shai-hulud-detector.sh test-cases/tanstack-attack

# Test Mini Shai-Hulud dead-man's-switch artifact detection (should show HIGH risk + wipe warning)
./shai-hulud-detector.sh test-cases/mini-shai-hulud-dead-mans-switch

# Test last-known-good @tanstack/* versions (should be clean — no false positives)
./shai-hulud-detector.sh test-cases/tanstack-clean

# Test PyPI Mini Shai-Hulud cross-ecosystem spread (requirements.txt with mistralai==2.4.6)
./shai-hulud-detector.sh test-cases/pypi-attack-requirements

# Test PyPI compromise in Poetry project (pyproject.toml + poetry.lock with guardrails-ai==0.10.1)
./shai-hulud-detector.sh test-cases/pypi-attack-poetry

# Test polyglot project with both npm AND PyPI compromises (exercises auto-detection of both ecosystems)
./shai-hulud-detector.sh test-cases/polyglot-attack

# Test safe PyPI versions (should be clean — verifies no false positives)
./shai-hulud-detector.sh test-cases/pypi-clean

# Test GitHub Actions runner detection (should show CRITICAL risk for SHA1HULUD self-hosted runners)
./shai-hulud-detector.sh test-cases/github-actions-runners

# Test file hash verification (should validate benign files against malicious hashes)
./shai-hulud-detector.sh test-cases/hash-verification

# Test destructive pattern detection (should show CRITICAL risk for data destruction commands)
./shai-hulud-detector.sh test-cases/destructive-patterns
```

### Paranoid Mode Testing

The `--paranoid` flag enables additional security checks beyond Shai-Hulud-specific detection:

- **Typosquatting Detection**: Identifies packages with names similar to popular packages (e.g., "raect" instead of "react", "lodsh" instead of "lodash")
- **Network Exfiltration Patterns**: Detects suspicious domains (webhook.site, pastebin.com), hardcoded IP addresses, WebSocket connections to external endpoints
- **Enhanced Security Auditing**: Useful for comprehensive project security reviews

**Note**: Paranoid mode may produce more false positives from legitimate code patterns, so review findings carefully.

## How it Works

The script performs these checks:

1. **Package Database Loading**: Loads 2,100+ compromised packages from `compromised-packages.txt` into O(1) lookup maps
2. **Workflow Detection**: Searches for `shai-hulud-workflow.yml` files (September 2025), `formatter_*.yml` files with SHA1HULUD runners (November 2025), SANDWORM_MODE workflow IoCs (February 2026), axios supply chain attack IoCs (March 2026), and Mini Shai-Hulud TanStack IoCs (May 2026)
3. **Hash Verification**: Calculates SHA-256 hashes against 10 known malicious file hashes — 7 Shai-Hulud worm `bundle.js` variants (V1-V7), `router_init.js`, `tanstack_runner.js`, and the malicious `@tanstack/setup` package.json
4. **Package Analysis**: Parses `package.json` files for compromised versions and affected namespaces
5. **Semver Range Checking** (opt-in with `--check-semver-ranges`): Checks if version ranges could resolve to compromised versions
6. **Postinstall Hook Detection**: Identifies suspicious postinstall/preinstall scripts containing curl, wget, eval, or fake Bun patterns
7. **Content Scanning**: Searches for suspicious URLs, webhook endpoints, and malicious patterns
8. **Cryptocurrency Theft Detection**: Identifies wallet replacement patterns, XMLHttpRequest hijacking, and crypto theft functions
9. **Trufflehog Activity Detection**: Looks for credential scanning tools and secret harvesting patterns
10. **Git Analysis**: Checks for suspicious branch names ("shai-hulud")
11. **Repository Detection**: Identifies "Shai-Hulud", "Second Coming", and "Goldox-T3chs" repository patterns
12. **November 2025 Bun Attack Detection**: Identifies `setup_bun.js`/`bun_installer.js` and `bun_environment.js`/`environment_source.js` attack files
13. **GitHub Actions Runner Detection**: Identifies malicious SHA1HULUD runners
14. **Discussion Workflow Detection**: Identifies workflows that trigger on discussion events (stealth persistence)
15. **Destructive Payload Detection**: Identifies destructive fallback patterns (`rm -rf`, `fs.rmSync`, etc.)
16. **Lockfile Integrity Checking**: Analyzes package-lock.json, yarn.lock, and pnpm-lock.yaml for compromised packages
17. **Typosquatting Detection** (paranoid mode): Identifies packages with names similar to popular packages
18. **Network Exfiltration Detection** (paranoid mode): Detects suspicious domains and hardcoded IPs
19. **Obfuscated Exfiltration Detection**: Identifies Golden Path variant staging files (`3nvir0nm3nt.json`, `cl0vd.json`, etc.)
20. **Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime Detection** (May 2026): Identifies `router_init.js` / `tanstack_runner.js` payloads, the wipe-threat token-description string, marker repos, C2 domains, threat-actor references, malicious orphan-commit `optionalDependencies`, fake `@tanstack/setup` references, and (opt-in via `--check-host`) the `gh-token-monitor` dead-man's-switch persistence artifacts on the host. CRITICAL: revoking a monitored GitHub token while the service is active is designed to trigger a destructive wipe — stop the service before rotating credentials.
21. **PyPI Ecosystem Support** (May 2026): Auto-detects Python projects via marker files (`pyproject.toml`, `requirements*.txt`, `Pipfile*`, `poetry.lock`, `uv.lock`, `setup.py`, `setup.cfg`) and parses them with pure-bash awk parsers (no Python required). Exact version pins are checked against the `pypi:` entries in `compromised-packages.txt`. Range specifiers in manifests are intentionally not enforced; lockfiles carry exact versions and are authoritative. PEP 503 name normalization (lowercase + collapse `-`/`_`/`.`) is applied before lookup. Override auto-detection with `--ecosystem=npm|pypi|all|<list>`.

## Limitations

- **Hash Detection**: Only detects files with exact matches to the 7 known malicious hashes
- **Package Versions**: Detects specific compromised versions; new variants may not be detected until the package list is updated
- **False Positives**: Legitimate use of webhook.site, Trufflehog, or postinstall hooks may trigger alerts
- **Worm Evolution**: New variants may emerge with different signatures
- **Semver Ranges**: The `--check-semver-ranges` flag is informational only; compromised versions are largely unpublished from npm

## Security Note

This script is for **detection only**. It does not:
- Automatically remove malicious code
- Fix compromised packages
- Prevent future attacks

Always verify findings manually and take appropriate remediation steps.

## References

### Primary Sources
- [StepSecurity Blog: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [JFrog: New compromised packages in largest npm attack in history](https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/)
- [Aikido: NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)
- [Semgrep Security Advisory: NPM packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [Aikido: S1ngularity-nx attackers strike again](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)
- [Aikido: Shai-Hulud strikes again - The Golden Path](https://www.aikido.dev/blog/shai-hulud-strikes-again---the-golden-path)

### Additional Resources
- [Socket: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [Ox Security: NPM 2.0 hack: 40+ npm packages hit in major supply chain attack](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/)
- [Phoenix Security: NPM tinycolor compromise](https://phoenix.security/npm-tinycolor-compromise/)

## Contributing

We welcome contributions to improve any of the code, documentation, tests and packages covered. 

### How to Contribute

#### Adding New Compromised Packages

1. **Fork the repository** on GitHub, then clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/shai-hulud-detect.git
   cd shai-hulud-detect
   ```

2. **Update the package list**
   - Add new packages to `compromised-packages.txt` in the format `package_name:version`
   - Include a source/reference for where you found the compromised package

3. **Test your changes**
   ```bash
   ./run-tests.sh
   # All 37 tests should pass
   ```

4. **Submit a Pull Request**
   - Push to your fork and open a PR against the upstream repository
   - Include the source of the information (security advisory, blog post, etc.)

#### Other Contributions

- **Bug fixes**: Report and fix issues with detection accuracy
- **New IoCs**: Add detection for additional indicators of compromise
- **Documentation**: Improve clarity and add examples
- **Test cases**: Add new test scenarios for edge cases

### Contribution Guidelines

- **Verify sources**: Only add packages confirmed by reputable security firms
- **Test thoroughly**: Ensure changes don't break existing functionality
- **Document changes**: Update relevant documentation and changelog
- **Follow patterns**: Match existing code style and organization
- **Security first**: Never include actual malicious code in test cases

### Reporting New Compromised Packages

If you can't submit a PR, you can still help by reporting new compromised packages:

1. Open an issue with the title "New compromised package: [package-name]"
2. Include the package name, version, and source of information
3. Provide links to security advisories or reports
4. We'll review and add verified packages to the detection list

## Release Notes

For a complete list of changes and version history, see the [CHANGELOG.md](CHANGELOG.md).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

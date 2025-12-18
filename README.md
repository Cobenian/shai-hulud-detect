# Shai-Hulud NPM Supply Chain Attack Detector

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-Bash-blue)](#requirements)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)](#requirements)
[![Status](https://img.shields.io/badge/status-Active-success)](../../)
[![Contributions](https://img.shields.io/badge/contributions-Welcome-orange)](#contributing)
[![Last Commit](https://img.shields.io/github/last-commit/Cobenian/shai-hulud-detect)](https://github.com/Cobenian/shai-hulud-detect/commits/main)
[![Security Tool](https://img.shields.io/badge/type-Security%20Tool-red)](#overview)

<img src="shai_hulu_detector.jpg" alt="Shai-Hulud Detector" width="80%" />

**A zero-dependency Bash security tool to detect indicators of compromise from the September 2025 npm supply chain attacks, including the Shai-Hulud self-replicating worm and the chalk/debug crypto theft attack.**

This comprehensive detector protects against 571+ compromised package versions across multiple attack campaigns, representing the most severe JavaScript supply chain attacks to date with over 2 billion weekly downloads affected.

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [What it Detects](#what-it-detects)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Output Interpretation](#output-interpretation)
- [Detection Coverage](#detection-coverage)
- [How it Works](#how-it-works)
- [Testing](#testing)
- [Requirements](#requirements)
- [Limitations](#limitations)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [Latest Updates](#latest-updates)
- [References](#references)
- [License](#license)

---

## Overview

This detector covers multiple npm supply chain attacks from September 2025 that compromised the JavaScript ecosystem at an unprecedented scale:

### **Chalk/Debug Crypto Theft Attack** (September 8, 2025)

- **Scope**: 18+ packages with 2+ billion weekly downloads
- **Attack Vector**: Cryptocurrency wallet address replacement in browsers
- **Duration**: ~2 hours before detection
- **Target Packages**: `chalk`, `debug`, `ansi-styles`, `color-*`, `supports-*`, and others
- **Method**: XMLHttpRequest hijacking to intercept and redirect crypto transactions
- **Impact**: Potential theft from millions of active installations

### **Shai-Hulud Self-Replicating Worm** (September 14-16, 2025)

- **Scope**: 517+ packages across multiple namespaces
- **Attack Type**: Credential harvesting and self-propagation
- **Method**: Uses Trufflehog to scan for secrets, exfiltrates to GitHub repositories
- **Propagation**: Self-replicates using stolen npm tokens
- **Namespaces**: `@ctrl/*`, `@crowdstrike/*`, `@operato/*`, `@nativescript-community/*`, and many others
- **Impact**: Massive credential compromise and supply chain contamination

The script provides comprehensive protection by detecting indicators from both sophisticated attack campaigns.

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/Cobenian/shai-hulud-detect.git
cd shai-hulud-detect

# 2. Make the script executable
chmod +x shai-hulud-detector.sh

# 3. Scan your project
./shai-hulud-detector.sh /path/to/your/project

# 4. For comprehensive security scanning (includes typosquatting and network analysis)
./shai-hulud-detector.sh --paranoid /path/to/your/project

# 5. For faster scanning on multi-core systems
./shai-hulud-detector.sh --parallelism 8 /path/to/your/project
```

**Example Output:**
```
✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

---

## What it Detects

### **HIGH RISK** Indicators (Immediate Action Required)

- Malicious workflow files (`shai-hulud-workflow.yml` in `.github/workflows/`)
- Known malicious file hashes (7 SHA-256 hashes from Shai-Hulud worm variants V1-V7)
- Compromised package versions (571+ specific versions detected)
- Suspicious postinstall hooks (scripts containing `curl`, `wget`, or `eval`)
- Trufflehog credential scanning activity
- "Shai-Hulud" named repositories (used for data exfiltration)
- XMLHttpRequest hijacking patterns (crypto theft attack)
- Ethereum wallet replacement code
- Known attacker domains and endpoints

### **MEDIUM RISK** Indicators (Manual Investigation Required)

- Suspicious content patterns (references to `webhook.site` and malicious endpoints)
- Suspicious git branches (named "shai-hulud")
- Semver pattern matching (packages that could become compromised during `npm update`)
- Repository migration patterns (suspicious "-migration" suffixes)
- Typosquatting attempts (paranoid mode only)
- Network exfiltration patterns (paranoid mode only)

### **LOW RISK** Indicators (Awareness/Monitoring)

- Namespace warnings (packages from affected namespaces but at safe versions)

---

## Features

### Core Detection Capabilities

- **Zero Dependencies**: Pure Bash using only standard Unix tools (`find`, `grep`, `shasum`)
- **Cross-Platform**: Runs on macOS and Linux without modifications
- **Multi-Attack Coverage**: Detects both Shai-Hulud worm and chalk/debug crypto theft attacks
- **571+ Package Database**: Comprehensive list of compromised packages with exact versions
- **Hash-Based Detection**: Identifies 7 known malware variants by SHA-256 signatures
- **Lockfile Analysis**: Scans `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml`
- **Semver Pattern Matching**: Warns about packages at risk during dependency updates
- **Parallel Processing**: Leverages multi-core CPUs for faster scanning

### Security Analysis Features

1. **Package Version Detection**: Exact and semver pattern matching for compromised versions
2. **Malware Hash Verification**: SHA-256 hash checking against 7 known malicious bundles
3. **Crypto Theft Pattern Recognition**: Detects wallet replacement and XMLHttpRequest hijacking
4. **Postinstall Hook Analysis**: Identifies suspicious installation scripts
5. **Credential Scanning Detection**: Finds Trufflehog usage and secret harvesting patterns
6. **Git Repository Analysis**: Checks for suspicious branches and exfiltration repos
7. **Lockfile Integrity**: Multi-format lockfile analysis (npm/yarn/pnpm)
8. **Typosquatting Detection**: Identifies homoglyph-based package name attacks (paranoid mode)
9. **Network Exfiltration Patterns**: Detects suspicious network activity (paranoid mode)
10. **Progress Reporting**: Real-time scanning progress with file counts
11. **Risk Classification**: Clear HIGH/MEDIUM/LOW risk levels for triage

### Operational Features

- **Paranoid Mode**: Enhanced security scanning with additional checks
- **Configurable Parallelism**: Optimize performance for your system
- **External Package Database**: Easy updates via `compromised-packages.txt`
- **Comprehensive Testing**: 19+ test cases covering all detection scenarios
- **Detailed Reporting**: Clear, actionable output with risk levels
- **No Network Required**: All detection runs offline

---

## Installation

### Prerequisites

- macOS or Linux operating system
- Bash shell (version 4.0+)
- Standard Unix utilities: `find`, `grep`, `shasum` (or `sha256sum`)

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/Cobenian/shai-hulud-detect.git

# Navigate to the directory
cd shai-hulud-detect

# Make the script executable
chmod +x shai-hulud-detector.sh

# Verify installation
./shai-hulud-detector.sh --help
```

**Note**: The script requires the `compromised-packages.txt` file to be in the same directory for full detection capability.

---

## Usage

### Basic Usage

```bash
# Scan a project directory
./shai-hulud-detector.sh /path/to/project

# Scan current directory
./shai-hulud-detector.sh .

# Scan with paranoid mode (additional security checks)
./shai-hulud-detector.sh --paranoid /path/to/project

# Scan with custom parallelism
./shai-hulud-detector.sh --parallelism 8 /path/to/project

# Combine options
./shai-hulud-detector.sh --paranoid --parallelism 16 /path/to/project
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--paranoid` | Enable additional security checks (typosquatting, network patterns) |
| `--parallelism N` | Set number of parallel processes for hash scanning (default: CPU count) |
| `--help` | Display help information |

### Usage Examples

**Scan a Node.js project:**
```bash
./shai-hulud-detector.sh ~/projects/my-app
```

**Comprehensive security audit:**
```bash
./shai-hulud-detector.sh --paranoid ~/projects/production-app
```

**Fast scan on multi-core system:**
```bash
./shai-hulud-detector.sh --parallelism 16 /var/www/app
```

### Core vs Paranoid Mode

**Core Mode (Default)**
- Focuses specifically on Shai-Hulud and chalk/debug attack indicators
- Recommended for most users checking for these specific threats
- Clean, focused output with minimal false positives
- Fast execution time

**Paranoid Mode (`--paranoid`)**
- Includes all core detection PLUS additional security checks
- Adds typosquatting detection and network exfiltration pattern analysis
- General security tools, not specific to Shai-Hulud attacks
- May produce more false positives from legitimate code
- Useful for comprehensive security auditing
- Longer execution time

---

## Output Interpretation

### Clean System

```
🔍 Starting Shai-Hulud NPM Supply Chain Attack Detection...
📦 Loaded 571 compromised packages from compromised-packages.txt

[Scanning progress indicators...]

✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

### Compromised System

The script will display:

```
🚨 HIGH RISK: Compromised package detected: @ctrl/tinycolor@4.1.1 in /path/to/package.json
🚨 HIGH RISK: Malicious file hash detected: bundle.js (hash: de0e25a3...)
⚠️  MEDIUM RISK: Suspicious webhook.site reference in /path/to/file.js

═══════════════════════════════════════════════════════════
🔍 SCAN SUMMARY
═══════════════════════════════════════════════════════════
🚨 HIGH RISK issues found: 2
⚠️  MEDIUM RISK issues found: 1
ℹ️  LOW RISK issues found: 0
```

### Risk Level Definitions

| Level | Icon | Meaning | Action Required |
|-------|------|---------|----------------|
| **HIGH** | 🚨 | Definitive indicators of compromise | **Immediate action required** |
| **MEDIUM** | ⚠️ | Suspicious patterns requiring review | **Manual investigation needed** |
| **LOW** | ℹ️ | Awareness/monitoring recommended | **Review when convenient** |

---

## Detection Coverage

### Compromised Packages

The script detects **571+ confirmed compromised package versions** across multiple attack campaigns:

#### Key Compromised Packages

- `@ctrl/tinycolor@4.1.1, 4.1.2` - Shai-Hulud attack vector (2M+ weekly downloads)
- `chalk@5.6.1` - Crypto theft attack (100M+ weekly downloads)
- `debug@4.4.2` - Crypto theft attack (300M+ weekly downloads)
- `@art-ws/*` packages (16+ packages) - Art workspace utilities
- `@crowdstrike/*` packages (25+ packages) - CrowdStrike-related packages
- `@nativescript-community/*` packages (40+ packages) - NativeScript community tools
- `ngx-bootstrap`, `angulartics2`, `koa2-swagger-ui` - Popular standalone packages

#### Affected Namespaces (17 Total)

The following npm namespaces were compromised during the September 2025 attacks:

- `@ctrl/*` - Control utility packages
- `@crowdstrike/*` - CrowdStrike-related packages
- `@art-ws/*` - Art workspace packages
- `@ngx/*` - Angular-related packages
- `@nativescript-community/*` - NativeScript community packages
- `@ahmedhfarag/*`, `@operato/*`, `@teselagen/*` - Additional namespaces
- `@things-factory/*`, `@hestjs/*`, `@nstudio/*` - Development tools
- `@basic-ui-components-stc/*`, `@nexe/*`, `@thangved/*` - UI and tooling
- `@tnf-dev/*`, `@ui-ux-gang/*`, `@yoobic/*` - Additional affected namespaces

### Malware Hash Database

The script detects **7 distinct Shai-Hulud worm variants** (V1-V7) based on comprehensive research from Socket.dev:

| Variant | SHA-256 Hash | Date | Notes |
|---------|--------------|------|-------|
| V1 | `de0e25a3...` | Sept 14 | Initial deployment |
| V2 | `81d2a004...` | Sept 14 | Early iteration |
| V3 | `83a650ce...` | Sept 15 | Enhanced propagation |
| V4 | `4b239964...` | Sept 15 | Improved stealth |
| V5 | `dc67467a...` | Sept 15 | Credential harvesting |
| V6 | `46faab8a...` | Sept 16 | Final evolution |
| V7 | `b74caeaa...` | Sept 16 | Stealth improvements |

### Package Database Maintenance

**Important**: The Shai-Hulud attack was self-replicating, meaning new compromised packages may still be discovered.

#### Staying Updated

Check these security advisories regularly for newly discovered compromised packages:

- **[StepSecurity Blog](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)** - Original comprehensive analysis
- **[Semgrep Security Advisory](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)** - Detailed technical analysis
- **[JFrog Security Research](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)** - Ongoing detection
- **[Wiz Security Blog](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)** - Attack analysis with appendix
- **[Socket.dev Blog](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)** - CrowdStrike analysis

#### Adding New Packages

1. Check security advisories for new compromised packages
2. Add to `compromised-packages.txt` in format: `package_name:version`
3. Test detection: `./shai-hulud-detector.sh test-cases/clean-project`
4. Consider contributing updates via pull request

**Format Example (`compromised-packages.txt`):**
```
# Shai-Hulud Attack (September 14-16, 2025)
@ctrl/tinycolor:4.1.1
@ctrl/tinycolor:4.1.2

# Chalk/Debug Attack (September 8, 2025)
chalk:5.6.1
debug:4.4.2
```

---

## How it Works

The script performs 11 comprehensive security checks:

### Detection Workflow

1. **Package Database Loading**
   - Loads 571+ compromised packages from `compromised-packages.txt`
   - Initializes malicious hash database (7 variants)
   - Sets up namespace detection patterns

2. **Workflow File Detection**
   - Searches for `shai-hulud-workflow.yml` in `.github/workflows/`
   - Identifies malicious CI/CD automation attempts

3. **Hash-Based Malware Detection**
   - Calculates SHA-256 hashes of JavaScript/JSON files
   - Parallel processing for performance (configurable cores)
   - Matches against 7 known malicious bundle.js variants
   - Covers complete Shai-Hulud worm evolution (V1-V7)

4. **Package Version Analysis**
   - Parses `package.json` files for exact version matches
   - Checks against 571+ compromised package versions
   - Detects packages from 17 affected namespaces
   - Validates semver patterns for update risk assessment

5. **Postinstall Hook Detection**
   - Identifies suspicious postinstall scripts
   - Flags usage of `curl`, `wget`, `eval` in install hooks
   - Detects potential malware propagation mechanisms

6. **Cryptocurrency Theft Detection**
   - Identifies Ethereum wallet replacement patterns
   - Detects XMLHttpRequest prototype hijacking
   - Recognizes known malicious functions (`checkethereumw`, `runmask`)
   - Flags attacker wallet addresses from September 8 attack
   - Identifies phishing domains (`npmjs.help`)

7. **Content Pattern Scanning**
   - Greps for suspicious URLs and webhook endpoints
   - Detects known malicious endpoint: `webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
   - Identifies data exfiltration patterns

8. **Credential Scanning Detection**
   - Looks for Trufflehog references and usage
   - Detects secret harvesting patterns
   - Context-aware to reduce false positives

9. **Git Repository Analysis**
   - Checks for suspicious branch names ("shai-hulud")
   - Identifies "Shai-Hulud" repositories (data exfiltration)
   - Detects repository migration patterns

10. **Lockfile Integrity Checking**
    - Analyzes `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
    - Transforms pnpm YAML to JSON for unified processing
    - Detects compromised packages in dependency trees
    - Flags suspicious modifications

11. **Enhanced Security Checks (Paranoid Mode)**
    - Typosquatting detection with homoglyph analysis
    - Network exfiltration pattern recognition
    - General security vulnerability scanning

### Performance Optimizations

- **Parallel Processing**: Hash scanning uses all available CPU cores
- **Incremental Reporting**: Real-time progress updates during file scanning
- **Efficient Pattern Matching**: Optimized grep operations with early exit
- **Smart File Filtering**: Targets only relevant file types

---

## Testing

The repository includes comprehensive test cases to validate detection accuracy:

### Available Test Cases

```bash
# Clean project (should show no issues)
./shai-hulud-detector.sh test-cases/clean-project

# Infected project (should show multiple HIGH risk issues)
./shai-hulud-detector.sh test-cases/infected-project

# Mixed project (should show MEDIUM risk issues)
./shai-hulud-detector.sh test-cases/mixed-project

# Namespace warnings (should show LOW risk warnings only)
./shai-hulud-detector.sh test-cases/namespace-warning

# Semver matching (should show MEDIUM risk for update-vulnerable packages)
./shai-hulud-detector.sh test-cases/semver-matching

# Legitimate crypto libraries (should NOT trigger HIGH risk false positives)
./shai-hulud-detector.sh test-cases/legitimate-crypto

# Chalk/Debug attack patterns (should show HIGH risk)
./shai-hulud-detector.sh test-cases/chalk-debug-attack

# Common crypto libraries (should not trigger false positives)
./shai-hulud-detector.sh test-cases/common-crypto-libs

# Multi-hash detection (should detect all 7 hash variants)
./shai-hulud-detector.sh test-cases/multi-hash-detection
```

### Test Coverage

The test suite covers:
- All 7 Shai-Hulud worm hash variants
- Exact package version detection
- Semver pattern matching
- Namespace-based detection
- False positive prevention
- Risk level classification
- Both attack campaigns (Shai-Hulud and chalk/debug)

---

## Requirements

### System Requirements

- **Operating System**: macOS or Linux (Unix-like systems)
- **Shell**: Bash 4.0 or higher
- **Disk Space**: ~1 MB for script and database
- **Memory**: Minimal (runs efficiently on systems with limited RAM)

### Required Tools (Standard on Unix Systems)

- `find` - File discovery
- `grep` - Pattern matching
- `shasum` or `sha256sum` - Hash calculation
- `wc` - Line counting
- `date` - Timestamp operations

### Optional Tools (For Enhanced Features)

- `nproc` (Linux) or `sysctl` (macOS) - CPU core detection for parallel processing
- `xargs` - Parallel execution support

### Compatibility

| Platform | Status | Notes |
|----------|--------|-------|
| macOS | ✅ Fully Supported | Tested on macOS 10.15+ |
| Linux | ✅ Fully Supported | Tested on Ubuntu, Debian, RHEL |
| Windows | ⚠️ Requires WSL | Use Windows Subsystem for Linux |
| BSD | ⚠️ Untested | Should work but not officially supported |

---

## Limitations

### Detection Scope

- **Hash Detection**: Only detects files with exact matches to 7 known malicious bundle.js hashes
  - New worm variants with different hashes will not be detected
  - Hash-based detection cannot identify polymorphic malware

- **Package Versions**: Detects 571+ specific compromised versions
  - New compromised versions require database updates
  - Zero-day compromises will not be detected until database is updated

- **False Positives**: Legitimate tools may trigger alerts
  - `webhook.site` usage for debugging/testing
  - Trufflehog for legitimate security scanning
  - Postinstall hooks for valid build processes
  - Crypto libraries for legitimate blockchain applications

### Technical Limitations

- **Worm Evolution**: Self-replicating nature means new variants may emerge
  - Continuous monitoring of security advisories required
  - Regular updates to detection signatures needed

- **Coverage**: Covers known attacks from September 2025
  - Future supply chain attacks require separate detection logic
  - Not a general-purpose malware scanner

- **Package Integrity**: Relies on lockfile analysis
  - Sophisticated attacks may evade lockfile-based detection
  - Does not perform deep code analysis or decompilation

- **Performance**: Large codebases may take time to scan
  - Hash calculation on thousands of files can be slow
  - Parallel processing helps but is CPU-bound

### Operational Limitations

- **Detection Only**: This script does NOT:
  - Automatically remove malicious code
  - Fix compromised packages
  - Prevent future attacks
  - Quarantine infected files
  - Provide runtime protection

- **Manual Remediation Required**: Users must manually:
  - Update or remove compromised packages
  - Review and delete malicious files
  - Audit systems for credential theft
  - Implement preventive measures

---

## Security Considerations

### What to Do if Issues Are Found

#### HIGH RISK Issues (Immediate Action)

1. **Isolate the System**
   - Disconnect from network if actively running
   - Stop all Node.js processes

2. **Identify Compromised Packages**
   - Note all flagged packages and versions
   - Check `package.json` and lockfiles

3. **Remove Malicious Code**
   - Delete compromised packages: `npm uninstall <package>`
   - Remove malicious workflow files
   - Delete suspicious JavaScript files

4. **Update to Safe Versions**
   ```bash
   # Update to latest safe versions
   npm install @ctrl/tinycolor@latest
   npm install chalk@latest
   npm install debug@latest
   ```

5. **Audit for Credential Theft**
   - Assume all credentials may be compromised
   - Rotate npm tokens immediately
   - Change GitHub personal access tokens
   - Update API keys and secrets
   - Review git commit history for exposed secrets

6. **Check for Data Exfiltration**
   - Review network logs for connections to `webhook.site`
   - Check for "Shai-Hulud" repositories in your GitHub account
   - Audit recent package publishes

7. **Full System Audit**
   - Scan all other projects on the system
   - Review recent npm installs
   - Check for suspicious git activity

#### MEDIUM RISK Issues (Investigation Required)

1. **Manual Review**
   - Examine flagged files for legitimacy
   - Verify if `webhook.site` usage is intentional
   - Check git branch purposes

2. **Semver Pattern Warnings**
   - Review packages with caret (`^`) or tilde (`~`) versions
   - Pin to specific safe versions if concerned
   - Update with caution: `npm update --dry-run` first

3. **Context Analysis**
   - Determine if patterns are from legitimate code
   - Check commit history and authors
   - Verify package source and maintainers

#### LOW RISK Issues (Monitoring)

1. **Namespace Warnings**
   - Verify package versions are safe
   - Monitor for security advisories
   - Consider alternatives from unaffected namespaces

2. **Stay Informed**
   - Subscribe to security advisories
   - Follow npm security blog
   - Monitor this repository for updates

### Prevention Strategies

#### Package Management Best Practices

1. **Use Lockfiles**
   - Always commit `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
   - Prevents unexpected version updates

2. **Pin Exact Versions**
   ```json
   {
     "dependencies": {
       "chalk": "5.3.0",
       "debug": "4.3.4"
     }
   }
   ```

3. **Regular Audits**
   ```bash
   # Run npm audit regularly
   npm audit

   # Use this detector periodically
   ./shai-hulud-detector.sh .
   ```

4. **Enable 2FA on npm**
   ```bash
   npm profile enable-2fa auth-and-writes
   ```

#### Continuous Monitoring

1. **Automated Scanning**
   - Integrate this detector into CI/CD pipelines
   - Run on every dependency update
   - Gate deployments on clean scans

2. **Security Tools**
   - Use Socket.dev, Snyk, or similar dependency scanners
   - Enable GitHub Dependabot alerts
   - Subscribe to security mailing lists

3. **Code Review**
   - Review all `postinstall` scripts before installing packages
   - Be cautious with packages requiring postinstall hooks
   - Audit new dependencies before adding

### Incident Response Plan

If you discover a compromised system:

1. **Document everything** - Take screenshots, save logs
2. **Report to npm** - [security@npmjs.com](mailto:security@npmjs.com)
3. **Notify your team** - Alert other developers
4. **Update this repository** - Help the community with your findings
5. **Learn and improve** - Document lessons learned

---

## Contributing

We welcome contributions to improve the Shai-Hulud detector. The community's help is crucial for keeping pace with this evolving threat.

### How to Contribute

#### Adding New Compromised Packages

1. **Fork and clone the repository**
   ```bash
   git clone https://github.com/yourusername/shai-hulud-detect.git
   cd shai-hulud-detect
   ```

2. **Update the package database**
   - Edit `compromised-packages.txt`
   - Add packages in format: `package_name:version`
   - Include source/reference as comment
   - Group by namespace for organization

   Example:
   ```
   # Source: https://example.com/security-advisory
   @example/package:1.2.3
   @example/package:1.2.4
   ```

3. **Test your changes**
   ```bash
   # Verify new packages are loaded
   ./shai-hulud-detector.sh test-cases/clean-project

   # Run full test suite
   ./shai-hulud-detector.sh test-cases/infected-project
   ./shai-hulud-detector.sh test-cases/mixed-project
   ```

4. **Submit a pull request**
   - Use descriptive title: "Add @example/package compromised versions"
   - Include source of information
   - Reference security advisories
   - Explain version patterns or attack details

#### Other Contributions

- **Bug Fixes**: Report and fix detection accuracy issues
- **New Indicators**: Add detection for additional IoCs
- **Documentation**: Improve clarity and add examples
- **Test Cases**: Add new test scenarios for edge cases
- **Performance**: Optimize scanning algorithms
- **Platform Support**: Improve cross-platform compatibility

### Contribution Guidelines

- **Verify Sources**: Only add packages confirmed by reputable security firms
- **Test Thoroughly**: Ensure changes don't break existing functionality
- **Document Changes**: Update CHANGELOG.md and relevant documentation
- **Follow Patterns**: Match existing code style and organization
- **Security First**: Never include actual malicious code in test cases
  - Use benign test files with controlled patterns
  - Document test file purposes clearly

### Reporting New Compromised Packages

If you can't submit a PR, you can still help:

1. Open an issue: "New compromised package: [package-name]"
2. Include:
   - Package name and version
   - Source of information (link to advisory)
   - Date discovered
   - Any additional context
3. We'll review and add verified packages

### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/shai-hulud-detect.git
cd shai-hulud-detect

# Create a feature branch
git checkout -b add-new-packages

# Make changes and test
./shai-hulud-detector.sh test-cases/

# Commit with descriptive message
git commit -m "feat: add @example compromised versions from XYZ advisory"

# Push and create PR
git push origin add-new-packages
```

---

## Latest Updates

### Version 2.3.0 (2025-09-24)
**Semver Matching & Improved Warnings**
- Merged PR #28: Semver pattern matching to detect packages vulnerable on `npm update`
- Merged PR #27: Parallelized hash scanning (~20% performance improvement)
- Changed namespace warnings from MEDIUM to LOW risk (reduced false positive fatigue)
- Enhanced test coverage with new semver matching scenarios
- Fixed macOS compatibility (removed `-readable` flag from find commands)

### Version 2.2.2 (2025-09-21)
**Progress Display & Cross-platform Support**
- Merged PR #19: Real-time file scanning progress with percentage completion
- Merged PR #26: Comprehensive test cases for all 7 hash variants
- Merged PR #25: Cross-platform file age detection (BSD vs GNU compatibility)
- Added pnpm-lock.yaml support with YAML-to-JSON transformation
- Enhanced error handling to prevent script hangs

### Version 2.2.1 (2025-09-19)
**Missing Socket.dev Packages Added**
- Added 34 additional compromised packages from Socket.dev analysis
- Enhanced coverage: @ctrl (9), @nativescript-community (8), @rxap (2), and 15 standalone packages
- Total coverage now 571+ confirmed compromised packages

### Version 2.2.0 (2025-09-19)
**Multi-Hash Detection**
- Added detection for all 7 Shai-Hulud worm variants (V1-V7)
- Enhanced malware detection covering September 14-16 attack campaign
- Complete worm evolution timeline based on Socket.dev research

### Version 2.1.0 (2025-09-19)
**Enhanced Error Handling & pnpm Support**
- Added robust error handling for grep pipelines (PR #13)
- Implemented pnpm-lock.yaml support
- Improved reliability across different shell environments

*For complete version history, see [CHANGELOG.md](CHANGELOG.md)*

---

## References

### Primary Security Advisories

- **[StepSecurity: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)**
  Original comprehensive analysis of the Shai-Hulud attack

- **[Semgrep Security Advisory: NPM packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)**
  Detailed technical analysis of credential harvesting mechanism

- **[JFrog: New compromised packages in largest npm attack in history](https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/)**
  Ongoing detection of new compromised packages

- **[Socket.dev: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)**
  Comprehensive hash analysis and worm variant timeline

- **[Aikido: NPM debug and chalk packages compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)**
  Analysis of chalk/debug crypto theft attack

- **[Aikido: S1ngularity-nx attackers strike again](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)**
  Follow-up analysis of advanced attack patterns

### Additional Resources

- **[Wiz Security: Shai-Hulud NPM Supply Chain Attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)**
  Attack analysis with comprehensive package appendix

- **[Ox Security: NPM 2.0 hack - 40+ npm packages hit](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/)**
  Supply chain attack impact analysis

- **[Phoenix Security: NPM tinycolor compromise](https://phoenix.security/npm-tinycolor-compromise/)**
  Detailed analysis of tinycolor attack vector

### Attack Timeline

- **September 8, 2025**: Chalk/Debug crypto theft attack (18+ packages, 2B+ weekly downloads)
- **September 14, 2025**: Shai-Hulud worm initial deployment (V1)
- **September 15, 2025**: Worm evolution and propagation (V2-V5)
- **September 16, 2025**: Final worm variants with stealth improvements (V6-V7)
- **September 17-24, 2025**: Discovery and analysis of full attack scope

### Key Attack Details

- **Total Packages**: 571+ confirmed compromised versions
- **Weekly Downloads**: 2+ billion affected
- **Attack Vector**: Self-replicating postinstall hooks + crypto wallet replacement
- **Malicious Endpoint**: `https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Exfiltration Method**: GitHub repositories named "Shai-Hulud"
- **Credential Tool**: Trufflehog for secret scanning
- **Propagation**: Stolen npm tokens for self-replication

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 @Cobenian

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## Acknowledgments

- **Security Researchers**: StepSecurity, Socket.dev, JFrog, Semgrep, Aikido, Wiz, Ox Security, Phoenix Security
- **Contributors**: All community members who have submitted packages and improvements
- **npm Security Team**: For their rapid response to these attacks
- **Open Source Community**: For maintaining vigilance against supply chain threats

---

## Support

- **Issues**: [GitHub Issues](https://github.com/Cobenian/shai-hulud-detect/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Cobenian/shai-hulud-detect/discussions)
- **Security**: For security concerns, email [security contact]

---

**Stay vigilant. Keep your dependencies secure.**

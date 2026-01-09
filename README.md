# Shai-Hulud NPM Supply Chain Attack Detector

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Shell](https://img.shields.io/badge/shell-Bash%205.0%2B-blue)](#requirements)
[![Status](https://img.shields.io/badge/status-Active-success)](../../)
[![Contributions](https://img.shields.io/badge/contributions-Welcome-orange)](CONTRIBUTING.md)
[![Last Commit](https://img.shields.io/github/last-commit/Cobenian/shai-hulud-detect)](https://github.com/Cobenian/shai-hulud-detect/commits/main)
[![Security Tool](https://img.shields.io/badge/type-Security%20Tool-red)](#overview)


<img src="shai_hulu_detector.jpg" alt="sshd" width="80%" />

A Bash tool that helps you spot known traces of the September 2025 and November 2025 npm supply-chain attacks—including the Shai-Hulud self-replicating worm, the chalk/debug crypto-theft incident, and the "Shai-Hulud: The Second Coming" fake Bun runtime attack. It cross-checks 979+ confirmed bad package versions across multiple campaigns and checks for the most relevant red flags in your project.

## Overview

Covers multiple npm supply chain attacks from September 2025 and November 2025:

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
- **Malicious workflow files**: `shai-hulud-workflow.yml` files in `.github/workflows/` (September 2025) and `formatter_*.yml` files using SHA1HULUD runners (November 2025)
- **Known malicious file hashes**: Files matching any of 7 SHA-256 hashes from different Shai-Hulud worm variants (V1-V7), sourced from [Socket.dev's comprehensive attack analysis](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- **November 2025 Bun attack files**: `setup_bun.js`/`bun_installer.js` (fake Bun runtime installer) and `bun_environment.js`/`environment_source.js` (10MB+ obfuscated credential harvesting payload)
- **Obfuscated exfiltration files**: `3nvir0nm3nt.json`, `cl0vd.json`, `c9nt3nts.json`, `pigS3cr3ts.json` (Golden Path variant - stolen credentials staged for exfiltration)
- **Compromised package versions**: Specific versions of 1,682+ packages from multiple attacks (September, November & December 2025)
- **Suspicious postinstall hooks**: Package.json files with postinstall scripts containing curl, wget, eval commands, or fake Bun installation (`"preinstall": "node setup_bun.js"`)
- **Trufflehog activity**: Files containing trufflehog references, credential scanning patterns, or November 2025 enhanced patterns (automated TruffleHog download and execution)
- **Shai-Hulud repositories**: Git repositories named "Shai-Hulud" (used for data exfiltration) or with "Sha1-Hulud: The Second Coming" or "Goldox-T3chs: Only Happy Girl" descriptions
- **Secrets exfiltration files**: `actionsSecrets.json` files with double Base64 encoded credentials (November 2025)
- **SHA1HULUD GitHub Actions runners**: GitHub Actions workflows using malicious runners for credential theft

### Medium Risk Indicators
- **Suspicious content patterns**: References to `webhook.site` and the malicious endpoint `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Suspicious git branches**: Branches named "shai-hulud"
- **Semver pattern matching**: Packages that could become compromised during `npm update` due to caret (^) or tilde (~) version patterns

### Low Risk Indicators
- **Namespace warnings**: Packages from namespaces known to be affected (@ctrl, @crowdstrike, @art-ws, @ngx, @nativescript-community) but at safe versions

### Package Detection Method

The script loads a list of the compromised packages from an external file (`compromised-packages.txt`) which contains:
- **1,682+ confirmed compromised package versions** with exact version numbers (571+ from September 2025 + 1,100+ from November/December 2025)
- **18+ affected namespaces** for broader detection of packages from compromised maintainer accounts

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
- **[HelixGuard](https://helixguard.ai/blog/malicious-sha1hulud-2025-11-24)** - Second Coming analysis

### How to Add Newly Discovered Packages

1. Check the security advisories above for new compromised packages
2. Add them to `compromised-packages.txt` in the format `package_name:version`
3. Test the script to ensure detection works
4. Consider contributing updates back to this repository

**Coverage Note**: Multiple September, November, and December 2025 attacks affected 1,682+ packages total. Our detection aims to provide **comprehensive coverage** across the Shai-Hulud worm (517+ packages), Chalk/Debug crypto theft (26+ packages), "Shai-Hulud: The Second Coming" fake Bun runtime attack (1,100+ packages), and the Golden Path variant. Combined with namespace-based detection and enhanced attack pattern recognition, this provides excellent protection against these sophisticated supply chain compromises.

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

The repository includes a comprehensive test suite with 32 test cases. Use the automated test runner to validate all cases:

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

1. **Package Database Loading**: Loads 1,682+ compromised packages from `compromised-packages.txt` into O(1) lookup maps
2. **Workflow Detection**: Searches for `shai-hulud-workflow.yml` files (September 2025) and `formatter_*.yml` files with SHA1HULUD runners (November 2025)
3. **Hash Verification**: Calculates SHA-256 hashes against 7 known malicious bundle.js variants (V1-V7)
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

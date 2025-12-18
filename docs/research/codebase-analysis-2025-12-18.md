# Shai-Hulud Detector - Comprehensive Codebase Analysis

**Date**: December 18, 2025
**Analyst**: Research Agent
**Repository**: https://github.com/Cobenian/shai-hulud-detect

---

## Executive Summary

The Shai-Hulud Detector is a specialized security tool designed to detect indicators of compromise from multiple sophisticated npm supply chain attacks that occurred in September 2025. The tool is implemented as a standalone Bash script that scans JavaScript/TypeScript projects for signs of two major attack campaigns: the Chalk/Debug crypto theft attack and the Shai-Hulud self-replicating worm.

**Key Statistics:**
- **Detection Coverage**: 571+ compromised package versions across 11 namespaces
- **Attack Timeframe**: September 2025 (multiple campaigns)
- **Detection Methods**: 11 distinct security checks
- **Language**: Bash script (100%)
- **Dependencies**: Standard Unix tools only (find, grep, shasum)
- **License**: MIT

---

## 1. Project Purpose

### What Problem Does It Solve?

In September 2025, the npm ecosystem experienced multiple severe supply chain attacks:

1. **Chalk/Debug Crypto Theft Attack (Sept 8, 2025)**
   - Affected 18+ packages with 2+ billion weekly downloads
   - Malware replaced cryptocurrency wallet addresses in browser environments
   - Duration: ~2 hours before detection
   - Attack vector: XMLHttpRequest hijacking

2. **Shai-Hulud Self-Replicating Worm (Sept 14-16, 2025)**
   - Affected 517+ packages across multiple namespaces
   - Credential harvesting using Trufflehog secret scanning
   - Self-propagating using stolen npm tokens
   - Data exfiltration via GitHub repositories

This detector provides a comprehensive scanning solution to identify if a codebase has been compromised by either attack campaign.

### Core Capabilities

- **Package Version Detection**: Identifies exact compromised package versions
- **Hash-Based Malware Detection**: Matches files against 7 known malicious SHA-256 hashes
- **Behavioral Analysis**: Detects suspicious patterns like postinstall hooks, credential scanning
- **Crypto Theft Pattern Recognition**: Identifies wallet address manipulation code
- **Git Repository Analysis**: Checks for malicious branches and repositories
- **Lockfile Integrity**: Analyzes package-lock.json, yarn.lock, and pnpm-lock.yaml
- **Risk Stratification**: Categorizes findings as HIGH/MEDIUM/LOW risk

---

## 2. Technology Stack

### Primary Language & Runtime

**Bash Script** (100% of implementation)
- Target: Bash 3.2+ (macOS and Linux compatible)
- Execution: Direct shell execution, no compilation needed
- Standard: POSIX-compatible with bash-specific features

### Core Dependencies

The tool uses only **standard Unix utilities** (no external package dependencies):

| Tool | Purpose | Availability |
|------|---------|--------------|
| `find` | File system traversal | Standard Unix |
| `grep` | Pattern matching and content search | Standard Unix |
| `shasum` | SHA-256 hash calculation | Standard Unix |
| `awk` | Text processing for package.json parsing | Standard Unix |
| `sed` | Text transformation for YAML parsing | Standard Unix |
| `xargs` | Parallel execution | Standard Unix |
| `date` | File age calculation | Standard Unix |

### System Requirements

- **Operating Systems**: macOS (darwin) or Unix-like systems (Linux, BSD)
- **Shell**: Bash (version 3.2+)
- **Permissions**: Read access to scan directory
- **Resources**: CPU cores for parallel processing (auto-detected)

### Platform Compatibility Features

- **Cross-platform date command**: Uses `date -r` instead of BSD-specific `stat -f`
- **Automatic CPU detection**: Uses `sysctl -n hw.ncpu` (macOS) or `nproc` (Linux)
- **Graceful degradation**: Falls back to serial processing if parallel tools unavailable

---

## 3. Project Structure

### Repository Layout

```
shai-hulud-detect/
├── shai-hulud-detector.sh       # Main detection script (66KB, 1523 lines)
├── compromised-packages.txt     # Database of 571+ compromised packages (20KB)
├── README.md                    # Comprehensive documentation (19KB)
├── CHANGELOG.md                 # Version history (14KB)
├── LICENSE                      # MIT license
├── shai_hulu_detector.jpg       # Project logo/banner (456KB)
└── test-cases/                  # 19 test scenario directories
    ├── clean-project/           # Should show no issues
    ├── infected-project/        # Should show high risk issues
    ├── mixed-project/           # Should show medium risk issues
    ├── chalk-debug-attack/      # Tests crypto theft detection
    ├── semver-matching/         # Tests version pattern detection
    ├── namespace-warning/       # Tests namespace detection
    ├── legitimate-crypto/       # Tests false positive handling
    ├── common-crypto-libs/      # Tests legitimate crypto libraries
    ├── typosquatting-project/   # Tests typosquatting detection
    ├── network-exfiltration-project/  # Tests network pattern detection
    ├── infected-lockfile/       # Tests lockfile analysis (npm)
    ├── infected-lockfile-pnpm/  # Tests lockfile analysis (pnpm)
    ├── multi-hash-detection/    # Tests all 7 hash variants
    ├── comprehensive-test/      # Tests multiple detection types
    ├── legitimate-security-project/  # Tests legitimate security tools
    ├── edge-case-project/       # Tests edge cases
    ├── false-positive-project/  # Tests false positive handling
    └── debug-js/                # Additional debug test case
```

### Key Files

#### `shai-hulud-detector.sh` (Primary Executable)
- **Size**: 66,749 bytes
- **Lines**: 1,523
- **Purpose**: Main detection logic and scanning engine
- **Entry point**: Direct execution via `./shai-hulud-detector.sh <directory>`

#### `compromised-packages.txt` (Threat Database)
- **Size**: 20,555 bytes
- **Format**: `package_name:version` (one per line)
- **Content**: 571+ confirmed compromised package versions
- **Maintenance**: Regularly updated as new compromised packages discovered
- **Comments**: Lines starting with `#` are ignored (used for organization)

#### Test Cases (19 Scenarios)
Each test case directory contains:
- `package.json` - Defines test scenario dependencies
- Additional files specific to test (e.g., malicious files, lockfiles)

---

## 4. Main Features & Functionality

### Core Detection Methods

The script implements **11 distinct security checks**:

#### 1. Malicious Workflow Detection
- **Check**: Searches for `shai-hulud-workflow.yml` files in `.github/workflows/`
- **Risk Level**: HIGH
- **Rationale**: Known malware deployment mechanism

#### 2. File Hash Verification
- **Check**: Calculates SHA-256 hashes of .js/.ts/.json files
- **Database**: 7 known malicious hashes (covering worm variants V1-V7)
- **Risk Level**: HIGH
- **Optimization**: Parallel processing using `xargs -P N` for ~20% speedup
- **Progress**: Real-time progress display with percentage completion

#### 3. Package Version Analysis
- **Check**: Parses package.json dependencies against compromised package database
- **Matching**: Exact version matching for HIGH risk
- **Semver Matching**: Pattern matching (^, ~) for MEDIUM risk
- **Database**: 571+ package:version entries loaded from external file
- **Risk Level**: HIGH (exact match) or MEDIUM (pattern match)

#### 4. Postinstall Hook Detection
- **Check**: Identifies suspicious postinstall scripts
- **Patterns**: `curl`, `wget`, `node -e`, `eval` in postinstall commands
- **Risk Level**: HIGH
- **Rationale**: Postinstall hooks can execute arbitrary code during installation

#### 5. Suspicious Content Scanning
- **Check**: Searches for known malicious URLs and endpoints
- **Patterns**:
  - `webhook.site` references
  - Known malicious webhook ID: `bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- **Risk Level**: MEDIUM
- **File Types**: .js, .ts, .json, .yml, .yaml

#### 6. Cryptocurrency Theft Pattern Detection
- **Check**: Identifies crypto wallet manipulation code
- **Patterns**:
  - Ethereum wallet addresses: `0x[a-fA-F0-9]{40}`
  - XMLHttpRequest prototype modification
  - Known malicious function names: `checkethereumw`, `runmask`, `newdlocal`, `_0x19ca67`
  - Known attacker wallets
  - Phishing domain: `npmjs.help`
  - JavaScript obfuscation patterns
  - Cryptocurrency regex patterns
- **Risk Level**: HIGH (known attacker wallets) or MEDIUM (suspicious patterns)

#### 7. Git Branch Analysis
- **Check**: Searches for branches named "shai-hulud"
- **Risk Level**: MEDIUM
- **Scope**: All .git directories in scan path

#### 8. Trufflehog Activity Detection (Context-Aware)
- **Check**: Identifies credential scanning tools and patterns
- **Context Analysis**: Evaluates file location and content
- **Patterns**:
  - Trufflehog binary presence (HIGH)
  - Credential patterns: `AWS_ACCESS_KEY`, `GITHUB_TOKEN`, `NPM_TOKEN`
  - Environment variable scanning: `process.env`, `os.environ`, `getenv`
- **False Positive Reduction**:
  - Documentation mentions ignored
  - Build output context considered
  - Framework patterns recognized (Vue, webpack, etc.)
- **Risk Level**: HIGH/MEDIUM/LOW based on context

#### 9. Shai-Hulud Repository Detection
- **Check**: Identifies repositories used for data exfiltration
- **Patterns**:
  - Repository name contains "shai-hulud" or "Shai-Hulud"
  - Migration pattern repositories (e.g., "*-migration")
  - Git remote URLs containing "shai-hulud"
  - Double base64-encoded `data.json` files
- **Risk Level**: HIGH

#### 10. Package Integrity Verification
- **Check**: Analyzes lockfiles for compromised packages and tampering
- **Supported Formats**:
  - npm: `package-lock.json`
  - yarn: `yarn.lock`
  - pnpm: `pnpm-lock.yaml` (with YAML-to-JSON transformation)
- **Checks**:
  - Compromised package versions in lockfiles
  - Recently modified lockfiles containing @ctrl packages
  - Suspicious integrity hash patterns
- **Risk Level**: MEDIUM

#### 11. Typosquatting Detection (Paranoid Mode Only)
- **Check**: Identifies potential package impersonation attacks
- **Techniques**:
  - Unicode/homoglyph character detection
  - Single character difference detection
  - Missing character detection
  - Extra character detection
  - Namespace confusion (e.g., @typescript vs @types)
  - Common character substitutions (rn→m, vv→w, cl→d)
- **Risk Level**: MEDIUM
- **Activation**: `--paranoid` flag

#### 12. Network Exfiltration Pattern Detection (Paranoid Mode Only)
- **Check**: Identifies suspicious network communication patterns
- **Patterns**:
  - Hardcoded IP addresses (excluding localhost)
  - Suspicious domains (pastebin.com, hastebin.com, ngrok.io, etc.)
  - Base64-encoded URLs (`atob()`, `base64.decode`)
  - DNS-over-HTTPS patterns
  - WebSocket connections to external endpoints
  - Suspicious HTTP headers (X-Exfiltrate, X-Data-Export)
  - Base64 encoding near network operations
- **Risk Level**: MEDIUM
- **Activation**: `--paranoid` flag

### Operating Modes

#### Core Mode (Default)
- Focuses on Shai-Hulud-specific indicators
- Minimal false positives
- Recommended for most users
- Fast execution

#### Paranoid Mode (`--paranoid`)
- Includes all core checks PLUS general security checks
- Adds typosquatting and network exfiltration detection
- Higher false positive rate
- Useful for comprehensive security auditing
- Longer execution time

### Performance Optimizations

1. **Parallel Hash Scanning**: Uses `xargs -P N` for concurrent SHA-256 calculations
2. **CPU Auto-detection**: Automatically determines optimal parallelism
3. **Progress Display**: Real-time feedback with percentage completion
4. **Efficient Pattern Matching**: Uses grep with appropriate context limits
5. **Adaptive Context**: Adjusts grep context based on match count

### Risk Stratification

| Risk Level | Meaning | Action Required |
|------------|---------|-----------------|
| **HIGH** | Definitive indicators of compromise | Immediate investigation and remediation |
| **MEDIUM** | Suspicious patterns requiring review | Manual investigation needed |
| **LOW** | Informational findings (likely false positives) | Review if concerned, likely legitimate |

---

## 5. Installation & Usage

### Installation

#### Clone Repository
```bash
git clone https://github.com/Cobenian/shai-hulud-detect.git
cd shai-hulud-detect
```

#### Make Executable
```bash
chmod +x shai-hulud-detector.sh
```

### Usage Examples

#### Basic Scan (Core Mode)
```bash
./shai-hulud-detector.sh /path/to/your/project
```

#### Paranoid Mode (Comprehensive Security Scan)
```bash
./shai-hulud-detector.sh --paranoid /path/to/your/project
```

#### Custom Parallelism
```bash
./shai-hulud-detector.sh --parallelism 8 /path/to/your/project
```

#### Test on Sample Projects
```bash
# Clean project (should show no issues)
./shai-hulud-detector.sh test-cases/clean-project

# Infected project (should show HIGH RISK issues)
./shai-hulud-detector.sh test-cases/infected-project

# Mixed project (should show MEDIUM RISK issues)
./shai-hulud-detector.sh test-cases/mixed-project
```

### Command-Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--paranoid` | Enable additional security checks (typosquatting, network patterns) | Disabled |
| `--parallelism N` | Set number of parallel threads for hash scanning | Auto-detected (CPU cores) |
| `--help` or `-h` | Display usage information | N/A |

### Output Interpretation

#### Clean System
```
✅ No indicators of Shai-Hulud compromise detected.
Your system appears clean from this specific attack.
```

#### Compromised System
Output shows:
- **🚨 HIGH RISK**: Definitive indicators requiring immediate action
- **⚠️ MEDIUM RISK**: Suspicious patterns needing manual review
- **ℹ️ LOW RISK**: Informational findings (likely false positives)
- **Summary**: Count of issues by risk level

#### Example Output Structure
```
============================================
      SHAI-HULUD DETECTION REPORT
============================================

🚨 HIGH RISK: Compromised package versions detected:
   - Package: @ctrl/tinycolor@4.1.1
     Found in: /path/to/package.json

⚠️  MEDIUM RISK: Suspicious content patterns:
   - Pattern: webhook.site reference
     Found in: /path/to/file.js

ℹ️  LOW RISK FINDINGS (informational only):
   - Namespace warning: Contains packages from compromised namespace: @ctrl

============================================
🔍 SUMMARY:
   High Risk Issues: 1
   Medium Risk Issues: 1
   Low Risk (informational): 1
   Total Critical Issues: 2
============================================
```

---

## 6. Dependencies

### Runtime Dependencies

**None** - The tool requires only standard Unix utilities included with macOS and Linux:

| Utility | Version | Purpose |
|---------|---------|---------|
| bash | 3.2+ | Script interpreter |
| find | Standard | File system traversal |
| grep | Standard | Pattern matching |
| shasum | Standard | SHA-256 hashing |
| awk | Standard | Text processing |
| sed | Standard | Text transformation |
| xargs | Standard | Parallel execution |
| date | Standard | File age calculation |

### Package Manager Support

The tool scans projects using any of these package managers:
- **npm**: Analyzes `package.json` and `package-lock.json`
- **yarn**: Analyzes `package.json` and `yarn.lock`
- **pnpm**: Analyzes `package.json` and `pnpm-lock.yaml` (with YAML-to-JSON transformation)

### No Installation Required

The detector is a self-contained script with **zero external dependencies**. This design choice ensures:
- **Portability**: Works on any Unix-like system
- **Security**: No supply chain risk from dependencies
- **Simplicity**: No installation or configuration needed
- **Auditability**: Single file to review

---

## 7. Entry Points

### Primary Entry Point

**File**: `shai-hulud-detector.sh`
**Type**: Bash script
**Execution**: `./shai-hulud-detector.sh [OPTIONS] <directory>`

### Main Function Flow

```bash
main() {
    1. Parse command-line arguments
    2. Load compromised packages database (571+ packages)
    3. Validate scan directory exists
    4. Execute core detection checks:
       - check_workflow_files()
       - check_file_hashes()
       - check_packages()
       - check_postinstall_hooks()
       - check_content()
       - check_crypto_theft_patterns()
       - check_trufflehog_activity()
       - check_git_branches()
       - check_shai_hulud_repos()
       - check_package_integrity()
    5. If --paranoid: Execute additional checks:
       - check_typosquatting()
       - check_network_exfiltration()
    6. generate_report()
}
```

### Key Functions

#### Package Database Management
```bash
load_compromised_packages()
# Loads 571+ package:version entries from compromised-packages.txt
# Falls back to embedded list if file not found
```

#### Detection Functions
```bash
check_workflow_files()        # Searches for malicious workflow files
check_file_hashes()           # SHA-256 hash verification (parallel)
check_packages()              # package.json analysis with semver matching
check_postinstall_hooks()     # Suspicious script detection
check_content()               # Malicious URL/pattern search
check_crypto_theft_patterns() # Crypto wallet manipulation detection
check_git_branches()          # Git branch analysis
check_trufflehog_activity()   # Credential scanning detection
check_shai_hulud_repos()      # Malicious repository detection
check_package_integrity()     # Lockfile analysis (npm/yarn/pnpm)
check_typosquatting()         # Typosquatting detection (paranoid)
check_network_exfiltration()  # Network pattern detection (paranoid)
```

#### Utility Functions
```bash
transform_pnpm_yaml()         # Converts pnpm-lock.yaml to JSON
semver_match()                # Semantic version pattern matching
get_file_context()            # Determines file context for risk assessment
is_legitimate_pattern()       # Identifies legitimate code patterns
show_file_preview()           # Displays file context for findings
print_status()                # Colored output formatting
```

#### Report Generation
```bash
generate_report()
# Consolidates findings and generates comprehensive report
# Includes risk stratification and actionable recommendations
```

### CLI Interface

```bash
Usage: shai-hulud-detector.sh [--paranoid] [--parallelism N] <directory_to_scan>

OPTIONS:
  --paranoid         Enable additional security checks (typosquatting, network patterns)
  --parallelism N    Set the number of threads for parallelized steps (default: auto)

EXAMPLES:
  ./shai-hulud-detector.sh /path/to/project
  ./shai-hulud-detector.sh --paranoid /path/to/project
  ./shai-hulud-detector.sh --parallelism 8 /path/to/project
```

---

## 8. Configuration

### Configuration Files

#### Primary Configuration: `compromised-packages.txt`

**Purpose**: External database of compromised package versions
**Format**: Plain text, one package per line
**Syntax**: `package_name:version`

Example:
```
# Chalk/Debug attack (Sept 8, 2025)
chalk:5.6.1
debug:4.4.2

# Shai-Hulud worm (Sept 14-16, 2025)
@ctrl/tinycolor:4.1.1
@ctrl/tinycolor:4.1.2
```

**Features**:
- Comments: Lines starting with `#` are ignored
- Sections: Organized by attack campaign and namespace
- Maintenance: Easily updated without modifying script
- Fallback: Script contains embedded list if file missing

#### No Environment Variables Required

The tool does **not** require any environment variables. All configuration is:
- Built into the script
- Loaded from `compromised-packages.txt`
- Specified via command-line arguments

### Hardcoded Configuration

#### Malicious Hash Database (Inside Script)
```bash
MALICIOUS_HASHLIST=(
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"  # V1
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"  # V2
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"  # V3
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"  # V4
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"  # V5
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"  # V6
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"  # V7
)
```

#### Compromised Namespaces (Inside Script)
```bash
COMPROMISED_NAMESPACES=(
    "@crowdstrike"
    "@art-ws"
    "@ngx"
    "@ctrl"
    "@nativescript-community"
    "@ahmedhfarag"
    "@operato"
    "@teselagen"
    "@things-factory"
    "@hestjs"
    "@nstudio"
)
```

#### Suspicious Domains (Paranoid Mode, Inside Script)
```bash
suspicious_domains=(
    "pastebin.com" "hastebin.com" "ix.io" "0x0.st" "transfer.sh"
    "file.io" "anonfiles.com" "mega.nz" "dropbox.com/s/"
    "discord.com/api/webhooks" "telegram.org" "t.me"
    "ngrok.io" "localtunnel.me" "serveo.net"
    "requestbin.com" "webhook.site" "beeceptor.com"
    "pipedream.com" "zapier.com/hooks"
)
```

### Customization Points

#### Updating Compromised Packages
1. Edit `compromised-packages.txt`
2. Add new packages in format: `package_name:version`
3. Run script (changes take effect immediately)

#### Adjusting Parallelism
```bash
# Auto-detect CPU cores (default)
./shai-hulud-detector.sh /path/to/project

# Manually specify parallelism
./shai-hulud-detector.sh --parallelism 8 /path/to/project
```

#### Modifying Detection Logic
All detection logic is in `shai-hulud-detector.sh`. Key sections:
- Lines 150-161: Workflow detection
- Lines 163-191: Hash verification
- Lines 349-395: Package analysis
- Lines 398-416: Postinstall hooks
- Lines 419-434: Content scanning
- Lines 437-479: Crypto theft patterns
- Lines 563-663: Trufflehog activity
- Lines 666-702: Repository detection
- Lines 705-761: Package integrity

### No Configuration File Needed

Unlike many security tools, this detector requires **no configuration file**:
- **Zero setup**: Just clone and run
- **Self-contained**: All settings embedded or CLI-specified
- **Maintainable**: Package database in separate text file
- **Portable**: Works identically across systems

---

## 9. Architecture & Design Patterns

### Architectural Style

**Monolithic Script Architecture**
- Single executable file containing all logic
- No module system or external libraries
- Sequential execution with parallel optimization
- State management via global arrays

### Design Patterns

#### 1. Database Pattern (External Configuration)
```bash
load_compromised_packages() {
    # Loads external package database
    # Falls back to embedded list if file missing
}
```
**Benefits**:
- Easy maintenance without script modification
- Community contributions via simple text file
- Version control friendly

#### 2. Strategy Pattern (Detection Modes)
```bash
# Core mode: Shai-Hulud-specific checks
# Paranoid mode: Core + general security checks

if [[ "$paranoid_mode" == "true" ]]; then
    check_typosquatting()
    check_network_exfiltration()
fi
```

#### 3. Factory Pattern (Risk Classification)
```bash
# Context-aware risk assessment
case "$context" in
    "documentation") continue ;;
    "node_modules") risk="MEDIUM" ;;
    "source_code") risk="HIGH" ;;
esac
```

#### 4. Observer Pattern (Progress Display)
```bash
# Real-time progress updates
echo -ne "\r\033[K$filesChecked / $filesCount checked ($percentage %)"
```

#### 5. Pipeline Pattern (Data Processing)
```bash
find | xargs | shasum | while read hash file; do
    # Process results
done
```

### Code Organization

#### Global State Management
```bash
# Arrays store findings by category
WORKFLOW_FILES=()
MALICIOUS_HASHES=()
COMPROMISED_FOUND=()
SUSPICIOUS_FOUND=()
CRYPTO_PATTERNS=()
# ... etc
```

#### Function Composition
```bash
main() {
    # High-level orchestration
    load_compromised_packages
    check_workflow_files
    check_file_hashes
    # ... etc
    generate_report
}
```

#### Error Handling
```bash
set -eo pipefail  # Exit on error, catch pipeline failures

# Graceful error handling with || true
local result=$(command 2>/dev/null) || true
```

### Performance Characteristics

#### Time Complexity
- **File hashing**: O(n) where n = number of JS/TS/JSON files
- **Package checking**: O(m*p) where m = packages in project, p = compromised packages
- **Content scanning**: O(n*k) where k = pattern count

#### Space Complexity
- **Memory**: O(n) for storing findings arrays
- **Disk**: No temporary files (except pnpm transformation)

#### Optimization Strategies
1. **Parallel hashing**: Distributes work across CPU cores
2. **Efficient grep**: Uses appropriate context limits
3. **Early exit**: Stops processing on critical errors
4. **Lazy evaluation**: Only runs paranoid checks if requested

### Semver Matching Algorithm

**Purpose**: Detect packages that could become compromised during `npm update`

**Implementation**:
```bash
semver_match() {
    local test_subject=$1  # Compromised version (e.g., "4.1.1")
    local test_pattern=$2  # Package.json pattern (e.g., "^4.0.0")

    # Handles caret (^) and tilde (~) ranges
    # Returns 0 (match) if compromised version matches pattern
}
```

**Example**:
- Package.json has: `"@ctrl/tinycolor": "^4.0.0"`
- Compromised version: `4.1.1`
- semver_match returns: TRUE (would update to compromised version)
- Risk level: MEDIUM (requires npm update to trigger)

### YAML Transformation (pnpm Support)

**Challenge**: pnpm uses YAML lockfiles, script needs JSON-like structure

**Solution**: Transform YAML to pseudo-JSON on-the-fly
```bash
transform_pnpm_yaml() {
    # Reads pnpm-lock.yaml
    # Outputs JSON-compatible structure
    # Enables unified lockfile processing
}
```

---

## 10. Testing Strategy

### Test Case Coverage

The repository includes **19 comprehensive test scenarios**:

| Test Case | Purpose | Expected Result |
|-----------|---------|-----------------|
| `clean-project` | Baseline test with no issues | ✅ No indicators detected |
| `infected-project` | Multiple HIGH RISK indicators | 🚨 Multiple HIGH RISK findings |
| `mixed-project` | Medium risk patterns | ⚠️ MEDIUM RISK findings |
| `chalk-debug-attack` | Crypto theft patterns | 🚨 HIGH RISK crypto patterns |
| `semver-matching` | Version pattern detection | ⚠️ MEDIUM RISK semver matches |
| `namespace-warning` | Namespace detection | ℹ️ LOW RISK namespace warnings |
| `legitimate-crypto` | False positive testing | ⚠️ MEDIUM RISK only (not HIGH) |
| `common-crypto-libs` | Legitimate crypto libraries | ✅ No HIGH RISK false positives |
| `typosquatting-project` | Typosquatting detection | ⚠️ MEDIUM RISK (paranoid mode) |
| `network-exfiltration-project` | Network pattern detection | ⚠️ MEDIUM RISK (paranoid mode) |
| `infected-lockfile` | npm lockfile analysis | 🚨 HIGH RISK in lockfile |
| `infected-lockfile-pnpm` | pnpm lockfile analysis | 🚨 HIGH RISK in lockfile |
| `multi-hash-detection` | All 7 hash variants | 🚨 HIGH RISK for all hashes |
| `comprehensive-test` | Multiple detection types | Multiple findings |
| `legitimate-security-project` | Security tools context | Context-aware risk levels |
| `edge-case-project` | Edge cases and boundaries | Appropriate handling |
| `false-positive-project` | False positive mitigation | Low/Medium risk only |
| `debug-js` | Debug package testing | Specific to debug scenarios |

### Running Tests

#### Manual Test Execution
```bash
# Run all test cases
for dir in test-cases/*/; do
    echo "Testing: $dir"
    ./shai-hulud-detector.sh "$dir"
done
```

#### Individual Test Cases
```bash
./shai-hulud-detector.sh test-cases/clean-project
./shai-hulud-detector.sh test-cases/infected-project
./shai-hulud-detector.sh --paranoid test-cases/typosquatting-project
```

### Test Case Structure

Each test case directory contains:
```
test-case-name/
├── package.json           # Defines test scenario
├── .github/               # (Optional) Workflow files
│   └── workflows/
│       └── shai-hulud-workflow.yml  # Malicious workflow
├── node_modules/          # (Optional) Mock dependencies
├── package-lock.json      # (Optional) Lockfile
└── src/                   # (Optional) Source files
    └── malicious.js       # Known malicious file
```

### Quality Assurance

#### Hash Verification Test (test-cases/multi-hash-detection)
- Contains files matching all 7 known malicious hashes
- Validates comprehensive worm variant detection
- Ensures no hash variant goes undetected

#### False Positive Testing (test-cases/legitimate-crypto)
- Contains legitimate cryptocurrency libraries (web3.js, ethers.js)
- Should NOT trigger HIGH RISK crypto theft alerts
- Validates context-aware detection logic

#### Cross-Platform Testing (PR #25)
- Tests file age detection on both macOS and Linux
- Validates `date -r` compatibility
- Ensures portable behavior

---

## 11. Security Considerations

### Threat Model

#### What It Detects
1. **Known Compromised Packages**: Exact version matches (HIGH confidence)
2. **At-Risk Package Versions**: Semver pattern matches (MEDIUM confidence)
3. **Malicious Code**: Hash-based detection of known malware files
4. **Suspicious Behavior**: Postinstall hooks, credential scanning
5. **Crypto Theft**: Wallet manipulation patterns
6. **Data Exfiltration**: Network exfiltration patterns

#### What It Does NOT Detect
1. **Zero-day attacks**: Unknown attack patterns
2. **New malware variants**: Hashes not in database
3. **Obfuscated code**: Advanced code obfuscation
4. **Memory-only attacks**: Runtime-only malware
5. **Supply chain attacks**: On packages not in database

### False Positive Management

#### Context-Aware Risk Assessment
The tool uses **file context analysis** to reduce false positives:

```bash
get_file_context() {
    # Classifies files as:
    # - node_modules (dependency code)
    # - documentation (markdown, txt)
    # - type_definitions (.d.ts files)
    # - build_output (dist/, build/)
    # - configuration (config files)
    # - source_code (application code)
}
```

#### Legitimate Pattern Recognition
```bash
is_legitimate_pattern() {
    # Recognizes legitimate patterns:
    # - Vue.js development patterns (process.env.NODE_ENV)
    # - Build tool patterns (webpack, vite, rollup)
    # - Framework patterns (createApp, Vue)
}
```

#### Risk Stratification
- **HIGH**: Definitive indicators (exact package match, known hashes)
- **MEDIUM**: Suspicious patterns requiring review
- **LOW**: Informational findings (namespace warnings)

### Security Best Practices

#### 1. Detection Only (No Remediation)
The tool **does not**:
- Modify files
- Remove packages
- Execute code
- Connect to network

**Rationale**: Separation of concerns, prevent accidental damage

#### 2. No External Dependencies
- Zero npm packages required
- No network calls
- No remote code execution
- Fully auditable single script

#### 3. Read-Only Operations
- Only reads files (no write operations)
- No destructive actions
- Safe to run in production

#### 4. Privacy Conscious
- No telemetry or reporting
- No data sent to external servers
- All processing local

#### 5. Supply Chain Security
- No dependencies = no supply chain risk
- Self-contained script
- Easily verifiable (single file)

### Limitations & Caveats

#### Known Limitations
1. **Static Analysis Only**: Cannot detect runtime behavior
2. **Hash Database**: Only detects known malicious files
3. **Package Database**: Requires updates for new compromised packages
4. **False Positives**: Legitimate tools may trigger alerts (Trufflehog, crypto libraries)
5. **Worm Evolution**: Self-replicating nature means new variants may emerge

#### Mitigation Strategies
1. **Regular Updates**: Keep compromised-packages.txt current
2. **Multiple Tools**: Use alongside npm audit, Snyk, Socket.dev
3. **Manual Review**: Investigate MEDIUM/HIGH findings carefully
4. **Security Monitoring**: Monitor security advisories for new packages

---

## 12. Maintenance & Updates

### Update Strategy

#### Compromised Package Database Updates

**Frequency**: As new compromised packages discovered
**Process**:
1. Monitor security advisories (StepSecurity, Socket.dev, Semgrep, JFrog, Wiz)
2. Add new packages to `compromised-packages.txt`
3. Format: `package_name:version`
4. Test detection with updated list
5. Commit changes

**Security Advisory Sources**:
- [StepSecurity Blog](https://www.stepsecurity.io/blog/)
- [Socket.dev Blog](https://socket.dev/blog/)
- [Semgrep Security](https://semgrep.dev/blog/)
- [JFrog Security](https://jfrog.com/blog/)
- [Wiz Security](https://www.wiz.io/blog/)

#### Hash Database Updates

**When**: New malware variants discovered
**How**: Add SHA-256 hashes to `MALICIOUS_HASHLIST` array in script

```bash
MALICIOUS_HASHLIST=(
    "existing_hash_1"
    "existing_hash_2"
    "new_hash_3"  # Add new hashes here
)
```

### Version History

Current version: **v2.3.0** (September 24, 2025)

**Recent Releases**:
- **v2.3.0**: Semver matching, parallel processing, LOW risk namespace warnings
- **v2.2.2**: Progress display, cross-platform support, pnpm support
- **v2.2.1**: Additional Socket.dev packages (34 packages)
- **v2.2.0**: Multi-hash detection (7 variants)
- **v2.1.0**: Enhanced error handling, pnpm support
- **v2.0.0**: Paranoid mode, typosquatting, network exfiltration

### Contributing

#### How to Contribute

**Adding Compromised Packages**:
1. Fork repository
2. Edit `compromised-packages.txt`
3. Add package in format: `package_name:version`
4. Include source/reference
5. Test detection
6. Submit pull request

**Bug Fixes**:
1. Report issue with details
2. Submit pull request with fix
3. Include test case if applicable

**New Detection Methods**:
1. Propose new IoC or pattern
2. Implement detection function
3. Add test case
4. Update documentation
5. Submit pull request

#### Community Engagement

**GitHub Repository**: https://github.com/Cobenian/shai-hulud-detect
- **Stars**: Active community interest
- **Pull Requests**: Recent PRs merged (#13, #19, #25, #26, #27, #28)
- **Issues**: Open for bug reports and feature requests

---

## 13. Related Tools & Ecosystem

### Complementary Security Tools

The Shai-Hulud detector works best alongside other security tools:

#### npm Official Tools
- **npm audit**: Built-in vulnerability scanning
- **npm outdated**: Identifies outdated packages

#### Third-Party Security Platforms
- **Socket.dev**: Real-time supply chain protection
- **Snyk**: Vulnerability database and monitoring
- **Semgrep**: Static analysis and security patterns
- **JFrog Xray**: Artifact security scanning

#### Specialized Detection Tools
- **Trufflehog**: Secret scanning (legitimate use)
- **git-secrets**: Prevent committing secrets
- **SecretScanner**: Container secret scanning

### Integration Recommendations

#### CI/CD Integration
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]
jobs:
  shai-hulud-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Shai-Hulud Detector
        run: |
          git clone https://github.com/Cobenian/shai-hulud-detect.git
          cd shai-hulud-detect
          ./shai-hulud-detector.sh ..
```

#### Pre-commit Hook
```bash
#!/bin/bash
# .git/hooks/pre-commit
./path/to/shai-hulud-detector.sh .
```

---

## 14. Future Enhancements

### Potential Improvements

#### Proposed Features
1. **JSON Output**: Machine-readable report format for CI/CD
2. **Configurable Risk Levels**: User-defined risk thresholds
3. **Incremental Scanning**: Only scan changed files
4. **Watch Mode**: Continuous monitoring
5. **Remediation Suggestions**: Automated fix recommendations
6. **Integration APIs**: Hooks for security platforms

#### Community Requests
- Docker image for containerized scanning
- Windows PowerShell port
- Web-based UI for reports
- Database of safe package versions
- Automatic package.json remediation

---

## 15. Conclusions & Recommendations

### Summary

The Shai-Hulud Detector is a **well-engineered, production-ready security tool** that addresses a critical need in the JavaScript ecosystem. Its strengths include:

**Strengths**:
1. **Zero Dependencies**: Self-contained, no supply chain risk
2. **Comprehensive Coverage**: 571+ packages, 11 detection methods
3. **Performance**: Parallel processing, efficient algorithms
4. **Usability**: Simple CLI, clear output, risk stratification
5. **Maintainability**: External package database, well-documented
6. **Testing**: 19 test scenarios, cross-platform compatibility
7. **Community**: Active development, recent contributions

**Limitations**:
1. **Static Analysis Only**: Cannot detect runtime attacks
2. **Known Threats Only**: Requires database updates for new attacks
3. **False Positives**: Paranoid mode may flag legitimate patterns
4. **Platform**: Bash-only (macOS/Linux)

### Use Cases

**Recommended For**:
- JavaScript/TypeScript project security audits
- CI/CD security scanning pipelines
- Post-incident forensic analysis
- Development team security awareness
- Open source project security validation

**Not Recommended As**:
- Real-time runtime protection
- Sole security tool (use with npm audit, Snyk, etc.)
- Windows-only environments

### Operational Recommendations

#### For Development Teams
1. **Regular Scans**: Run weekly or on dependency updates
2. **CI/CD Integration**: Add to automated pipelines
3. **Monitor Advisories**: Subscribe to security feeds
4. **Update Database**: Keep compromised-packages.txt current
5. **Investigate Findings**: Don't ignore MEDIUM/HIGH alerts

#### For Security Teams
1. **Incident Response**: Use for forensic analysis during incidents
2. **Baseline Scanning**: Establish clean baseline for projects
3. **Continuous Monitoring**: Integrate with security platforms
4. **Threat Intelligence**: Contribute findings back to repository

#### For Open Source Maintainers
1. **Badge**: Add scan status badge to README
2. **Pre-release Checks**: Scan before publishing
3. **Dependency Review**: Check dependencies regularly
4. **Community Contribution**: Share new compromised packages

### Final Assessment

**Verdict**: **Highly Recommended**

The Shai-Hulud Detector is a valuable addition to any JavaScript project's security toolkit. Its design prioritizes:
- **Simplicity**: Easy to understand and audit
- **Reliability**: No dependencies, stable execution
- **Effectiveness**: Comprehensive detection capabilities
- **Community**: Open source, actively maintained

While it should not be the only security tool in your arsenal, it provides excellent coverage for the specific September 2025 npm supply chain attacks and serves as a strong general-purpose malware detector for JavaScript projects.

---

## 16. Appendices

### Appendix A: Complete File Manifest

```
shai-hulud-detect/
├── shai-hulud-detector.sh (66KB, 1523 lines)
├── compromised-packages.txt (20KB, 696 lines)
├── README.md (19KB, 350 lines)
├── CHANGELOG.md (14KB, 200+ lines)
├── LICENSE (1KB, MIT)
├── shai_hulu_detector.jpg (456KB)
├── .gitignore
└── test-cases/ (19 directories)
```

### Appendix B: Compromised Package Statistics

**Total Packages**: 571+
- **Chalk/Debug Attack**: 26 packages
- **Shai-Hulud Worm**: 517+ packages
- **DuckDB Extension**: 5 packages

**Affected Namespaces**: 11
- @ctrl (9+ packages)
- @crowdstrike (25+ packages)
- @art-ws (16+ packages)
- @nativescript-community (40+ packages)
- @operato (80+ package versions)
- @teselagen (10+ packages)
- @things-factory (25+ package versions)
- @hestjs (8+ packages)
- @nstudio (15+ packages)
- @ahmedhfarag (2+ packages)
- @nexe (3+ packages)

### Appendix C: Known Malicious Hashes

Seven SHA-256 hashes representing Shai-Hulud worm variants V1-V7:
1. `de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6`
2. `81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3`
3. `83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e`
4. `4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db`
5. `dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c`
6. `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
7. `b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777`

### Appendix D: Security Advisory Links

**Primary Sources**:
- [StepSecurity: CTRL, tinycolor and 40 NPM packages compromised](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- [Socket.dev: Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- [Semgrep: NPM packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- [JFrog: New compromised packages in largest npm attack in history](https://jfrog.com/blog/new-compromised-packages-in-largest-npm-attack-in-history/)
- [Wiz: Shai-Hulud npm supply chain attack](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)

---

**End of Analysis**

Generated by: Research Agent
Date: December 18, 2025
Document Version: 1.0

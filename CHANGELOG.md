# Changelog

All notable changes to the Shai-Hulud NPM Supply Chain Attack Detector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

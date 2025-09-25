# Changelog

All notable changes to the Shai-Hulud NPM Supply Chain Attack Detector will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

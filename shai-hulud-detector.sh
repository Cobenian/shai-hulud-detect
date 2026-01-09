#!/usr/bin/env bash

# Shai-Hulud NPM Supply Chain Attack Detection Script
# Detects indicators of compromise from September 2025 and November 2025 npm attacks
# Includes detection for "Shai-Hulud: The Second Coming" (fake Bun runtime attack)
# Usage: ./shai-hulud-detector.sh <directory_to_scan>
#
# Requires: Bash 5.0+

# Require Bash 5.0+ for associative arrays, mapfile, and modern features
if [[ -z "${BASH_VERSINFO[0]}" ]] || [[ "${BASH_VERSINFO[0]}" -lt 5 ]]; then
    echo "ERROR: Shai-Hulud Detector requires Bash 5.0 or newer."
    echo "You appear to be running: ${BASH_VERSION:-unknown}."
    echo
    echo "macOS:   brew install bash && run with:  /opt/homebrew/bin/bash $0 ..."
    echo "Linux:   install a current bash via your package manager (bash 5.x is standard on modern distros)."
    exit 1
fi

set -eo pipefail

# Script directory for locating companion files (compromised-packages.txt)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Global temp directory for file-based storage
TEMP_DIR=""

# Global variables for risk tracking (used for exit codes)
high_risk=0
medium_risk=0

# Function: create_temp_dir
# Purpose: Create cross-platform temporary directory for findings storage
# Args: None
# Modifies: TEMP_DIR (global variable)
# Returns: 0 on success, exits on failure
create_temp_dir() {
    local temp_base="${TMPDIR:-${TMP:-${TEMP:-/tmp}}}"

    if command -v mktemp >/dev/null 2>&1; then
        # Try mktemp with our preferred pattern
        TEMP_DIR=$(mktemp -d -t shai-hulud-detect-XXXXXX 2>/dev/null || true) || \
        TEMP_DIR=$(mktemp -d 2>/dev/null || true) || \
        TEMP_DIR="$temp_base/shai-hulud-detect-$$-$(date +%s)"
    else
        # Fallback for systems without mktemp (rare with bash)
        TEMP_DIR="$temp_base/shai-hulud-detect-$$-$(date +%s)"
    fi

    mkdir -p "$TEMP_DIR" || {
        echo "Error: Cannot create temporary directory"
        exit 1
    }

    # Create findings files
    touch "$TEMP_DIR/workflow_files.txt"
    touch "$TEMP_DIR/malicious_hashes.txt"
    touch "$TEMP_DIR/compromised_found.txt"
    touch "$TEMP_DIR/suspicious_found.txt"
    touch "$TEMP_DIR/suspicious_content.txt"
    touch "$TEMP_DIR/crypto_patterns.txt"
    touch "$TEMP_DIR/git_branches.txt"
    touch "$TEMP_DIR/postinstall_hooks.txt"
    touch "$TEMP_DIR/trufflehog_activity.txt"
    touch "$TEMP_DIR/shai_hulud_repos.txt"
    touch "$TEMP_DIR/namespace_warnings.txt"
    touch "$TEMP_DIR/low_risk_findings.txt"
    touch "$TEMP_DIR/integrity_issues.txt"
    touch "$TEMP_DIR/typosquatting_warnings.txt"
    touch "$TEMP_DIR/network_exfiltration_warnings.txt"
    touch "$TEMP_DIR/lockfile_safe_versions.txt"
    touch "$TEMP_DIR/bun_setup_files.txt"
    touch "$TEMP_DIR/bun_environment_files.txt"
    touch "$TEMP_DIR/new_workflow_files.txt"
    touch "$TEMP_DIR/github_sha1hulud_runners.txt"
    touch "$TEMP_DIR/preinstall_bun_patterns.txt"
    touch "$TEMP_DIR/malicious_repo_descriptions.txt"
    touch "$TEMP_DIR/actions_secrets_files.txt"
    touch "$TEMP_DIR/obfuscated_exfil_files.txt"
    touch "$TEMP_DIR/discussion_workflows.txt"
    touch "$TEMP_DIR/github_runners.txt"
    touch "$TEMP_DIR/malicious_hashes.txt"
    touch "$TEMP_DIR/destructive_patterns.txt"
    touch "$TEMP_DIR/trufflehog_patterns.txt"
}

# Function: cleanup_temp_files
# Purpose: Clean up temporary directory on script exit, interrupt, or termination
# Args: None (uses $? for exit code)
# Modifies: Removes temp directory and all contents
# Returns: Exits with original script exit code
cleanup_temp_files() {
    local exit_code=$?
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
    exit $exit_code
}

# Set trap for cleanup on exit, interrupt, or termination
trap cleanup_temp_files EXIT INT TERM

# Color codes for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
ORANGE='\033[38;5;172m'  # Muted orange for stage headers (256-color mode)
NC='\033[0m' # No Color

# Detect available grep tools at startup
# Priority order: git-grep > ripgrep > grep
# git-grep is fastest (~40% faster than ripgrep) and uses DFA-based regex (no backtracking)

HAS_GIT_GREP=false
HAS_RIPGREP=false

# Check for git grep (requires git to be installed)
if command -v git >/dev/null 2>&1; then
    HAS_GIT_GREP=true
fi

# Check for ripgrep
if command -v rg >/dev/null 2>&1; then
    HAS_RIPGREP=true
fi

# Active grep tool selection (set by auto-detection or --use-* flags)
# Values: "git-grep", "ripgrep", "grep"
GREP_TOOL=""

# Semver range checking (opt-in via --check-semver-ranges flag)
CHECK_SEMVER_RANGES=false

# Function: select_grep_tool
# Purpose: Auto-select the best available grep tool (git-grep > ripgrep > grep)
# Called after argument parsing to allow --use-* flags to override
select_grep_tool() {
    # If user specified a tool via flag, use that (already set in GREP_TOOL)
    if [[ -n "$GREP_TOOL" ]]; then
        return
    fi

    # Auto-select: git-grep > ripgrep > grep
    if [[ "$HAS_GIT_GREP" == "true" ]]; then
        GREP_TOOL="git-grep"
    elif [[ "$HAS_RIPGREP" == "true" ]]; then
        GREP_TOOL="ripgrep"
    else
        GREP_TOOL="grep"
    fi
}

# Known malicious file hashed (source: https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
MALICIOUS_HASHLIST=(
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6"
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3"
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e"
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db"
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c"
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777"
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b" # test-cases/multi-hash-detection/file1.js
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee" # test-cases/multi-hash-detection/file2.js
)

PARALLELISM=4
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  PARALLELISM=$(nproc)
elif [[ "$OSTYPE" == "darwin"* ]]; then
  PARALLELISM=$(sysctl -n hw.ncpu)
fi

# Timing variables
SCAN_START_TIME=0

# Function: get_elapsed_time
# Purpose: Get elapsed time since scan start in seconds
# Returns: Time in format "X.XXXs"
get_elapsed_time() {
    local now=$(date +%s%N 2>/dev/null || echo "$(date +%s)000000000")
    local elapsed_ns=$((now - SCAN_START_TIME))
    local elapsed_s=$((elapsed_ns / 1000000000))
    local elapsed_ms=$(((elapsed_ns % 1000000000) / 1000000))
    printf "%d.%03ds" "$elapsed_s" "$elapsed_ms"
}

# Function: print_stage_complete
# Purpose: Print stage completion with elapsed time
# Args: $1 = stage name
print_stage_complete() {
    local stage_name=$1
    local elapsed=$(get_elapsed_time)
    print_status "$BLUE" "   $stage_name completed [$elapsed]"
}

# Associative arrays for O(1) lookups (Bash 5.0+ feature)
declare -A COMPROMISED_PACKAGES_MAP    # "package:version" -> 1
declare -A COMPROMISED_NAMESPACES_MAP  # "@namespace" -> 1
declare -A COMPROMISED_VERSIONS_BY_NAME # "package_name" -> "version1 version2 ..." (for semver range checking)

# Function: load_compromised_packages
# Purpose: Load compromised package database from external file or fallback list
# Args: None (reads from compromised-packages.txt in script directory)
# Modifies: COMPROMISED_PACKAGES_MAP, COMPROMISED_VERSIONS_BY_NAME (global associative arrays)
# Returns: Populates COMPROMISED_PACKAGES_MAP for O(1) lookups, COMPROMISED_VERSIONS_BY_NAME for semver range checking
load_compromised_packages() {
    local packages_file="$SCRIPT_DIR/compromised-packages.txt"
    local count=0

    if [[ -f "$packages_file" ]]; then
        # Use mapfile to read all valid lines at once, then populate associative array
        local -a raw_packages
        mapfile -t raw_packages < <(
            grep -v '^[[:space:]]*#' "$packages_file" | \
            grep -E '^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+' | \
            tr -d $'\r'
        )

        # Populate associative arrays for O(1) lookups
        for pkg in "${raw_packages[@]}"; do
            COMPROMISED_PACKAGES_MAP["$pkg"]=1
            # Also build reverse lookup by package name for semver range checking
            local pkg_name="${pkg%:*}"
            local pkg_version="${pkg#*:}"
            COMPROMISED_VERSIONS_BY_NAME["$pkg_name"]+="$pkg_version "
            ((count++)) || true  # Prevent errexit when count starts at 0
        done

        print_status "$BLUE" "📦 Loaded $count compromised packages from $packages_file (O(1) lookup enabled)"
    else
        # Fallback to embedded list if file not found
        print_status "$YELLOW" "⚠️  Warning: $packages_file not found, using embedded package list"
        local fallback_packages=(
            "@ctrl/tinycolor:4.1.0"
            "@ctrl/tinycolor:4.1.1"
            "@ctrl/tinycolor:4.1.2"
            "@ctrl/deluge:1.2.0"
            "angulartics2:14.1.2"
            "koa2-swagger-ui:5.11.1"
            "koa2-swagger-ui:5.11.2"
        )
        for pkg in "${fallback_packages[@]}"; do
            COMPROMISED_PACKAGES_MAP["$pkg"]=1
            # Also build reverse lookup for fallback packages
            local pkg_name="${pkg%:*}"
            local pkg_version="${pkg#*:}"
            COMPROMISED_VERSIONS_BY_NAME["$pkg_name"]+="$pkg_version "
        done
    fi
}

# Known compromised namespaces - packages in these namespaces may be compromised
# Stored in both array (for iteration) and associative array (for O(1) lookup)
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
    "@basic-ui-components-stc"
    "@nexe"
    "@thangved"
    "@tnf-dev"
    "@ui-ux-gang"
    "@yoobic"
)

# Populate namespace associative array for O(1) lookups
for ns in "${COMPROMISED_NAMESPACES[@]}"; do
    COMPROMISED_NAMESPACES_MAP["$ns"]=1
done

# Function: is_compromised_package
# Purpose: O(1) lookup to check if a package:version is compromised
# Args: $1 = package:version string
# Returns: 0 if compromised, 1 if not
is_compromised_package() {
    [[ -v COMPROMISED_PACKAGES_MAP["$1"] ]]
}

# Function: is_compromised_namespace
# Purpose: O(1) lookup to check if a namespace is compromised
# Args: $1 = @namespace string
# Returns: 0 if compromised, 1 if not
is_compromised_namespace() {
    [[ -v COMPROMISED_NAMESPACES_MAP["$1"] ]]
}

# Function: cleanup_and_exit
# Purpose: Clean up background processes and temp files when script is interrupted
# Args: None
# Modifies: Kills all background jobs, removes temp files
# Returns: Exits with code 130 (standard for Ctrl-C interruption)
cleanup_and_exit() {
    print_status "$YELLOW" "🛑 Scan interrupted by user. Cleaning up..."

    # Kill all background jobs (more portable approach)
    local job_pids
    job_pids=$(jobs -p 2>/dev/null || true)
    if [[ -n "$job_pids" ]]; then
        echo "$job_pids" | while read -r pid; do
            [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
        done

        # Wait a moment for jobs to terminate
        sleep 0.5

        # Force kill any remaining processes
        echo "$job_pids" | while read -r pid; do
            [[ -n "$pid" ]] && kill -9 "$pid" 2>/dev/null || true
        done
    fi

    # Clean up temp directory
    if [[ -n "$TEMP_DIR" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi

    print_status "$NC" "Cleanup complete. Exiting."
    exit 130
}

# Phase 2: Bash 3.x Compatible In-Memory Caching System
# Uses temp files in memory (tmpfs) for compatibility with older Bash versions

# Function: get_cached_file_hash
# Purpose: Get cached SHA256 hash using tmpfs for near-memory speed
# Args: $1 = file_path (absolute path to file)
# Modifies: Creates small cache files in TEMP_DIR for reuse
# Returns: Echoes SHA256 hash of file
get_cached_file_hash() {
    local file_path="$1"

    # Create cache key from file path, size, and modification time
    local file_size file_mtime cache_key hash_cache_file
    file_size=$(stat -f%z "$file_path" 2>/dev/null || stat -c%s "$file_path" 2>/dev/null || echo "0")
    file_mtime=$(stat -f%m "$file_path" 2>/dev/null || stat -c%Y "$file_path" 2>/dev/null || echo "0")
    cache_key=$(echo "${file_path}:${file_size}:${file_mtime}" | shasum 2>/dev/null | cut -d' ' -f1 || echo "${file_path//\//_}_${file_size}_${file_mtime}")
    hash_cache_file="$TEMP_DIR/hcache_$cache_key"

    # Check cache first - small file reads are very fast
    if [[ -f "$hash_cache_file" ]]; then
        cat "$hash_cache_file"
        return 0
    fi

    # Calculate hash and store in cache
    local file_hash=""
    if command -v sha256sum >/dev/null 2>&1; then
        file_hash=$(sha256sum "$file_path" 2>/dev/null | cut -d' ' -f1)
    elif command -v shasum >/dev/null 2>&1; then
        file_hash=$(shasum -a 256 "$file_path" 2>/dev/null | cut -d' ' -f1)
    fi

    # Store in cache for future lookups
    if [[ -n "$file_hash" ]]; then
        echo "$file_hash" > "$hash_cache_file"
        echo "$file_hash"
    fi
}

# Function: get_cached_package_dependencies
# Purpose: Get cached package dependencies using tmpfs storage
# Args: $1 = package_file (path to package.json)
# Modifies: Creates cache files in TEMP_DIR
# Returns: Echoes package dependencies in name:version format
get_cached_package_dependencies() {
    local package_file="$1"

    # Create cache key from file path, size, and modification time
    local file_size file_mtime cache_key deps_cache_file
    file_size=$(stat -f%z "$package_file" 2>/dev/null || stat -c%s "$package_file" 2>/dev/null || echo "0")
    file_mtime=$(stat -f%m "$package_file" 2>/dev/null || stat -c%Y "$package_file" 2>/dev/null || echo "0")
    cache_key=$(echo "${package_file}:${file_size}:${file_mtime}" | shasum 2>/dev/null | cut -d' ' -f1 || echo "${package_file//\//_}_${file_size}_${file_mtime}")
    deps_cache_file="$TEMP_DIR/dcache_$cache_key"

    # Check cache first
    if [[ -f "$deps_cache_file" ]]; then
        cat "$deps_cache_file"
        return 0
    fi

    # Extract dependencies and store in cache
    local deps_output
    deps_output=$(awk '/"dependencies":|"devDependencies":/{flag=1;next}/}/{flag=0}flag' "$package_file" 2>/dev/null || true)

    if [[ -n "$deps_output" ]]; then
        echo "$deps_output" > "$deps_cache_file"
        echo "$deps_output"
    fi
}

# File-based storage for findings (replaces global arrays for memory efficiency)
# Files created in create_temp_dir() function:
# - workflow_files.txt, malicious_hashes.txt, compromised_found.txt
# - suspicious_found.txt, suspicious_content.txt, crypto_patterns.txt
# - git_branches.txt, postinstall_hooks.txt, trufflehog_activity.txt
# - shai_hulud_repos.txt, namespace_warnings.txt, low_risk_findings.txt
# - integrity_issues.txt, typosquatting_warnings.txt, network_exfiltration_warnings.txt
# - lockfile_safe_versions.txt, bun_setup_files.txt, bun_environment_files.txt
# - new_workflow_files.txt, github_sha1hulud_runners.txt, preinstall_bun_patterns.txt
# - second_coming_repos.txt, actions_secrets_files.txt, trufflehog_patterns.txt

# Function: usage
# Purpose: Display help message and exit
# Args: None
# Modifies: None
# Returns: Exits with code 1
usage() {
    echo "Usage: $0 [OPTIONS] <directory_to_scan>"
    echo
    echo "OPTIONS:"
    echo "  --paranoid         Enable additional security checks (typosquatting, network patterns)"
    echo "                     These are general security features, not specific to Shai-Hulud"
    echo "  --check-semver-ranges"
    echo "                     Check if package.json semver ranges (^, ~) could resolve to"
    echo "                     compromised versions. Reports LOW risk (informational) since"
    echo "                     packages are largely unpublished from npm."
    echo "  --parallelism N    Set the number of threads to use for parallelized steps (current: ${PARALLELISM})"
    echo "  --save-log FILE    Save all detected file paths to FILE, grouped by severity"
    echo "                     Output format: # HIGH / # MEDIUM / # LOW headers with file paths"
    echo ""
    echo "GREP TOOL SELECTION (auto-selects fastest available by default: git-grep > ripgrep > grep):"
    echo "  --use-git-grep     Force use of git grep (fastest, DFA-based, no backtracking)"
    echo "  --use-ripgrep      Force use of ripgrep (rg)"
    echo "  --use-grep         Force use of standard grep (may hang on complex patterns)"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 /path/to/your/project                    # Core Shai-Hulud detection only"
    echo "  $0 --paranoid /path/to/your/project         # Core + advanced security checks"
    echo "  $0 --save-log report.log /path/to/project   # Save findings to file"
    echo "  $0 --use-ripgrep /path/to/your/project      # Force ripgrep for testing"
    exit 1
}

# Function: print_status
# Purpose: Print colored status messages to console
# Args: $1 = color code (RED, YELLOW, GREEN, BLUE, NC), $2 = message text
# Modifies: None (outputs to stdout)
# Returns: Prints colored message
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# =============================================================================
# Fast Pattern Matching Helpers (git-grep > ripgrep > grep)
# =============================================================================
# These helper functions provide a clean abstraction over grep tools.
# GREP_TOOL is set by select_grep_tool() based on auto-detection or --use-* flags.

# Function: fast_grep_files
# Purpose: Find files matching a pattern (case-sensitive)
# Args: $1 = pattern (stdin = list of files to search)
# Output: Matching filenames to stdout
# Note: Uses null-delimited input to handle filenames with spaces (issue #92)
fast_grep_files() {
    local pattern="$1"
    case "$GREP_TOOL" in
        git-grep)
            # git grep uses DFA-based regex (no backtracking) - safe for complex patterns
            # --no-index allows searching files not managed by git
            tr '\n' '\0' | xargs -0 git grep -l --no-index -E "$pattern" -- 2>/dev/null || true
            ;;
        ripgrep)
            tr '\n' '\0' | xargs -0 rg -l --no-messages -e "$pattern" 2>/dev/null || true
            ;;
        grep)
            tr '\n' '\0' | xargs -0 grep -lE "$pattern" 2>/dev/null || true
            ;;
    esac
}

# Function: fast_grep_files_i
# Purpose: Find files matching a pattern (case-insensitive)
# Args: $1 = pattern (stdin = list of files to search)
# Output: Matching filenames to stdout
# Note: Uses null-delimited input to handle filenames with spaces (issue #92)
fast_grep_files_i() {
    local pattern="$1"
    case "$GREP_TOOL" in
        git-grep)
            tr '\n' '\0' | xargs -0 git grep -li --no-index -E "$pattern" -- 2>/dev/null || true
            ;;
        ripgrep)
            tr '\n' '\0' | xargs -0 rg -li --no-messages -e "$pattern" 2>/dev/null || true
            ;;
        grep)
            tr '\n' '\0' | xargs -0 grep -liE "$pattern" 2>/dev/null || true
            ;;
    esac
}

# Function: fast_grep_files_fixed
# Purpose: Find files matching a fixed string (faster, no regex)
# Args: $1 = literal string (stdin = list of files to search)
# Output: Matching filenames to stdout
# Note: Uses null-delimited input to handle filenames with spaces (issue #92)
fast_grep_files_fixed() {
    local pattern="$1"
    case "$GREP_TOOL" in
        git-grep)
            tr '\n' '\0' | xargs -0 git grep -l --no-index -F "$pattern" -- 2>/dev/null || true
            ;;
        ripgrep)
            tr '\n' '\0' | xargs -0 rg -l --no-messages --fixed-strings "$pattern" 2>/dev/null || true
            ;;
        grep)
            tr '\n' '\0' | xargs -0 grep -lF "$pattern" 2>/dev/null || true
            ;;
    esac
}

# Function: fast_grep_quiet
# Purpose: Check if pattern exists in a single file (for conditionals)
# Args: $1 = pattern, $2 = file
# Returns: 0 if found, non-zero if not
fast_grep_quiet() {
    local pattern="$1"
    local file="$2"
    case "$GREP_TOOL" in
        git-grep)
            git grep -q --no-index -E "$pattern" -- "$file" 2>/dev/null
            ;;
        ripgrep)
            rg -q "$pattern" "$file" 2>/dev/null
            ;;
        grep)
            grep -qE "$pattern" "$file" 2>/dev/null
            ;;
    esac
}

# Function: show_file_preview
# Purpose: Display file context for HIGH RISK findings only
# Args: $1 = file_path, $2 = context description
# Modifies: None (outputs to stdout)
# Returns: Prints formatted file preview box for HIGH RISK items only
show_file_preview() {
    local file_path=$1
    local context="$2"

    # Only show file preview for HIGH RISK items to reduce noise
    if [[ "$context" == *"HIGH RISK"* ]]; then
        echo -e "   ${BLUE}┌─ File: $file_path${NC}"
        echo -e "   ${BLUE}│  Context: $context${NC}"
        echo -e "   ${BLUE}└─${NC}"
        echo
    fi
}

# Function: show_progress
# Purpose: Display real-time progress indicator for file scanning operations
# Args: $1 = current files processed, $2 = total files to process
# Modifies: None (outputs to stderr with ANSI escape codes)
# Returns: Prints "X / Y checked (Z %)" with line clearing
show_progress() {
    local current=$1
    local total=$2
    local percent=0
    [[ $total -gt 0 ]] && percent=$((current * 100 / total))
    echo -ne "\r\033[K$current / $total checked ($percent %)"
}

# Function: count_files
# Purpose: Count files matching find criteria, returns clean integer
# Args: All arguments passed to find command (e.g., path, -name, -type)
# Modifies: None
# Returns: Integer count of matching files (strips whitespace)
count_files() {
    (find "$@" 2>/dev/null || true) | wc -l | tr -d ' '
}

# Function: collect_all_files
# Purpose: Single comprehensive file collection to replace 20+ separate find operations
# Args: $1 = scan_dir (directory to scan)
# Modifies: Creates categorized temp files for all functions to use
# Returns: Populates temp files with file paths by category
collect_all_files() {
    local scan_dir="$1"

    # Ensure temp directory exists
    [[ -d "$TEMP_DIR" ]] || mkdir -p "$TEMP_DIR"

    # Single comprehensive find operation for all file types needed (silent)
    {
        find "$scan_dir" \( \
            -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.mjs" -o \
            -name "*.yml" -o -name "*.yaml" -o \
            -name "*.py" -o -name "*.sh" -o -name "*.bat" -o -name "*.ps1" -o -name "*.cmd" -o \
            -name "package.json" -o \
            -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" -o \
            -name "shai-hulud-workflow.yml" -o \
            -name "setup_bun.js" -o -name "bun_environment.js" -o \
            -name "bun_installer.js" -o -name "environment_source.js" -o \
            -name "actionsSecrets.json" -o \
            -name "3nvir0nm3nt.json" -o -name "cl0vd.json" -o \
            -name "c9nt3nts.json" -o -name "pigS3cr3ts.json" -o \
            -name "*trufflehog*" -o \
            -name "formatter_*.yml" \
        \) -type f 2>/dev/null || true
    } > "$TEMP_DIR/all_files_raw.txt"

    # Also collect directories in a separate operation (silent)
    {
        find "$scan_dir" -name ".git" -type d 2>/dev/null || true | sed 's|/.git$||'
    } > "$TEMP_DIR/git_repos.txt"

    {
        find "$scan_dir" -type d \( -name ".dev-env" -o -name "*shai*hulud*" \) 2>/dev/null || true
    } > "$TEMP_DIR/suspicious_dirs.txt"

    # Categorize files for specific functions using grep (much faster than separate finds)
    grep "package\.json$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/package_files.txt" 2>/dev/null || touch "$TEMP_DIR/package_files.txt"
    grep "\.\(js\|ts\|json\|mjs\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/code_files.txt" 2>/dev/null || touch "$TEMP_DIR/code_files.txt"
    grep "\.\(yml\|yaml\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/yaml_files.txt" 2>/dev/null || touch "$TEMP_DIR/yaml_files.txt"
    grep "\.\(py\|sh\|bat\|ps1\|cmd\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/script_files.txt" 2>/dev/null || touch "$TEMP_DIR/script_files.txt"
    grep "\(package-lock\.json\|yarn\.lock\|pnpm-lock\.yaml\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/lockfiles.txt" 2>/dev/null || touch "$TEMP_DIR/lockfiles.txt"
    grep "shai-hulud-workflow\.yml$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/workflow_files_found.txt" 2>/dev/null || touch "$TEMP_DIR/workflow_files_found.txt"
    grep "\(setup_bun\.js\|bun_installer\.js\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/setup_bun_files.txt" 2>/dev/null || touch "$TEMP_DIR/setup_bun_files.txt"
    grep "\(bun_environment\.js\|environment_source\.js\)$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/bun_environment_files.txt" 2>/dev/null || touch "$TEMP_DIR/bun_environment_files.txt"
    grep "actionsSecrets\.json$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/actions_secrets_found.txt" 2>/dev/null || touch "$TEMP_DIR/actions_secrets_found.txt"
    grep -E "(3nvir0nm3nt|cl0vd|c9nt3nts|pigS3cr3ts)\.json$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/obfuscated_exfil_found.txt" 2>/dev/null || touch "$TEMP_DIR/obfuscated_exfil_found.txt"
    grep "trufflehog" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/trufflehog_files.txt" 2>/dev/null || touch "$TEMP_DIR/trufflehog_files.txt"
    grep "formatter_.*\.yml$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/formatter_workflows.txt" 2>/dev/null || touch "$TEMP_DIR/formatter_workflows.txt"

    # Filter GitHub workflow files specifically
    grep "/.github/workflows/.*\.ya\?ml$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/github_workflows.txt" 2>/dev/null || touch "$TEMP_DIR/github_workflows.txt"
}

# Function: check_workflow_files
# Purpose: Detect malicious shai-hulud-workflow.yml files in project directories
# Args: $1 = scan_dir (directory to scan)
# Modifies: WORKFLOW_FILES (global array)
# Returns: Populates WORKFLOW_FILES array with paths to suspicious workflow files
check_workflow_files() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for malicious workflow files..."

    # Use pre-categorized files from collect_all_files (performance optimization)
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/workflow_files.txt"
        fi
    done < "$TEMP_DIR/workflow_files_found.txt"
}

# Function: check_bun_attack_files
# Purpose: Detect November 2025 "Shai-Hulud: The Second Coming" Bun attack files
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/bun_setup_files.txt, bun_environment_files.txt, malicious_hashes.txt
# Returns: Populates temp files with paths to suspicious Bun-related malicious files
check_bun_attack_files() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for November 2025 Bun attack files..."

    # Known malicious file hashes from Koi.ai incident report
    local setup_bun_hashes=(
        "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a"
    )

    local bun_environment_hashes=(
        "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0"
        "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068"
        "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd"
    )

    # Look for setup_bun.js files (fake Bun runtime installation)
    # Use pre-categorized files from collect_all_files (performance optimization)
    if [[ -s "$TEMP_DIR/setup_bun_files.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                echo "$file" >> "$TEMP_DIR/bun_setup_files.txt"

                # Phase 2: Use in-memory cached hash calculation for performance
                local file_hash=$(get_cached_file_hash "$file")

                if [[ -n "$file_hash" ]]; then
                    for known_hash in "${setup_bun_hashes[@]}"; do
                        if [[ "$file_hash" == "$known_hash" ]]; then
                            echo "$file:SHA256=$file_hash (CONFIRMED MALICIOUS - Koi.ai IOC)" >> "$TEMP_DIR/malicious_hashes.txt"
                            break
                        fi
                    done
                fi
            fi
        done < "$TEMP_DIR/setup_bun_files.txt"
    fi

    # Look for bun_environment.js files (10MB+ obfuscated payload)
    # Use pre-categorized files from collect_all_files (performance optimization)
    if [[ -s "$TEMP_DIR/bun_environment_files.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                echo "$file" >> "$TEMP_DIR/bun_environment_files_found.txt"

                # Phase 2: Use in-memory cached hash calculation for performance
                local file_hash=$(get_cached_file_hash "$file")

                if [[ -n "$file_hash" ]]; then
                    for known_hash in "${bun_environment_hashes[@]}"; do
                        if [[ "$file_hash" == "$known_hash" ]]; then
                            echo "$file:SHA256=$file_hash (CONFIRMED MALICIOUS - Koi.ai IOC)" >> "$TEMP_DIR/malicious_hashes.txt"
                            break
                        fi
                    done
                fi
            fi
        done < "$TEMP_DIR/bun_environment_files.txt"
    fi
}

# Function: check_new_workflow_patterns
# Purpose: Detect November 2025 new workflow file patterns and actionsSecrets.json
# Args: $1 = scan_dir (directory to scan)
# Modifies: NEW_WORKFLOW_FILES, ACTIONS_SECRETS_FILES (global arrays)
# Returns: Populates arrays with paths to new attack pattern files
check_new_workflow_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for new workflow patterns..."

    # Look for formatter_123456789.yml workflow files
    # Use pre-categorized files from collect_all_files (performance optimization)
    if [[ -s "$TEMP_DIR/formatter_workflows.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]] && [[ "$file" == */.github/workflows/* ]]; then
                echo "$file" >> "$TEMP_DIR/new_workflow_files.txt"
            fi
        done < "$TEMP_DIR/formatter_workflows.txt"
    fi

    # Look for actionsSecrets.json files (double Base64 encoded secrets)
    # Use pre-categorized files from collect_all_files (performance optimization)
    if [[ -s "$TEMP_DIR/actions_secrets_found.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                echo "$file" >> "$TEMP_DIR/actions_secrets_files.txt"
            fi
        done < "$TEMP_DIR/actions_secrets_found.txt"
    fi

    # Look for obfuscated exfiltration JSON files (Golden Path variant)
    # Files: 3nvir0nm3nt.json, cl0vd.json, c9nt3nts.json, pigS3cr3ts.json
    if [[ -s "$TEMP_DIR/obfuscated_exfil_found.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                echo "$file" >> "$TEMP_DIR/obfuscated_exfil_files.txt"
            fi
        done < "$TEMP_DIR/obfuscated_exfil_found.txt"
    fi
}

# Function: check_discussion_workflows
# Purpose: Detect malicious GitHub Actions workflows with discussion triggers
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/discussion_workflows.txt (temp file)
# Returns: Populates discussion_workflows.txt with paths to suspicious discussion-triggered workflows
check_discussion_workflows() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for malicious discussion workflows..."

    # Phase 3 Optimization: Batch processing with combined patterns
    # Create a temporary file list for valid workflow files to process in batches
    while IFS= read -r file; do
        [[ -f "$file" ]] && echo "$file"
    done < "$TEMP_DIR/github_workflows.txt" > "$TEMP_DIR/valid_workflows.txt"

    # Check if we have any files to process
    if [[ ! -s "$TEMP_DIR/valid_workflows.txt" ]]; then
        return 0
    fi

    # Batch 1: Discussion trigger patterns (combined for efficiency)
    # Use null-delimited input to handle filenames with spaces (issue #92)
    tr '\n' '\0' < "$TEMP_DIR/valid_workflows.txt" | \
        xargs -0 -I {} grep -l -E "on:.*discussion|on:\s*discussion" {} 2>/dev/null | \
        while IFS= read -r file; do
            echo "$file:Discussion trigger detected" >> "$TEMP_DIR/discussion_workflows.txt"
        done || true

    # Batch 2: Self-hosted runners with dynamic payloads (two-stage batch processing)
    # Use null-delimited input to handle filenames with spaces (issue #92)
    tr '\n' '\0' < "$TEMP_DIR/valid_workflows.txt" | \
        xargs -0 -I {} grep -l "runs-on:.*self-hosted" {} 2>/dev/null | \
        tr '\n' '\0' | xargs -0 -I {} grep -l "\${{ github\.event\..*\.body }}" {} 2>/dev/null | \
        while IFS= read -r file; do
            echo "$file:Self-hosted runner with dynamic payload execution" >> "$TEMP_DIR/discussion_workflows.txt"
        done || true

    # Batch 3: Suspicious filenames (filename-based detection)
    while IFS= read -r file; do
        if [[ "$(basename "$file")" == "discussion.yaml" ]] || [[ "$(basename "$file")" == "discussion.yml" ]]; then
            echo "$file:Suspicious discussion workflow filename" >> "$TEMP_DIR/discussion_workflows.txt"
        fi
    done < "$TEMP_DIR/valid_workflows.txt"
}

# Function: check_github_runners
# Purpose: Detect self-hosted GitHub Actions runners installed by malware
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/github_runners.txt (temp file)
# Returns: Populates github_runners.txt with paths to suspicious runner installations
check_github_runners() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for malicious GitHub Actions runners..."

    # Performance Optimization: Single find operation with combined patterns
    {
        # Use pre-collected suspicious directories if available
        if [[ -f "$TEMP_DIR/suspicious_dirs.txt" ]]; then
            cat "$TEMP_DIR/suspicious_dirs.txt"
        fi

        # Single find operation combining all patterns with timeout protection
        timeout 10 find "$scan_dir" -type d \( \
            -name ".dev-env" -o \
            -name "actions-runner" -o \
            -name ".runner" -o \
            -name "_work" \
        \) 2>/dev/null || true
    } | sort | uniq | while IFS= read -r dir; do
        if [[ -d "$dir" ]]; then
            # Check for runner configuration files
            if [[ -f "$dir/.runner" ]] || [[ -f "$dir/.credentials" ]] || [[ -f "$dir/config.sh" ]]; then
                echo "$dir:Runner configuration files found" >> "$TEMP_DIR/github_runners.txt"
            fi

            # Check for runner binaries
            if [[ -f "$dir/Runner.Worker" ]] || [[ -f "$dir/run.sh" ]] || [[ -f "$dir/run.cmd" ]]; then
                echo "$dir:Runner executable files found" >> "$TEMP_DIR/github_runners.txt"
            fi

            # Check for .dev-env specifically (from Koi.ai report)
            if [[ "$(basename "$dir")" == ".dev-env" ]]; then
                echo "$dir:Suspicious .dev-env directory (matches Koi.ai report)" >> "$TEMP_DIR/github_runners.txt"
            fi
        fi
    done

    # Also check user home directory specifically for ~/.dev-env
    if [[ -d "${HOME}/.dev-env" ]]; then
        echo "${HOME}/.dev-env:Malicious runner directory in home folder (Koi.ai IOC)" >> "$TEMP_DIR/github_runners.txt"
    fi
}

# Function: check_destructive_patterns
# Purpose: Detect destructive patterns that can cause data loss when credential theft fails
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/destructive_patterns.txt (temp file)
# Returns: Populates destructive_patterns.txt with paths to files containing destructive patterns
check_destructive_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for destructive payload patterns..."

    # Phase 3 Optimization: Pre-compile combined regex patterns for batch processing
    # Basic destructive patterns - ONLY flag when targeting user directories ($HOME, ~, /home/)
    # Standalone rimraf/unlinkSync/rmSync removed to reduce false positives (GitHub issue #74)
    # Standalone glob patterns ($HOME/*, ~/*) removed - they match comments/docs (GitHub issue #105)
    local basic_destructive_regex="rm -rf[[:space:]]+(\\\$HOME|~[^a-zA-Z0-9_/]|/home/)|del /s /q[[:space:]]+(%USERPROFILE%|\\\$HOME)|Remove-Item -Recurse[[:space:]]+(\\\$HOME|~[^a-zA-Z0-9_/])|find[[:space:]]+(\\\$HOME|~[^a-zA-Z0-9_/]|/home/).*-exec rm|find[[:space:]]+(\\\$HOME|~[^a-zA-Z0-9_/]|/home/).*-delete"

    # Shai-Hulud 2.0 wiper patterns - SPECIFIC signatures from actual malware (Koi Security disclosure)
    # These tight patterns eliminate false positives on TypeScript/minified JS (GitHub issue #105)
    # while still catching the real wiper code that uses Bun.spawnSync, shred, cipher, etc.
    local shai_hulud_wiper_regex="Bun\.spawnSync.{1,50}(cmd\.exe|bash).{1,100}(del /F|shred|cipher /W)|shred.{1,30}-[nuvz].{1,50}(\\\$HOME|~/)|cipher[[:space:]]*/W:.{0,30}USERPROFILE|del[[:space:]]*/F[[:space:]]*/Q[[:space:]]*/S.{1,30}USERPROFILE|find.{1,30}\\\$HOME.{1,50}shred|rd[[:space:]]*/S[[:space:]]*/Q.{1,30}USERPROFILE"

    # Shell-specific patterns (broader patterns for actual shell scripts)
    local shell_conditional_regex="if.*credential.*(fail|error).*rm|if.*token.*not.*found.*(delete|rm)|if.*github.*auth.*fail.*rm|catch.*rm -rf|error.*delete.*home"

    # Phase 3 Optimization: Create file category lists for batch processing
    cat "$TEMP_DIR/script_files.txt" "$TEMP_DIR/code_files.txt" 2>/dev/null | sort | uniq > "$TEMP_DIR/all_script_files.txt" || touch "$TEMP_DIR/all_script_files.txt"

    # Separate files by type for optimized batch processing
    grep -E '\.(js|py)$' "$TEMP_DIR/all_script_files.txt" > "$TEMP_DIR/js_py_files.txt" 2>/dev/null || touch "$TEMP_DIR/js_py_files.txt"
    grep -E '\.(sh|bat|ps1|cmd)$' "$TEMP_DIR/all_script_files.txt" > "$TEMP_DIR/shell_files.txt" 2>/dev/null || touch "$TEMP_DIR/shell_files.txt"

    # FAST: Use xargs without -I for bulk grep (much faster)
    # Batch 1: Basic destructive patterns (all file types)
    if [[ -s "$TEMP_DIR/all_script_files.txt" ]]; then
        fast_grep_files_i "$basic_destructive_regex" < "$TEMP_DIR/all_script_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Basic destructive pattern detected" >> "$TEMP_DIR/destructive_patterns.txt"
            done
    fi

    # Batch 2: JavaScript/Python Shai-Hulud wiper patterns
    # Simplified to single-pass using tight signatures (no more two-stage grep or backtracking issues)
    if [[ -s "$TEMP_DIR/js_py_files.txt" ]]; then
        fast_grep_files_i "$shai_hulud_wiper_regex" < "$TEMP_DIR/js_py_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Shai-Hulud wiper pattern detected (JS/Python context)" >> "$TEMP_DIR/destructive_patterns.txt"
            done
    fi

    # Batch 3: Shell script conditional patterns
    if [[ -s "$TEMP_DIR/shell_files.txt" ]]; then
        fast_grep_files_i "$shell_conditional_regex" < "$TEMP_DIR/shell_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Conditional destruction pattern detected (Shell script context)" >> "$TEMP_DIR/destructive_patterns.txt"
            done
    fi
}

# Function: check_preinstall_bun_patterns
# Purpose: Detect fake Bun runtime preinstall patterns in package.json files
# Args: $1 = scan_dir (directory to scan)
# Modifies: PREINSTALL_BUN_PATTERNS (global array)
# Returns: Populates array with files containing suspicious preinstall patterns
check_preinstall_bun_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for fake Bun preinstall patterns..."

    # Look for package.json files with suspicious "preinstall": "node setup_bun.js" pattern
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            # Check if the file contains the malicious preinstall pattern
            if grep -Eq '"preinstall"[[:space:]]*:[[:space:]]*"node (setup_bun|bun_installer)\.js"' "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/preinstall_bun_patterns.txt"
            fi
        fi
    # Use pre-categorized files from collect_all_files (performance optimization)
    done < "$TEMP_DIR/package_files.txt"
}

# Function: check_github_actions_runner
# Purpose: Detect SHA1HULUD GitHub Actions runners in workflow files
# Args: $1 = scan_dir (directory to scan)
# Modifies: GITHUB_SHA1HULUD_RUNNERS (global array)
# Returns: Populates array with workflow files containing SHA1HULUD runner references
check_github_actions_runner() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for SHA1HULUD GitHub Actions runners..."

    # Look for workflow files containing SHA1HULUD runner names
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            # Check for SHA1HULUD runner references in YAML files
            if grep -qi "SHA1HULUD" "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/github_sha1hulud_runners.txt"
            fi
        fi
    # Use pre-categorized files from collect_all_files (performance optimization)
    done < "$TEMP_DIR/yaml_files.txt"
}

# Function: check_malicious_repo_descriptions
# Purpose: Detect repository descriptions with known malicious patterns
# Args: $1 = scan_dir (directory to scan)
# Modifies: malicious_repo_descriptions.txt (temp file)
# Returns: Populates temp file with git repositories matching malicious description patterns
check_malicious_repo_descriptions() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for malicious repository descriptions..."

    # Performance Optimization: Use pre-collected git repositories
    local git_repos_source
    if [[ -f "$TEMP_DIR/git_repos.txt" ]]; then
        git_repos_source="$TEMP_DIR/git_repos.txt"
    else
        # Fallback with timeout protection
        timeout 10 find "$scan_dir" -type d -name ".git" 2>/dev/null | sed 's|/.git$||' > "$TEMP_DIR/git_repos_fallback.txt" || true
        git_repos_source="$TEMP_DIR/git_repos_fallback.txt"
    fi

    # Descriptions observed across attacks
    local malicious_descriptions=(
        "Sha1-Hulud: The Second Coming"
        "Goldox-T3chs: Only Happy Girl"
    )

    # Check git repositories with malicious descriptions
    while IFS= read -r repo_dir; do
        if [[ -d "$repo_dir/.git" ]]; then
            # Check git config for repository description with timeout
            local description=""
            if command -v timeout >/dev/null 2>&1; then
                # GNU timeout is available
                description=$(timeout 5s git -C "$repo_dir" config --get --local --null --default "" repository.description 2>/dev/null | tr -d '\0') || description=""
            else
                # Fallback for systems without timeout command (e.g., macOS)
                description=$(git -C "$repo_dir" config --get --local --null --default "" repository.description 2>/dev/null | tr -d '\0') || description=""
            fi

            if [[ -n "$description" ]]; then
                for malicious_desc in "${malicious_descriptions[@]}"; do
                    if [[ "$description" == *"$malicious_desc"* ]]; then
                        echo "$repo_dir:Description: $description" >> "$TEMP_DIR/malicious_repo_descriptions.txt"
                        break
                    fi
                done
            fi
            # Skip repositories where git command times out or fails
        fi
    done < "$git_repos_source"
}

# Function: check_file_hashes
# Purpose: Scan files and compare SHA256 hashes against known malicious hash list
# Args: $1 = scan_dir (directory to scan)
# Modifies: MALICIOUS_HASHES (global array)
# Returns: Populates MALICIOUS_HASHES array with "file:hash" entries for matches
check_file_hashes() {
    local scan_dir=$1
    local totalFiles
    totalFiles=$(wc -l < "$TEMP_DIR/code_files.txt" 2>/dev/null || echo "0")

    # FAST FILTER: Use single find command for recently modified non-node_modules files
    # This is much faster than looping through every file with stat
    print_status "$BLUE" "   Filtering files for hash checking..."

    # Priority files: recently modified (30 days) OR known malicious patterns
    {
        # Priority 1: Known malicious file patterns (always check)
        grep -E "(setup_bun\.js|bun_environment\.js|actionsSecrets\.json|trufflehog)" "$TEMP_DIR/code_files.txt" 2>/dev/null || true

        # Priority 2: Non-node_modules files (fast grep filter)
        grep -v "/node_modules/" "$TEMP_DIR/code_files.txt" 2>/dev/null || true
    } | sort | uniq > "$TEMP_DIR/priority_files.txt"

    local filesCount
    filesCount=$(wc -l < "$TEMP_DIR/priority_files.txt" 2>/dev/null || echo "0")

    print_status "$BLUE" "   Checking $filesCount priority files for known malicious content (filtered from $totalFiles total)..."

    # BATCH HASH: Calculate all hashes in parallel using xargs
    # Create hash lookup file with format: hash filename
    print_status "$BLUE" "   Computing hashes in parallel..."
    # FIX: Use sha256sum on Linux/WSL, shasum on macOS/Git Bash
    # Check if shasum actually works (not just exists in PATH)
    local hash_cmd="sha256sum"
    if shasum -a 256 /dev/null &>/dev/null; then
        hash_cmd="shasum -a 256"
    fi
    # Use -n 100 to batch files and avoid "argument list too long" on large repos (issue #94)
    # Use null-delimited input to handle filenames with spaces (issue #92)
    tr '\n' '\0' < "$TEMP_DIR/priority_files.txt" | \
        xargs -0 -n 100 -P "$PARALLELISM" $hash_cmd 2>/dev/null | \
        awk '{print $1, $2}' > "$TEMP_DIR/file_hashes.txt"

    # Create malicious hash lookup pattern for grep
    printf '%s\n' "${MALICIOUS_HASHLIST[@]}" > "$TEMP_DIR/malicious_patterns.txt"

    # Fast set intersection: find matching hashes
    print_status "$BLUE" "   Checking against known malicious hashes..."
    while IFS=' ' read -r hash file; do
        if grep -qF "$hash" "$TEMP_DIR/malicious_patterns.txt" 2>/dev/null; then
            echo "$file:$hash" >> "$TEMP_DIR/malicious_hashes.txt"
        fi
    done < "$TEMP_DIR/file_hashes.txt"
}

# Function: transform_pnpm_yaml
# Purpose: Convert pnpm-lock.yaml to pseudo-package-lock.json format for parsing
# Args: $1 = packages_file (path to pnpm-lock.yaml)
# Modifies: None
# Returns: Outputs JSON to stdout with packages structure compatible with package-lock parser
transform_pnpm_yaml() {
    declare -a path
    packages_file=$1

    echo -e "{"
    echo -e "  \"packages\": {"

    depth=0
    while IFS= read -r line; do

        # Find indentation
        sep="${line%%[^ ]*}"
        currentdepth="${#sep}"

        # Remove surrounding whitespace
        line=${line##*( )} # From the beginning
        line=${line%%*( )} # From the end

        # Remove comments
        line=${line%%#*}
        line=${line%%*( )}

        # Remove comments and empty lines
        if [[ "${line:0:1}" == '#' ]] || [[ "${#line}" == 0 ]]; then
            continue
        fi

        # split into key/val
        key=${line%%:*}
        key=${key%%*( )}
        val=${line#*:}
        val=${val##*( )}

        # Save current path
        path[$currentdepth]=$key

        # Interested in packages.*
        if [ "${path[0]}" != "packages" ]; then continue; fi
        if [ "${currentdepth}" != "2" ]; then continue; fi

        # Remove surrounding whitespace (yes, again)
        key="${key#"${key%%[![:space:]]*}"}"
        key="${key%"${key##*[![:space:]]}"}"

        # Remove quote
        key="${key#"${key%%[!\']*}"}"
        key="${key%"${key##*[!\']}"}"

        # split into name/version
        name=${key%\@*}
        name=${name%*( )}
        version=${key##*@}
        version=${version##*( )}

        echo "    \"${name}\": {"
        echo "      \"version\": \"${version}\""
        echo "    },"

    done < "$packages_file"
    echo "  }"
    echo "}"
}

# Function: semverParseInto
# Purpose: Parse semantic version string into major, minor, patch, and special components
# Args: $1 = version_string, $2 = major_var, $3 = minor_var, $4 = patch_var, $5 = special_var
# Modifies: Sets variables named by $2-$5 using printf -v
# Returns: Populates variables with parsed version components
# Origin: https://github.com/cloudflare/semver_bash/blob/6cc9ce10/semver.sh
semverParseInto() {
  local RE='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
  #MAJOR
  printf -v "$2" '%s' "$(echo $1 | sed -e "s/$RE/\1/")"
  #MINOR
  printf -v "$3" '%s' "$(echo $1 | sed -e "s/$RE/\2/")"
  #PATCH
  printf -v "$4" '%s' "$(echo $1 | sed -e "s/$RE/\3/")"
  #SPECIAL
  printf -v "$5" '%s' "$(echo $1 | sed -e "s/$RE/\4/")"
}

# Function: semver_match
# Purpose: Check if version matches semver pattern with caret (^), tilde (~), or exact matching
# Args: $1 = test_subject (version to test), $2 = test_pattern (pattern like "^1.0.0" or "~1.1.0")
# Modifies: None
# Returns: 0 for match, 1 for no match (supports || for multi-pattern matching)
# Examples: "1.1.2" matches "^1.0.0", "~1.1.0", "*" but not "^2.0.0" or "~1.2.0"
semver_match() {
    local test_subject=$1
    local test_pattern=$2

    # Always matches
    if [[ "*" == "${test_pattern}" ]]; then
        return 0
    fi

    # Destructure subject
    local subject_major=0
    local subject_minor=0
    local subject_patch=0
    local subject_special=0
    semverParseInto ${test_subject} subject_major subject_minor subject_patch subject_special

    # Handle multi-variant patterns
    while IFS= read -r pattern; do
        pattern="${pattern#"${pattern%%[![:space:]]*}"}"
        pattern="${pattern%"${pattern##*[![:space:]]}"}"
        # Always matches
        if [[ "*" == "${pattern}" ]]; then
            return 0
        fi
        local pattern_major=0
        local pattern_minor=0
        local pattern_patch=0
        local pattern_special=0
        case "${pattern}" in
            ^*) # Major must match
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}"  ==  "${pattern_major}"   ]] || continue
                [[ "${subject_minor}" -ge  "${pattern_minor}"   ]] || continue
                if [[ "${subject_minor}" == "${pattern_minor}"   ]]; then
                    [[ "${subject_patch}"   -ge "${pattern_patch}"   ]] || continue
                fi
                return 0 # Match
                ;;
            ~*) # Major+minor must match
                semverParseInto ${pattern:1} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}"   ==  "${pattern_major}"   ]] || continue
                [[ "${subject_minor}"   ==  "${pattern_minor}"   ]] || continue
                [[ "${subject_patch}"   -ge "${pattern_patch}"   ]] || continue
                return 0 # Match
                ;;
            *[xX]*) # Wildcard pattern (4.x, 1.2.x, 4.X, 1.2.X, etc.)
                # Parse pattern components, handling 'x' wildcards specially
                local pattern_parts
                IFS='.' read -ra pattern_parts <<< "${pattern}"
                local subject_parts
                IFS='.' read -ra subject_parts <<< "${test_subject}"

                # Check each component, skip comparison for 'x' wildcards
                for i in 0 1 2; do
                    if [[ ${i} -lt ${#pattern_parts[@]} && ${i} -lt ${#subject_parts[@]} ]]; then
                        local pattern_part="${pattern_parts[i]}"
                        local subject_part="${subject_parts[i]}"

                        # Skip wildcard components (both lowercase x and uppercase X)
                        if [[ "${pattern_part}" == "x" ]] || [[ "${pattern_part}" == "X" ]]; then
                            continue
                        fi

                        # Extract numeric part (remove any non-numeric suffix)
                        pattern_part=$(echo "${pattern_part}" | sed 's/[^0-9].*//')
                        subject_part=$(echo "${subject_part}" | sed 's/[^0-9].*//')

                        # Compare numeric parts
                        if [[ "${subject_part}" != "${pattern_part}" ]]; then
                            continue 2  # Continue outer loop (try next pattern)
                        fi
                    fi
                done
                return 0 # Match
                ;;
            *) # Exact match
                semverParseInto ${pattern} pattern_major pattern_minor pattern_patch pattern_special
                [[ "${subject_major}"  -eq "${pattern_major}"   ]] || continue
                [[ "${subject_minor}"  -eq "${pattern_minor}"   ]] || continue
                [[ "${subject_patch}"  -eq "${pattern_patch}"   ]] || continue
                [[ "${subject_special}" == "${pattern_special}" ]] || continue
                return 0 # MATCH
                ;;
        esac
        # Splits '||' into newlines with sed
    done < <(echo "${test_pattern}" | sed 's/||/\n/g')

    # Fallthrough = no match
    return 1;
}

# Function: check_packages
# Purpose: Scan package.json files for compromised packages and suspicious namespaces
# Args: $1 = scan_dir (directory to scan)
# Modifies: COMPROMISED_FOUND, SUSPICIOUS_FOUND, NAMESPACE_WARNINGS (global arrays)
# Returns: Populates arrays with matches using exact and semver pattern matching
check_packages() {
    local scan_dir=$1

    local filesCount
    filesCount=$(wc -l < "$TEMP_DIR/package_files.txt" 2>/dev/null || echo "0")

    print_status "$BLUE" "   Checking $filesCount package.json files for compromised packages..."

    # BATCH OPTIMIZATION: Extract all deps using parallel processing
    print_status "$BLUE" "   Extracting dependencies from all package.json files..."

    # Create optimized lookup table from compromised packages (sorted for join)
    awk -F: '{print $1":"$2}' $SCRIPT_DIR/compromised-packages.txt | LC_ALL=C sort > "$TEMP_DIR/compromised_lookup.txt"

    # Extract all dependencies from all package.json files using parallel xargs + awk
    # Format: file_path|package_name:version
    # Use awk to parse JSON dependencies - portable and fast
    # Use null-delimited input to handle filenames with spaces (issue #92)
    tr '\n' '\0' < "$TEMP_DIR/package_files.txt" | \
        xargs -0 -P "$PARALLELISM" -n1 -r awk '
            /"dependencies":|"devDependencies":/ {flag=1; next}
            /^[[:space:]]*\}/ {flag=0}
            flag && /^[[:space:]]*"[^"]+":/ {
                # Extract "package": "version"
                gsub(/^[[:space:]]*"/, "")
                gsub(/":[[:space:]]*"/, ":")
                gsub(/".*$/, "")
                if (length($0) > 0 && index($0, ":") > 0) {
                    print FILENAME "|" $0
                }
            }
        ' > "$TEMP_DIR/all_deps.txt" 2>/dev/null

    # FAST SET INTERSECTION: Use awk hash lookup instead of grep per line
    print_status "$BLUE" "   Checking dependencies against compromised list..."
    local depCount=$(wc -l < "$TEMP_DIR/all_deps.txt" 2>/dev/null || echo "0")
    print_status "$BLUE" "   Found $depCount total dependencies to check"

    # Create sorted deps file for set intersection
    cut -d'|' -f2 "$TEMP_DIR/all_deps.txt" | LC_ALL=C sort | uniq > "$TEMP_DIR/deps_only.txt"

    # Find matching deps using comm (set intersection - super fast)
    # FIX: Use LC_ALL=C to ensure comm uses the same sort order as sort (Git Bash compatibility)
    LC_ALL=C comm -12 "$TEMP_DIR/compromised_lookup.txt" "$TEMP_DIR/deps_only.txt" > "$TEMP_DIR/matched_deps.txt"

    # If matches found, map back to file paths
    if [[ -s "$TEMP_DIR/matched_deps.txt" ]]; then
        while IFS= read -r matched_dep; do
            { grep -F "|$matched_dep" "$TEMP_DIR/all_deps.txt" || true; } | while IFS='|' read -r file_path dep; do
                [[ -n "$file_path" ]] && echo "$file_path:${dep/:/@}" >> "$TEMP_DIR/compromised_found.txt"
            done
        done < "$TEMP_DIR/matched_deps.txt"
    fi

    # Check for suspicious namespaces - simplified for speed
    print_status "$BLUE" "   Checking for compromised namespaces..."
    # Quick check: just look in the already-extracted dependencies file
    # This is much faster than re-reading all package.json files
    for namespace in "${COMPROMISED_NAMESPACES[@]}"; do
        # Check if any dependency starts with this namespace
        if grep -q "|$namespace/" "$TEMP_DIR/all_deps.txt" 2>/dev/null; then
            { grep "|$namespace/" "$TEMP_DIR/all_deps.txt" || true; } | cut -d'|' -f1 | sort | uniq | while read -r file; do
                [[ -n "$file" ]] && echo "$file:Contains packages from compromised namespace: $namespace" >> "$TEMP_DIR/namespace_warnings.txt"
            done
        fi
    done

    echo -ne "\r\033[K"
}

# Function: check_semver_ranges
# Purpose: Check if package.json semver ranges (^, ~) could resolve to compromised versions
# Args: $1 = scan_dir (directory to scan)
# Modifies: lockfile_safe_versions.txt, suspicious_found.txt, compromised_found.txt
# Returns: Populates findings files based on lockfile analysis
# Note: Only runs when --check-semver-ranges flag is passed (opt-in)
check_semver_ranges() {
    [[ "$CHECK_SEMVER_RANGES" != "true" ]] && return 0

    local scan_dir=$1
    print_status "$BLUE" "   Checking semver ranges for potential compromised version matches..."

    # Re-use already extracted deps from check_packages (all_deps.txt)
    # Format: file_path|package_name:version_range
    local checked=0
    local matches=0

    while IFS='|' read -r file_path dep_info; do
        [[ -z "$file_path" || -z "$dep_info" ]] && continue

        local pkg_name="${dep_info%:*}"
        local version_range="${dep_info#*:}"

        # Skip if no compromised versions for this package
        [[ -z "${COMPROMISED_VERSIONS_BY_NAME[$pkg_name]}" ]] && continue

        # Skip exact versions (no ^, ~, x, *)
        [[ ! "$version_range" =~ [\^~xX\*] ]] && continue

        ((checked++)) || true

        # Check each compromised version against the range
        for comp_version in ${COMPROMISED_VERSIONS_BY_NAME[$pkg_name]}; do
            if semver_match "$comp_version" "$version_range"; then
                ((matches++)) || true
                # Range could match compromised version - check lockfile
                local pkg_dir
                pkg_dir=$(dirname "$file_path")
                local locked_version
                locked_version=$(get_lockfile_version "$pkg_name" "$pkg_dir" "$scan_dir")

                if [[ -n "$locked_version" ]]; then
                    if [[ "$locked_version" == "$comp_version" ]]; then
                        # Lockfile has compromised version - HIGH risk (already detected by check_packages)
                        # Don't double-report, just skip
                        :
                    else
                        # Lockfile has safe version - LOW risk warning
                        echo "$file_path:$pkg_name@$version_range (locked to $locked_version, could match $comp_version)" >> "$TEMP_DIR/lockfile_safe_versions.txt"
                    fi
                else
                    # No lockfile - LOW risk (packages largely unpublished, only matters with stale caches)
                    echo "$file_path:$pkg_name@$version_range (no lockfile, could resolve to $comp_version)" >> "$TEMP_DIR/lockfile_safe_versions.txt"
                fi
                break  # Found a match, no need to check other versions
            fi
        done
    done < "$TEMP_DIR/all_deps.txt"

    if [[ $matches -gt 0 ]]; then
        print_status "$BLUE" "   Found $matches semver ranges that could match compromised versions (checked $checked ranges)"
    fi
}

# Function: check_postinstall_hooks
# Purpose: Detect suspicious postinstall scripts that may execute malicious code
# Args: $1 = scan_dir (directory to scan)
# Modifies: POSTINSTALL_HOOKS (global array)
# Returns: Populates POSTINSTALL_HOOKS array with package.json files containing hooks
check_postinstall_hooks() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for suspicious postinstall hooks..."

    while IFS= read -r -d '' package_file; do
        if [[ -f "$package_file" && -r "$package_file" ]]; then
            # Look for postinstall scripts
            if grep -q "\"postinstall\"" "$package_file" 2>/dev/null; then
                local postinstall_cmd
                postinstall_cmd=$(grep -A1 "\"postinstall\"" "$package_file" 2>/dev/null | grep -o '"[^"]*"' 2>/dev/null | tail -1 2>/dev/null | tr -d '"' 2>/dev/null || true) || true

                # Check for suspicious patterns in postinstall commands
                if [[ -n "$postinstall_cmd" ]] && ([[ "$postinstall_cmd" == *"curl"* ]] || [[ "$postinstall_cmd" == *"wget"* ]] || [[ "$postinstall_cmd" == *"node -e"* ]] || [[ "$postinstall_cmd" == *"eval"* ]]); then
                    echo "$package_file:Suspicious postinstall: $postinstall_cmd" >> "$TEMP_DIR/postinstall_hooks.txt"
                fi
            fi
        fi
    # Use pre-categorized files from collect_all_files (performance optimization)
    done < <(tr '\n' '\0' < "$TEMP_DIR/package_files.txt")
}

# Function: check_content
# Purpose: Search for suspicious content patterns like webhook.site and malicious endpoints
# Args: $1 = scan_dir (directory to scan)
# Modifies: SUSPICIOUS_CONTENT (global array)
# Returns: Populates SUSPICIOUS_CONTENT array with files containing suspicious patterns
check_content() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for suspicious content patterns..."

    # FAST: Use xargs with grep -l for bulk searching instead of per-file grep
    # Search for webhook.site references
    cat "$TEMP_DIR/code_files.txt" "$TEMP_DIR/yaml_files.txt" 2>/dev/null | \
        fast_grep_files_fixed "webhook.site" | while read -r file; do
        [[ -n "$file" ]] && echo "$file:webhook.site reference" >> "$TEMP_DIR/suspicious_content.txt"
    done

    # Search for malicious webhook endpoint
    cat "$TEMP_DIR/code_files.txt" "$TEMP_DIR/yaml_files.txt" 2>/dev/null | \
        fast_grep_files_fixed "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" | while read -r file; do
        [[ -n "$file" ]] && echo "$file:malicious webhook endpoint" >> "$TEMP_DIR/suspicious_content.txt"
    done
}

# Function: check_crypto_theft_patterns
# Purpose: Detect cryptocurrency theft patterns from the Chalk/Debug attack (Sept 8, 2025)
# Args: $1 = scan_dir (directory to scan)
# Modifies: CRYPTO_PATTERNS, HIGH_RISK_CRYPTO (global arrays)
# Returns: Populates arrays with wallet hijacking, XMLHttpRequest tampering, and attacker indicators
check_crypto_theft_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for cryptocurrency theft patterns..."

    # FAST: Use xargs with grep -l for bulk pattern searching
    # Check for specific malicious functions from chalk/debug attack (highest priority)
    fast_grep_files "checkethereumw|runmask|newdlocal|_0x19ca67" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -n "$file" ]] && echo "$file:Known crypto theft function names detected" >> "$TEMP_DIR/crypto_patterns.txt"
        done

    # Check for known attacker wallets (high priority)
    fast_grep_files "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -n "$file" ]] && echo "$file:Known attacker wallet address detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
        done

    # Check for npmjs.help phishing domain
    fast_grep_files_fixed "npmjs.help" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -n "$file" ]] && echo "$file:Phishing domain npmjs.help detected" >> "$TEMP_DIR/crypto_patterns.txt"
        done

    # Check for XMLHttpRequest hijacking (medium priority - filter out framework code)
    fast_grep_files_fixed "XMLHttpRequest.prototype.send" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -z "$file" ]] && continue
            if [[ "$file" == *"/react-native/Libraries/Network/"* ]] || [[ "$file" == *"/next/dist/compiled/"* ]]; then
                # Framework code - check for crypto patterns too
                if fast_grep_quiet "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help" "$file"; then
                    echo "$file:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                else
                    echo "$file:XMLHttpRequest prototype modification detected in framework code - LOW RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                fi
            else
                if fast_grep_quiet "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help" "$file"; then
                    echo "$file:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                else
                    echo "$file:XMLHttpRequest prototype modification detected - MEDIUM RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                fi
            fi
        done

    # Check for javascript obfuscation
    fast_grep_files_fixed "javascript-obfuscator" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -n "$file" ]] && echo "$file:JavaScript obfuscation detected" >> "$TEMP_DIR/crypto_patterns.txt"
        done

    # Check for generic Ethereum wallet address patterns (MEDIUM priority)
    # Files with 0x addresses AND crypto-related keywords
    fast_grep_files "0x[a-fA-F0-9]{40}" < "$TEMP_DIR/code_files.txt" | \
        while read -r file; do
            [[ -z "$file" ]] && continue
            # Skip if already flagged as HIGH RISK
            if grep -qF "$file:" "$TEMP_DIR/crypto_patterns.txt" 2>/dev/null; then
                continue
            fi
            # Check for crypto-related context keywords
            if fast_grep_quiet "ethereum|wallet|address|crypto" "$file"; then
                echo "$file:Ethereum wallet address patterns detected" >> "$TEMP_DIR/crypto_patterns.txt"
            fi
        done
}

# Function: check_git_branches
# Purpose: Search for suspicious git branches containing "shai-hulud" in their names
# Args: $1 = scan_dir (directory to scan)
# Modifies: GIT_BRANCHES (global array)
# Returns: Populates GIT_BRANCHES array with branch names and commit hashes
check_git_branches() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for suspicious git branches..."

    # Performance Optimization: Use pre-collected git repositories and limit search scope
    if [[ -f "$TEMP_DIR/git_repos.txt" ]]; then
        while IFS= read -r repo_dir; do
            if [[ -d "$repo_dir/.git/refs/heads" ]]; then
                # Quick check: only look for shai-hulud patterns in branch names
                local git_refs_dir="$repo_dir/.git/refs/heads"
                if [[ -d "$git_refs_dir" ]]; then
                    # Use shell globbing instead of find for better performance
                    for branch_file in "$git_refs_dir"/*shai-hulud* "$git_refs_dir"/*shai*hulud*; do
                        if [[ -f "$branch_file" ]]; then
                            local branch_name
                            branch_name=$(basename "$branch_file")
                            local commit_hash
                            commit_hash=$(cat "$branch_file" 2>/dev/null || echo "unknown")
                            echo "$repo_dir:Branch '$branch_name' (commit: ${commit_hash:0:8}...)" >> "$TEMP_DIR/git_branches.txt"
                        fi
                    done
                fi
            fi
        done < "$TEMP_DIR/git_repos.txt"
    else
        # Fallback: quick search with timeout to prevent hanging
        timeout 5 find "$scan_dir" -name ".git" -type d 2>/dev/null | head -20 | while IFS= read -r git_dir; do
            local repo_dir
            repo_dir=$(dirname "$git_dir")
            if [[ -d "$git_dir/refs/heads" ]]; then
                # Quick check only
                for branch_file in "$git_dir/refs/heads"/*shai-hulud*; do
                    if [[ -f "$branch_file" ]]; then
                        local branch_name
                        branch_name=$(basename "$branch_file")
                        echo "$repo_dir:Branch '$branch_name'" >> "$TEMP_DIR/git_branches.txt"
                    fi
                done
            fi
        done || true  # Don't fail if timeout occurs
    fi
}

# Function: get_file_context
# Purpose: Classify file context for risk assessment (node_modules, source, build, etc.)
# Args: $1 = file_path (path to file)
# Modifies: None
# Returns: Echoes context string (node_modules, documentation, type_definitions, build_output, configuration, source_code)
get_file_context() {
    local file_path=$1

    # Check if file is in node_modules
    if [[ "$file_path" == *"/node_modules/"* ]]; then
        echo "node_modules"
        return
    fi

    # Check if file is documentation
    if [[ "$file_path" == *".md" ]] || [[ "$file_path" == *".txt" ]] || [[ "$file_path" == *".rst" ]]; then
        echo "documentation"
        return
    fi

    # Check if file is TypeScript definitions
    if [[ "$file_path" == *".d.ts" ]]; then
        echo "type_definitions"
        return
    fi

    # Check if file is in build/dist directories
    if [[ "$file_path" == *"/dist/"* ]] || [[ "$file_path" == *"/build/"* ]] || [[ "$file_path" == *"/public/"* ]]; then
        echo "build_output"
        return
    fi

    # Check if it's a config file
    if [[ "$(basename "$file_path")" == *"config"* ]] || [[ "$(basename "$file_path")" == *".config."* ]]; then
        echo "configuration"
        return
    fi

    echo "source_code"
}

# Function: is_legitimate_pattern
# Purpose: Identify legitimate framework/build tool patterns to reduce false positives
# Args: $1 = file_path, $2 = content_sample (text snippet from file)
# Modifies: None
# Returns: 0 for legitimate, 1 for potentially suspicious
is_legitimate_pattern() {
    local file_path=$1
    local content_sample="$2"

    # Vue.js development patterns
    if [[ "$content_sample" == *"process.env.NODE_ENV"* ]] && [[ "$content_sample" == *"production"* ]]; then
        return 0  # legitimate
    fi

    # Common framework patterns
    if [[ "$content_sample" == *"createApp"* ]] || [[ "$content_sample" == *"Vue"* ]]; then
        return 0  # legitimate
    fi

    # Package manager and build tool patterns
    if [[ "$content_sample" == *"webpack"* ]] || [[ "$content_sample" == *"vite"* ]] || [[ "$content_sample" == *"rollup"* ]]; then
        return 0  # legitimate
    fi

    return 1  # potentially suspicious
}

# Function: get_lockfile_version
# Purpose: Extract actual installed version from lockfile for a specific package
# Args: $1 = package_name, $2 = package_json_dir (directory containing package.json), $3 = scan_boundary (original scan directory)
# Modifies: None
# Returns: Echoes installed version or empty string if not found
get_lockfile_version() {
    local package_name="$1"
    local package_dir="$2"
    local scan_boundary="$3"

    # Search upward for lockfiles (supports packages in node_modules subdirectories)
    local current_dir="$package_dir"

    # Traverse up the directory tree until we find a lockfile, reach root, or hit scan boundary
    while [[ "$current_dir" != "/" && "$current_dir" != "." && -n "$current_dir" ]]; do
        # SECURITY: Don't search above the original scan directory boundary
        if [[ ! "$current_dir/" =~ ^"$scan_boundary"/ && "$current_dir" != "$scan_boundary" ]]; then
            break
        fi
        # Check for package-lock.json first (most common)
        if [[ -f "$current_dir/package-lock.json" ]]; then
            # Use the existing logic from check_package_integrity for block-based parsing
            local found_version
            found_version=$(awk -v pkg="node_modules/$package_name" '
                $0 ~ "\"" pkg "\":" { in_block=1; brace_count=1 }
                in_block && /\{/ && !($0 ~ "\"" pkg "\":") { brace_count++ }
                in_block && /\}/ {
                    brace_count--
                    if (brace_count <= 0) { in_block=0 }
                }
                in_block && /\s*"version":/ {
                    # Extract version value between quotes
                    split($0, parts, "\"")
                    for (i in parts) {
                        if (parts[i] ~ /^[0-9]/) {
                            print parts[i]
                            exit
                        }
                    }
                }
            ' "$current_dir/package-lock.json" 2>/dev/null || true)

            if [[ -n "$found_version" ]]; then
                echo "$found_version"
                return
            fi
        fi

        # Check for yarn.lock
        if [[ -f "$current_dir/yarn.lock" ]]; then
            # Yarn.lock format: package-name@version:
            local found_version
            found_version=$(grep "^\"\\?$package_name@" "$current_dir/yarn.lock" 2>/dev/null | head -1 | sed 's/.*@\([^"]*\).*/\1/' 2>/dev/null || true)
            if [[ -n "$found_version" ]]; then
                echo "$found_version"
                return
            fi
        fi

        # Check for pnpm-lock.yaml
        if [[ -f "$current_dir/pnpm-lock.yaml" ]]; then
            # Use transform_pnpm_yaml and then parse like package-lock.json
            local temp_lockfile
            temp_lockfile=$(mktemp "${TMPDIR:-/tmp}/pnpm-parse.XXXXXXXX")
            TEMP_FILES+=("$temp_lockfile")

            transform_pnpm_yaml "$current_dir/pnpm-lock.yaml" > "$temp_lockfile" 2>/dev/null

            local found_version
            found_version=$(awk -v pkg="$package_name" '
                $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
                in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
                in_block && /\}/ {
                    brace_count--
                    if (brace_count <= 0) { in_block=0 }
                }
                in_block && /\s*"version":/ {
                    gsub(/.*"version":\s*"/, "")
                    gsub(/".*/, "")
                    print $0
                    exit
                }
            ' "$temp_lockfile" 2>/dev/null || true)

            if [[ -n "$found_version" ]]; then
                echo "$found_version"
                return
            fi
        fi

        # Move to parent directory
        current_dir=$(dirname "$current_dir")
    done

    # No lockfile or package not found
    echo ""
}

# Function: check_trufflehog_activity
# Purpose: Detect Trufflehog secret scanning activity with context-aware risk assessment
# Args: $1 = scan_dir (directory to scan)
# Modifies: TRUFFLEHOG_ACTIVITY (global array)
# Returns: Populates TRUFFLEHOG_ACTIVITY array with risk level (HIGH/MEDIUM/LOW) prefixes
check_trufflehog_activity() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for Trufflehog activity and secret scanning..."

    # Look for trufflehog binary files (always HIGH RISK)
    while IFS= read -r binary_file; do
        if [[ -f "$binary_file" ]]; then
            echo "$binary_file:HIGH:Trufflehog binary found" >> "$TEMP_DIR/trufflehog_activity.txt"
        fi
    done < "$TEMP_DIR/trufflehog_files.txt"

    # Combine script and code files for scanning
    cat "$TEMP_DIR/script_files.txt" "$TEMP_DIR/code_files.txt" 2>/dev/null | sort -u > "$TEMP_DIR/trufflehog_scan_files.txt"

    # HIGH PRIORITY: Dynamic TruffleHog download patterns (November 2025 attack)
    fast_grep_files_i "curl.*trufflehog|wget.*trufflehog|bunExecutable.*trufflehog|download.*trufflehog" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | while read -r file; do
        [[ -n "$file" ]] && echo "$file:HIGH:November 2025 pattern - Dynamic TruffleHog download via curl/wget/Bun" >> "$TEMP_DIR/trufflehog_activity.txt"
    done

    # HIGH PRIORITY: TruffleHog credential harvesting patterns
    fast_grep_files_i "TruffleHog.*scan.*credential|trufflehog.*env|trufflehog.*AWS|trufflehog.*NPM_TOKEN" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | while read -r file; do
        [[ -n "$file" ]] && echo "$file:HIGH:TruffleHog credential scanning pattern detected" >> "$TEMP_DIR/trufflehog_activity.txt"
    done

    # HIGH PRIORITY: Credential patterns with exfiltration indicators
    fast_grep_files "(AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN).*(webhook\.site|curl|https\.request)" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | \
        { grep -v "/node_modules/\|\.d\.ts$" || true; } | while read -r file; do
        [[ -n "$file" ]] && echo "$file:HIGH:Credential patterns with potential exfiltration" >> "$TEMP_DIR/trufflehog_activity.txt"
    done

    # MEDIUM PRIORITY: Trufflehog references in source code (not node_modules/docs)
    fast_grep_files_i "trufflehog|TruffleHog" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | \
        { grep -v "/node_modules/\|\.md$\|/docs/\|\.d\.ts$" || true; } | while read -r file; do
        # Check if already flagged as HIGH
        if [[ -n "$file" ]] && ! grep -qF "$file:" "$TEMP_DIR/trufflehog_activity.txt" 2>/dev/null; then
            echo "$file:MEDIUM:Contains trufflehog references in source code" >> "$TEMP_DIR/trufflehog_activity.txt"
        fi
    done

    # MEDIUM PRIORITY: Credential scanning patterns (not in type definitions)
    fast_grep_files "AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | \
        { grep -v "/node_modules/\|\.d\.ts$\|/docs/" || true; } | while read -r file; do
        # Check if already flagged
        if [[ -n "$file" ]] && ! grep -qF "$file:" "$TEMP_DIR/trufflehog_activity.txt" 2>/dev/null; then
            echo "$file:MEDIUM:Contains credential scanning patterns" >> "$TEMP_DIR/trufflehog_activity.txt"
        fi
    done

    # LOW PRIORITY: Environment variable scanning with suspicious patterns
    fast_grep_files_i "(process\.env|os\.environ|getenv).*(scan|harvest|steal|exfiltrat)" \
        < "$TEMP_DIR/trufflehog_scan_files.txt" | \
        { grep -v "/node_modules/\|\.d\.ts$" || true; } | while read -r file; do
        if [[ -n "$file" ]] && ! grep -qF "$file:" "$TEMP_DIR/trufflehog_activity.txt" 2>/dev/null; then
            echo "$file:LOW:Potentially suspicious environment variable access" >> "$TEMP_DIR/trufflehog_activity.txt"
        fi
    done
}

# Function: check_shai_hulud_repos
# Purpose: Detect Shai-Hulud worm repositories and malicious migration patterns
# Args: $1 = scan_dir (directory to scan)
# Modifies: SHAI_HULUD_REPOS (global array)
# Returns: Populates SHAI_HULUD_REPOS array with repository patterns and migration indicators
check_shai_hulud_repos() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for Shai-Hulud repositories and migration patterns..."

    # Performance Optimization: Use pre-collected git repositories
    local git_repos_source
    if [[ -f "$TEMP_DIR/git_repos.txt" ]]; then
        git_repos_source="$TEMP_DIR/git_repos.txt"
    else
        # Fallback with timeout protection
        timeout 10 find "$scan_dir" -name ".git" -type d 2>/dev/null | sed 's|/.git$||' > "$TEMP_DIR/git_repos_fallback.txt" || true
        git_repos_source="$TEMP_DIR/git_repos_fallback.txt"
    fi

    while IFS= read -r repo_dir; do
        # Check if this is a repository named shai-hulud
        local repo_name
        repo_name=$(basename "$repo_dir")
        if [[ "$repo_name" == *"shai-hulud"* ]] || [[ "$repo_name" == *"Shai-Hulud"* ]]; then
            echo "$repo_dir:Repository name contains 'Shai-Hulud'" >> "$TEMP_DIR/shai_hulud_repos.txt"
        fi

        # Check for migration pattern repositories (new IoC)
        if [[ "$repo_name" == *"-migration"* ]]; then
            echo "$repo_dir:Repository name contains migration pattern" >> "$TEMP_DIR/shai_hulud_repos.txt"
        fi

        # Check for GitHub remote URLs containing shai-hulud
        local git_config="$repo_dir/.git/config"
        if [[ -f "$git_config" ]]; then
            if grep -q "shai-hulud\|Shai-Hulud" "$git_config" 2>/dev/null; then
                echo "$repo_dir:Git remote contains 'Shai-Hulud'" >> "$TEMP_DIR/shai_hulud_repos.txt"
            fi
        fi

        # Check for double base64-encoded data.json (new IoC)
        if [[ -f "$repo_dir/data.json" ]]; then
            local content_sample
            content_sample=$(head -5 "$repo_dir/data.json" 2>/dev/null || true)
            if [[ "$content_sample" == *"eyJ"* ]] && [[ "$content_sample" == *"=="* ]]; then
                echo "$repo_dir:Contains suspicious data.json (possible base64-encoded credentials)" >> "$TEMP_DIR/shai_hulud_repos.txt"
            fi
        fi
    done < "$git_repos_source"
}

# Function: check_package_integrity
# Purpose: Verify package lock files for compromised packages and version integrity
# Args: $1 = scan_dir (directory to scan)
# Modifies: INTEGRITY_ISSUES (global array)
# Returns: Populates INTEGRITY_ISSUES with compromised packages found in lockfiles
check_package_integrity() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking package lock files for integrity issues..."

    # Check each lockfile
    while IFS= read -r -d '' lockfile; do
        if [[ -f "$lockfile" && -r "$lockfile" ]]; then
            org_file="$lockfile"

            # Transform pnpm-lock.yaml into pseudo-package-lock
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                lockfile=$(mktemp "${TMPDIR:-/tmp}/lockfile.XXXXXXXX")
                transform_pnpm_yaml "$org_file" > "$lockfile"
            fi

            # Extract all package:version pairs from lockfile using AWK block parser
            # This handles the JSON structure where name and version are on different lines
            awk '
                # Match "node_modules/package-name": { pattern
                /^[[:space:]]*"node_modules\/[^"]+":/ {
                    # Extract package name
                    gsub(/.*"node_modules\//, "")
                    gsub(/".*/, "")
                    current_pkg = $0
                    in_block = 1
                    next
                }
                # Match "package-name": { in packages section (older format)
                /^[[:space:]]*"[^"\/]+":.*\{/ && !in_block {
                    gsub(/^[[:space:]]*"/, "")
                    gsub(/".*/, "")
                    if ($0 !~ /^(name|version|resolved|integrity|dependencies|devDependencies|engines|funding|bin|peerDependencies)$/) {
                        current_pkg = $0
                        in_block = 1
                    }
                    next
                }
                # Extract version within block
                in_block && /"version":/ {
                    gsub(/.*"version"[[:space:]]*:[[:space:]]*"/, "")
                    gsub(/".*/, "")
                    if (current_pkg != "" && $0 ~ /^[0-9]/) {
                        print current_pkg ":" $0
                    }
                    in_block = 0
                    current_pkg = ""
                }
                # End of block
                in_block && /^[[:space:]]*\}/ {
                    in_block = 0
                    current_pkg = ""
                }
            ' "$lockfile" 2>/dev/null | while IFS=: read -r pkg_name pkg_version; do
                # Check if this package:version is compromised using O(1) lookup
                if [[ -v COMPROMISED_PACKAGES_MAP["$pkg_name:$pkg_version"] ]]; then
                    echo "$org_file:Compromised package in lockfile: $pkg_name@$pkg_version" >> "$TEMP_DIR/integrity_issues.txt"
                fi
            done

            # Check for @ctrl packages (potential worm activity)
            if grep -q "@ctrl" "$lockfile" 2>/dev/null; then
                echo "$org_file:Lockfile contains @ctrl packages (potential worm activity)" >> "$TEMP_DIR/integrity_issues.txt"
            fi

            # Cleanup temp lockfile for pnpm
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                rm -f "$lockfile"
            fi
        fi
    done < <(tr '\n' '\0' < "$TEMP_DIR/lockfiles.txt")
}

# Function: check_typosquatting
# Purpose: Detect typosquatting and homoglyph attacks in package dependencies
# Args: $1 = scan_dir (directory to scan)
# Modifies: TYPOSQUATTING_WARNINGS (global array)
# Returns: Populates TYPOSQUATTING_WARNINGS with Unicode chars, confusables, and similar names
check_typosquatting() {
    local scan_dir=$1

    # Popular packages commonly targeted for typosquatting
    local popular_packages=(
        "react" "vue" "angular" "express" "lodash" "axios" "typescript"
        "webpack" "babel" "eslint" "jest" "mocha" "chalk" "debug"
        "commander" "inquirer" "yargs" "request" "moment" "underscore"
        "jquery" "bootstrap" "socket.io" "redis" "mongoose" "passport"
    )

    # Track packages already warned about to prevent duplicates
    local warned_packages=()

    # Helper function to check if package already warned about
    already_warned() {
        local pkg="$1"
        local file="$2"
        local key="$file:$pkg"
        for warned in "${warned_packages[@]}"; do
            [[ "$warned" == "$key" ]] && return 0
        done
        return 1
    }

    # Cyrillic and Unicode lookalike characters for common ASCII characters
    # Using od to detect non-ASCII characters in package names
    while IFS= read -r -d '' package_file; do
        if [[ -f "$package_file" && -r "$package_file" ]]; then
            # Extract package names from dependencies sections only
            local package_names
            package_names=$(awk '
                /^[[:space:]]*"dependencies"[[:space:]]*:/ { in_deps=1; next }
                /^[[:space:]]*"devDependencies"[[:space:]]*:/ { in_deps=1; next }
                /^[[:space:]]*"peerDependencies"[[:space:]]*:/ { in_deps=1; next }
                /^[[:space:]]*"optionalDependencies"[[:space:]]*:/ { in_deps=1; next }
                /^[[:space:]]*}/ && in_deps { in_deps=0; next }
                in_deps && /^[[:space:]]*"[^"]+":/ {
                    gsub(/^[[:space:]]*"/, "", $0)
                    gsub(/".*$/, "", $0)
                    if (length($0) > 1) print $0
                }
            ' "$package_file" | sort -u)

            while IFS= read -r package_name; do
                [[ -z "$package_name" ]] && continue

                # Skip if not a package name (too short, no alpha chars, etc)
                [[ ${#package_name} -lt 2 ]] && continue
                echo "$package_name" | grep -q '[a-zA-Z]' || continue

                # Check for non-ASCII characters using LC_ALL=C for compatibility
                local has_unicode=0
                if ! LC_ALL=C echo "$package_name" | grep -q '^[a-zA-Z0-9@/._-]*$'; then
                    # Package name contains characters outside basic ASCII range
                    has_unicode=1
                fi

                if [[ $has_unicode -eq 1 ]]; then
                    # Simplified check - if it contains non-standard characters, flag it
                    if ! already_warned "$package_name" "$package_file"; then
                        echo "$package_file:Potential Unicode/homoglyph characters in package: $package_name" >> "$TEMP_DIR/typosquatting_warnings.txt"
                        warned_packages+=("$package_file:$package_name")
                    fi
                fi

                # Check for confusable characters (common typosquatting patterns)
                local confusables=(
                    # Common character substitutions
                    "rn:m" "vv:w" "cl:d" "ii:i" "nn:n" "oo:o"
                )

                for confusable in "${confusables[@]}"; do
                    local pattern="${confusable%:*}"
                    local target="${confusable#*:}"
                    if echo "$package_name" | grep -q "$pattern"; then
                        if ! already_warned "$package_name" "$package_file"; then
                            echo "$package_file:Potential typosquatting pattern '$pattern' in package: $package_name" >> "$TEMP_DIR/typosquatting_warnings.txt"
                            warned_packages+=("$package_file:$package_name")
                        fi
                    fi
                done

                # Check similarity to popular packages using simple character distance
                for popular in "${popular_packages[@]}"; do
                    # Skip exact matches
                    [[ "$package_name" == "$popular" ]] && continue

                    # Skip common legitimate variations
                    case "$package_name" in
                        "test"|"tests"|"testing") continue ;;  # Don't flag test packages
                        "types"|"util"|"utils"|"core") continue ;;  # Common package names
                        "lib"|"libs"|"common"|"shared") continue ;;
                    esac

                    # Check for single character differences (common typos) - but only for longer package names
                    if [[ ${#package_name} -eq ${#popular} && ${#package_name} -gt 4 ]]; then
                        local diff_count=0
                        for ((i=0; i<${#package_name}; i++)); do
                            if [[ "${package_name:$i:1}" != "${popular:$i:1}" ]]; then
                                diff_count=$((diff_count+1))
                            fi
                        done

                        if [[ $diff_count -eq 1 ]]; then
                            # Additional check - avoid common legitimate variations
                            if [[ "$package_name" != *"-"* && "$popular" != *"-"* ]]; then
                                if ! already_warned "$package_name" "$package_file"; then
                                    echo "$package_file:Potential typosquatting of '$popular': $package_name (1 character difference)" >> "$TEMP_DIR/typosquatting_warnings.txt"
                                    warned_packages+=("$package_file:$package_name")
                                fi
                            fi
                        fi
                    fi

                    # Check for common typosquatting patterns
                    if [[ ${#package_name} -eq $((${#popular} - 1)) ]]; then
                        # Missing character check
                        for ((i=0; i<=${#popular}; i++)); do
                            local test_name="${popular:0:$i}${popular:$((i+1))}"
                            if [[ "$package_name" == "$test_name" ]]; then
                                if ! already_warned "$package_name" "$package_file"; then
                                    echo "$package_file:Potential typosquatting of '$popular': $package_name (missing character)" >> "$TEMP_DIR/typosquatting_warnings.txt"
                                    warned_packages+=("$package_file:$package_name")
                                fi
                                break
                            fi
                        done
                    fi

                    # Check for extra character
                    if [[ ${#package_name} -eq $((${#popular} + 1)) ]]; then
                        for ((i=0; i<=${#package_name}; i++)); do
                            local test_name="${package_name:0:$i}${package_name:$((i+1))}"
                            if [[ "$test_name" == "$popular" ]]; then
                                if ! already_warned "$package_name" "$package_file"; then
                                    echo "$package_file:Potential typosquatting of '$popular': $package_name (extra character)" >> "$TEMP_DIR/typosquatting_warnings.txt"
                                    warned_packages+=("$package_file:$package_name")
                                fi
                                break
                            fi
                        done
                    fi
                done

                # Check for namespace confusion (e.g., @typescript_eslinter vs @typescript-eslint)
                if [[ "$package_name" == @* ]]; then
                    local namespace="${package_name%%/*}"
                    local package_part="${package_name#*/}"

                    # Common namespace typos
                    local suspicious_namespaces=(
                        "@types" "@angular" "@typescript" "@react" "@vue" "@babel"
                    )

                    for suspicious in "${suspicious_namespaces[@]}"; do
                        if [[ "$namespace" != "$suspicious" ]] && echo "$namespace" | grep -q "${suspicious:1}"; then
                            # Check if it's a close match but not exact
                            local ns_clean="${namespace:1}"  # Remove @
                            local sus_clean="${suspicious:1}"  # Remove @

                            if [[ ${#ns_clean} -eq ${#sus_clean} ]]; then
                                local ns_diff=0
                                for ((i=0; i<${#ns_clean}; i++)); do
                                    if [[ "${ns_clean:$i:1}" != "${sus_clean:$i:1}" ]]; then
                                        ns_diff=$((ns_diff+1))
                                    fi
                                done

                                if [[ $ns_diff -ge 1 && $ns_diff -le 2 ]]; then
                                    if ! already_warned "$package_name" "$package_file"; then
                                        echo "$package_file:Suspicious namespace variation: $namespace (similar to $suspicious)" >> "$TEMP_DIR/typosquatting_warnings.txt"
                                        warned_packages+=("$package_file:$package_name")
                                    fi
                                fi
                            fi
                        fi
                    done
                fi

            done <<< "$package_names"
        fi
    # Use pre-categorized files from collect_all_files (performance optimization)
    done < <(tr '\n' '\0' < "$TEMP_DIR/package_files.txt")
}

# Function: check_network_exfiltration
# Purpose: Detect network exfiltration patterns including suspicious domains and IPs
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/network_exfiltration_warnings.txt (temp file)
# Returns: Populates network_exfiltration_warnings.txt with hardcoded IPs and suspicious domains
check_network_exfiltration() {
    local scan_dir=$1

    # Suspicious domains and patterns beyond webhook.site
    local suspicious_domains=(
        "pastebin.com" "hastebin.com" "ix.io" "0x0.st" "transfer.sh"
        "file.io" "anonfiles.com" "mega.nz" "dropbox.com/s/"
        "discord.com/api/webhooks" "telegram.org" "t.me"
        "ngrok.io" "localtunnel.me" "serveo.net"
        "requestbin.com" "webhook.site" "beeceptor.com"
        "pipedream.com" "zapier.com/hooks"
    )

    # Suspicious IP patterns (private IPs used for exfiltration, common C2 patterns)
    local suspicious_ip_patterns=(
        "10\\.0\\." "192\\.168\\." "172\\.(1[6-9]|2[0-9]|3[01])\\."  # Private IPs
        "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}:[0-9]{4,5}"  # IP:Port
    )

    # Scan JavaScript, TypeScript, and JSON files for network patterns
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            # Check for hardcoded IP addresses (simplified)
            # Skip vendor/library files to reduce false positives
            if [[ "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* ]]; then
                if fast_grep_quiet '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' "$file"; then
                    local ips_context
                    ips_context=$(grep -o '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "$file" 2>/dev/null | head -3 | tr '\n' ' ')
                    # Skip common safe IPs
                    if [[ "$ips_context" != *"127.0.0.1"* && "$ips_context" != *"0.0.0.0"* ]]; then
                        # Check if it's a minified file to avoid showing file path details
                        if [[ "$file" == *".min.js"* ]]; then
                            echo "$file:Hardcoded IP addresses found (minified file): $ips_context" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                        else
                            echo "$file:Hardcoded IP addresses found: $ips_context" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                        fi
                    fi
                fi
            fi

            # Check for suspicious domains (but avoid package-lock.json and vendor files to reduce noise)
            if [[ "$file" != *"package-lock.json"* && "$file" != *"yarn.lock"* && "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* ]]; then
                for domain in "${suspicious_domains[@]}"; do
                    # Use word boundaries and URL patterns to avoid false positives like "timeZone" containing "t.me"
                    # Updated pattern to catch property values like hostname: 'webhook.site'
                    if grep -qE "https?://[^[:space:]]*$domain|[[:space:]:,\"\']$domain[[:space:]/\"\',;]" "$file" 2>/dev/null; then
                        # Additional check - make sure it's not just a comment or documentation
                        local suspicious_usage
                        suspicious_usage=$(grep -E "https?://[^[:space:]]*$domain|[[:space:]:,\"\']$domain[[:space:]/\"\',;]" "$file" 2>/dev/null | grep -vE "^[[:space:]]*#|^[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null || true) || true
                        if [[ -n "$suspicious_usage" ]]; then
                            # Get line number and context
                            # FIX: grep -n prefixes lines with "NNN:" so we must account for that in comment filtering
                            local line_info
                            line_info=$(grep -nE "https?://[^[:space:]]*$domain|[[:space:]:,\"\']$domain[[:space:]/\"\',;]" "$file" 2>/dev/null | grep -vE "^[0-9]+:[[:space:]]*#|^[0-9]+:[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null || true) || true
                            local line_num
                            line_num=$(echo "$line_info" | cut -d: -f1 2>/dev/null || true) || true

                            # Check if it's a minified file or has very long lines
                            if [[ "$file" == *".min.js"* ]] || [[ $(echo "$suspicious_usage" | wc -c 2>/dev/null || true) -gt 150 ]]; then
                                # Extract just around the domain
                                local snippet
                                snippet=$(echo "$suspicious_usage" | grep -o ".\{0,20\}$domain.\{0,20\}" 2>/dev/null | head -1 2>/dev/null || true) || true
                                if [[ -n "$line_num" ]]; then
                                    echo "$file:Suspicious domain found: $domain at line $line_num: ...${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                                else
                                    echo "$file:Suspicious domain found: $domain: ...${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                                fi
                            else
                                local snippet
                                snippet=$(echo "$suspicious_usage" | cut -c1-80 2>/dev/null || true) || true
                                if [[ -n "$line_num" ]]; then
                                    echo "$file:Suspicious domain found: $domain at line $line_num: ${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                                else
                                    echo "$file:Suspicious domain found: $domain: ${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                                fi
                            fi
                        fi
                    fi
                done
            fi

            # Check for base64-encoded URLs (skip vendor files to reduce false positives)
            if [[ "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* ]]; then
                if fast_grep_quiet 'atob\(' "$file" || fast_grep_quiet 'base64.*decode' "$file"; then
                    # Get line number and a small snippet
                    local line_num
                    line_num=$(grep -n 'atob\|base64.*decode' "$file" 2>/dev/null | head -1 2>/dev/null | cut -d: -f1 2>/dev/null || true) || true
                    local snippet

                    # For minified files, try to extract just the relevant part
                    if [[ "$file" == *".min.js"* ]] || [[ $(head -1 "$file" 2>/dev/null | wc -c 2>/dev/null || true) -gt 500 ]]; then
                        # Extract a small window around the atob call
                        if [[ -n "$line_num" ]]; then
                            snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | grep -o '.\{0,30\}atob.\{0,30\}' 2>/dev/null | head -1 2>/dev/null || true) || true
                            if [[ -z "$snippet" ]]; then
                                snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | grep -o '.\{0,30\}base64.*decode.\{0,30\}' 2>/dev/null | head -1 2>/dev/null || true) || true
                            fi
                            echo "$file:Base64 decoding at line $line_num: ...${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                        else
                            echo "$file:Base64 decoding detected" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                        fi
                    else
                        snippet=$(sed -n "${line_num}p" "$file" | cut -c1-80)
                        echo "$file:Base64 decoding at line $line_num: ${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                    fi
                fi
            fi

            # Check for DNS-over-HTTPS patterns
            if fast_grep_quiet "dns-query" "$file" || fast_grep_quiet "application/dns-message" "$file"; then
                echo "$file:DNS-over-HTTPS pattern detected" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
            fi

            # Check for WebSocket connections to unusual endpoints
            if fast_grep_quiet "ws://" "$file" || fast_grep_quiet "wss://" "$file"; then
                local ws_endpoints
                ws_endpoints=$(grep -o 'wss\?://[^"'\''[:space:]]*' "$file" 2>/dev/null || true)
                while IFS= read -r endpoint; do
                    [[ -z "$endpoint" ]] && continue
                    # Flag WebSocket connections that don't seem to be localhost or common development
                    if [[ "$endpoint" != *"localhost"* && "$endpoint" != *"127.0.0.1"* ]]; then
                        echo "$file:WebSocket connection to external endpoint: $endpoint" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                    fi
                done <<< "$ws_endpoints"
            fi

            # Check for suspicious HTTP headers
            if fast_grep_quiet "X-Exfiltrate|X-Data-Export|X-Credential" "$file"; then
                echo "$file:Suspicious HTTP headers detected" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
            fi

            # Check for data encoding that might hide exfiltration (but be more selective)
            if [[ "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* && "$file" != *".min.js"* ]]; then
                if fast_grep_quiet "btoa\(" "$file"; then
                    # Check if it's near network operations (simplified to avoid hanging)
                    if grep -C3 "btoa(" "$file" 2>/dev/null | grep -q "\(fetch\|XMLHttpRequest\|axios\)" 2>/dev/null; then
                        # Additional check - make sure it's not just legitimate authentication
                        if ! grep -C3 "btoa(" "$file" 2>/dev/null | grep -q "Authorization:\|Basic \|Bearer " 2>/dev/null; then
                            # Get a small snippet around the btoa usage
                            local line_num
                            line_num=$(grep -n "btoa(" "$file" 2>/dev/null | head -1 2>/dev/null | cut -d: -f1 2>/dev/null || true) || true
                            local snippet
                            if [[ -n "$line_num" ]]; then
                                snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | cut -c1-80 2>/dev/null || true) || true
                                echo "$file:Suspicious base64 encoding near network operation at line $line_num: ${snippet}..." >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                            else
                                echo "$file:Suspicious base64 encoding near network operation" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
                            fi
                        fi
                    fi
                fi
            fi

        fi
    # Use pre-categorized files from collect_all_files (performance optimization)
    done < <(tr '\n' '\0' < "$TEMP_DIR/code_files.txt")
}

# Function: write_log_file
# Purpose: Write all detected file paths to a log file, grouped by severity
# Args: $1 = output file path
# Modifies: Creates/overwrites the specified output file
# Returns: None
write_log_file() {
    local log_file="$1"

    # Start with empty file
    : > "$log_file"

    # HIGH RISK files
    # Note: Using || true on all patterns to prevent pipefail from causing non-zero exit on empty files
    echo "# HIGH" >> "$log_file"
    {
        # Workflow files (just file paths)
        [[ -s "$TEMP_DIR/workflow_files.txt" ]] && cat "$TEMP_DIR/workflow_files.txt" || true

        # Malicious hashes (extract file path before colon)
        [[ -s "$TEMP_DIR/malicious_hashes.txt" ]] && cut -d: -f1 "$TEMP_DIR/malicious_hashes.txt" || true

        # Bun attack files
        [[ -s "$TEMP_DIR/bun_setup_files.txt" ]] && cat "$TEMP_DIR/bun_setup_files.txt" || true
        [[ -s "$TEMP_DIR/bun_environment_files.txt" ]] && cat "$TEMP_DIR/bun_environment_files.txt" || true
        [[ -s "$TEMP_DIR/new_workflow_files.txt" ]] && cat "$TEMP_DIR/new_workflow_files.txt" || true
        [[ -s "$TEMP_DIR/actions_secrets_files.txt" ]] && cat "$TEMP_DIR/actions_secrets_files.txt" || true

        # Discussion workflows, runners (extract file path before colon)
        [[ -s "$TEMP_DIR/discussion_workflows.txt" ]] && cut -d: -f1 "$TEMP_DIR/discussion_workflows.txt" || true
        [[ -s "$TEMP_DIR/github_runners.txt" ]] && cut -d: -f1 "$TEMP_DIR/github_runners.txt" || true

        # Destructive patterns (extract file path before colon)
        [[ -s "$TEMP_DIR/destructive_patterns.txt" ]] && cut -d: -f1 "$TEMP_DIR/destructive_patterns.txt" || true

        # Preinstall patterns, SHA1HULUD runners
        [[ -s "$TEMP_DIR/preinstall_bun_patterns.txt" ]] && cat "$TEMP_DIR/preinstall_bun_patterns.txt" || true
        [[ -s "$TEMP_DIR/github_sha1hulud_runners.txt" ]] && cat "$TEMP_DIR/github_sha1hulud_runners.txt" || true

        # Second coming repos
        [[ -s "$TEMP_DIR/malicious_repo_descriptions.txt" ]] && cat "$TEMP_DIR/malicious_repo_descriptions.txt" || true

        # Compromised packages (extract file path before colon)
        [[ -s "$TEMP_DIR/compromised_found.txt" ]] && cut -d: -f1 "$TEMP_DIR/compromised_found.txt" || true

        # Trufflehog activity (extract file path before colon)
        [[ -s "$TEMP_DIR/trufflehog_activity.txt" ]] && cut -d: -f1 "$TEMP_DIR/trufflehog_activity.txt" || true

        # Shai-Hulud repos
        [[ -s "$TEMP_DIR/shai_hulud_repos.txt" ]] && cat "$TEMP_DIR/shai_hulud_repos.txt" || true

        # High-risk crypto patterns (extract from crypto_patterns.txt)
        if [[ -s "$TEMP_DIR/crypto_patterns.txt" ]]; then
            grep -E "(HIGH RISK|Known attacker wallet)" "$TEMP_DIR/crypto_patterns.txt" 2>/dev/null | cut -d: -f1 || true
        fi
    } | sort -u >> "$log_file"

    # MEDIUM RISK files
    echo "# MEDIUM" >> "$log_file"
    {
        # Suspicious packages (extract file path)
        # Note: Using || true to prevent pipefail from causing non-zero exit on empty files
        [[ -s "$TEMP_DIR/suspicious_found.txt" ]] && cut -d: -f1 "$TEMP_DIR/suspicious_found.txt" || true

        # Suspicious content (extract file path)
        [[ -s "$TEMP_DIR/suspicious_content.txt" ]] && cut -d: -f1 "$TEMP_DIR/suspicious_content.txt" || true

        # Git branches (extract file path)
        [[ -s "$TEMP_DIR/git_branches.txt" ]] && cut -d: -f1 "$TEMP_DIR/git_branches.txt" || true

        # Postinstall hooks
        [[ -s "$TEMP_DIR/postinstall_hooks.txt" ]] && cat "$TEMP_DIR/postinstall_hooks.txt" || true

        # Integrity issues (extract file path)
        [[ -s "$TEMP_DIR/integrity_issues.txt" ]] && cut -d: -f1 "$TEMP_DIR/integrity_issues.txt" || true

        # Typosquatting warnings (extract file path)
        [[ -s "$TEMP_DIR/typosquatting_warnings.txt" ]] && cut -d: -f1 "$TEMP_DIR/typosquatting_warnings.txt" || true

        # Network exfiltration (extract file path)
        [[ -s "$TEMP_DIR/network_exfiltration_warnings.txt" ]] && cut -d: -f1 "$TEMP_DIR/network_exfiltration_warnings.txt" || true

        # Medium-risk crypto patterns
        if [[ -s "$TEMP_DIR/crypto_patterns.txt" ]]; then
            grep -vE "(HIGH RISK|Known attacker wallet|LOW RISK)" "$TEMP_DIR/crypto_patterns.txt" 2>/dev/null | cut -d: -f1 || true
        fi

        # Namespace warnings (extract file path from "... (found in FILE)")
        if [[ -s "$TEMP_DIR/namespace_warnings.txt" ]]; then
            sed -n 's/.*found in \([^)]*\)).*/\1/p' "$TEMP_DIR/namespace_warnings.txt" || true
        fi
    } | sort -u >> "$log_file"

    # LOW RISK files
    echo "# LOW" >> "$log_file"
    {
        # Lockfile safe versions (extract file path)
        [[ -s "$TEMP_DIR/lockfile_safe_versions.txt" ]] && cut -d: -f1 "$TEMP_DIR/lockfile_safe_versions.txt" || true

        # Low-risk crypto patterns
        if [[ -s "$TEMP_DIR/crypto_patterns.txt" ]]; then
            grep "LOW RISK" "$TEMP_DIR/crypto_patterns.txt" 2>/dev/null | cut -d: -f1 || true
        fi

        # Namespace warnings (has full paths in format: /path/to/file:namespace_info)
        [[ -s "$TEMP_DIR/namespace_warnings.txt" ]] && cut -d: -f1 "$TEMP_DIR/namespace_warnings.txt" || true
    } | sort -u >> "$log_file"

    print_status "$GREEN" "Log saved to: $log_file"
}

# Function: generate_report
# Purpose: Generate comprehensive security report with risk stratification and findings
# Args: $1 = paranoid_mode ("true" or "false" for extended checks)
# Modifies: None (reads all global finding arrays)
# Returns: Outputs formatted report to stdout with HIGH/MEDIUM/LOW risk sections
generate_report() {
    local paranoid_mode="$1"
    echo
    print_status "$BLUE" "=============================================="
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "  SHAI-HULUD + PARANOID SECURITY REPORT"
    else
        print_status "$BLUE" "      SHAI-HULUD DETECTION REPORT"
    fi
    print_status "$BLUE" "=============================================="
    echo

    local total_issues=0

    # Reset global risk counters for this scan
    high_risk=0
    medium_risk=0

    # Report malicious workflow files
    if [[ -s "$TEMP_DIR/workflow_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious workflow files detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: Known malicious workflow filename"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/workflow_files.txt"
    fi

    # Report malicious file hashes
    if [[ -s "$TEMP_DIR/malicious_hashes.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Files with known malicious hashes:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local hash="${entry#*:}"
            echo "   - $file_path"
            echo "     Hash: $hash"
            show_file_preview "$file_path" "HIGH RISK: File matches known malicious SHA-256 hash"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/malicious_hashes.txt"
    fi

    # Report November 2025 "Shai-Hulud: The Second Coming" attack files
    if [[ -s "$TEMP_DIR/bun_setup_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: November 2025 Bun attack setup files detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: Fake Bun runtime installation malware (setup_bun.js / bun_installer.js)"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/bun_setup_files.txt"
    fi

    if [[ -s "$TEMP_DIR/bun_environment_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: November 2025 Bun environment payload detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: 10MB+ obfuscated credential harvesting payload (bun_environment.js / environment_source.js)"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/bun_environment_files.txt"
    fi

    if [[ -s "$TEMP_DIR/new_workflow_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: November 2025 malicious workflow files detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: formatter_*.yml - Malicious GitHub Actions workflow"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/new_workflow_files.txt"
    fi

    if [[ -s "$TEMP_DIR/actions_secrets_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Actions secrets exfiltration files detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: actionsSecrets.json - Double Base64 encoded secrets exfiltration"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/actions_secrets_files.txt"
    fi

    if [[ -s "$TEMP_DIR/obfuscated_exfil_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Obfuscated exfiltration files detected (Golden Path variant):"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: Obfuscated JSON - Stolen credentials/secrets staged for exfiltration"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/obfuscated_exfil_files.txt"
    fi

    if [[ -s "$TEMP_DIR/discussion_workflows.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious discussion-triggered workflows detected:"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Discussion workflow - Enables arbitrary command execution via GitHub discussions"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/discussion_workflows.txt"
    fi

    if [[ -s "$TEMP_DIR/github_runners.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious GitHub Actions runners detected:"
        while IFS= read -r line; do
            local dir="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $dir"
            echo "     Reason: $reason"
            show_file_preview "$dir" "HIGH RISK: GitHub Actions runner - Self-hosted backdoor for persistent access"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/github_runners.txt"
    fi

    if [[ -s "$TEMP_DIR/malicious_hashes.txt" ]]; then
        print_status "$RED" "🚨 CRITICAL: Hash-confirmed malicious files detected:"
        print_status "$RED" "    These files match exact SHA256 hashes from security incident reports!"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local hash_info="${line#*:}"
            echo "   - $file"
            echo "     $hash_info"
            show_file_preview "$file" "CRITICAL: Hash-confirmed malicious file - Exact match with known malware"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/malicious_hashes.txt"
    fi

    if [[ -s "$TEMP_DIR/destructive_patterns.txt" ]]; then
        print_status "$RED" "🚨 CRITICAL: Destructive payload patterns detected:"
        print_status "$RED" "    ⚠️  WARNING: These patterns can cause permanent data loss!"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local pattern_info="${line#*:}"
            echo "   - $file"
            echo "     Pattern: $pattern_info"
            show_file_preview "$file" "CRITICAL: Destructive pattern - Can delete user files when credential theft fails"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/destructive_patterns.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION REQUIRED: Quarantine these files and review for data destruction capabilities"
    fi

    if [[ -s "$TEMP_DIR/preinstall_bun_patterns.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Fake Bun preinstall patterns detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: package.json contains malicious preinstall: node setup_bun.js"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/preinstall_bun_patterns.txt"
    fi

    if [[ -s "$TEMP_DIR/github_sha1hulud_runners.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: SHA1HULUD GitHub Actions runners detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: GitHub Actions workflow contains SHA1HULUD runner references"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/github_sha1hulud_runners.txt"
    fi

    if [[ -s "$TEMP_DIR/malicious_repo_descriptions.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious repository descriptions detected:"
        while IFS= read -r repo_entry; do
            local repo_dir="${repo_entry%%:*}"
            local repo_info="${repo_entry#*:}"
            echo "   - $repo_dir"
            [[ -n "$repo_info" && "$repo_info" != "$repo_dir" ]] && echo "     ${repo_info#*: }"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/malicious_repo_descriptions.txt"
    fi

    # Report compromised packages
    if [[ -s "$TEMP_DIR/compromised_found.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Compromised package versions detected:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "HIGH RISK: Contains compromised package version: $package_info"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/compromised_found.txt"
        echo -e "   ${YELLOW}NOTE: These specific package versions are known to be compromised.${NC}"
        echo -e "   ${YELLOW}You should immediately update or remove these packages.${NC}"
        echo
    fi

    # Report suspicious packages
    if [[ -s "$TEMP_DIR/suspicious_found.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious package versions detected:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "MEDIUM RISK: Contains package version that could match compromised version: $package_info"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/suspicious_found.txt"
        echo -e "   ${YELLOW}NOTE: Manual review required to determine if these are malicious.${NC}"
        echo
    fi

    # Report lockfile-safe packages
    if [[ -s "$TEMP_DIR/lockfile_safe_versions.txt" ]]; then
        print_status "$BLUE" "ℹ️  LOW RISK: Packages with safe lockfile versions:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
        done < "$TEMP_DIR/lockfile_safe_versions.txt"
        echo -e "   ${BLUE}NOTE: These package.json ranges could match compromised versions, but lockfiles pin to safe versions.${NC}"
        echo -e "   ${BLUE}Your current installation is safe. Avoid running 'npm update' without reviewing changes.${NC}"
        echo
    fi

    # Report suspicious content
    if [[ -s "$TEMP_DIR/suspicious_content.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious content patterns:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local pattern="${entry#*:}"
            echo "   - Pattern: $pattern"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Contains suspicious pattern: $pattern"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/suspicious_content.txt"
        echo -e "   ${YELLOW}NOTE: Manual review required to determine if these are malicious.${NC}"
        echo
    fi

    # Report cryptocurrency theft patterns
    if [[ -s "$TEMP_DIR/crypto_patterns.txt" ]]; then
        # Create temporary files for categorizing crypto patterns by risk level
        local crypto_high_file="$TEMP_DIR/crypto_high_temp"
        local crypto_medium_file="$TEMP_DIR/crypto_medium_temp"

        while IFS= read -r entry; do
            if [[ "$entry" == *"HIGH RISK"* ]] || [[ "$entry" == *"Known attacker wallet"* ]]; then
                echo "$entry" >> "$crypto_high_file"
            elif [[ "$entry" == *"LOW RISK"* ]]; then
                echo "Crypto pattern: $entry" >> "$TEMP_DIR/low_risk_findings.txt"
            else
                echo "$entry" >> "$crypto_medium_file"
            fi
        done < "$TEMP_DIR/crypto_patterns.txt"

        # Report HIGH RISK crypto patterns
        if [[ -s "$crypto_high_file" ]]; then
            print_status "$RED" "🚨 HIGH RISK: Cryptocurrency theft patterns detected:"
            while IFS= read -r entry; do
                echo "   - ${entry}"
                high_risk=$((high_risk+1))
            done < "$crypto_high_file"
            echo -e "   ${RED}NOTE: These patterns strongly indicate crypto theft malware from the September 8 attack.${NC}"
            echo -e "   ${RED}Immediate investigation and remediation required.${NC}"
            echo
        fi

        # Report MEDIUM RISK crypto patterns
        if [[ -s "$crypto_medium_file" ]]; then
            print_status "$YELLOW" "⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:"
            while IFS= read -r entry; do
                echo "   - ${entry}"
                medium_risk=$((medium_risk+1))
            done < "$crypto_medium_file"
            echo -e "   ${YELLOW}NOTE: These may be legitimate crypto tools or framework code.${NC}"
            echo -e "   ${YELLOW}Manual review recommended to determine if they are malicious.${NC}"
            echo
        fi

        # Clean up temporary categorization files
        [[ -f "$crypto_high_file" ]] && rm -f "$crypto_high_file"
        [[ -f "$crypto_medium_file" ]] && rm -f "$crypto_medium_file"
    fi

    # Report git branches
    if [[ -s "$TEMP_DIR/git_branches.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious git branches:"
        while IFS= read -r entry; do
            local repo_path="${entry%%:*}"
            local branch_info="${entry#*:}"
            echo "   - Repository: $repo_path"
            echo "     $branch_info"
            echo -e "     ${BLUE}┌─ Git Investigation Commands:${NC}"
            echo -e "     ${BLUE}│${NC}  cd '$repo_path'"
            echo -e "     ${BLUE}│${NC}  git log --oneline -10 shai-hulud"
            echo -e "     ${BLUE}│${NC}  git show shai-hulud"
            echo -e "     ${BLUE}│${NC}  git diff main...shai-hulud"
            echo -e "     ${BLUE}└─${NC}"
            echo
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/git_branches.txt"
        echo -e "   ${YELLOW}NOTE: 'shai-hulud' branches may indicate compromise.${NC}"
        echo -e "   ${YELLOW}Use the commands above to investigate each branch.${NC}"
        echo
    fi

    # Report suspicious postinstall hooks
    if [[ -s "$TEMP_DIR/postinstall_hooks.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Suspicious postinstall hooks detected:"
        while IFS= read -r entry; do
            local file_path="${entry%:*}"
            local hook_info="${entry#*:}"
            echo "   - Hook: $hook_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "HIGH RISK: Contains suspicious postinstall hook: $hook_info"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/postinstall_hooks.txt"
        echo -e "   ${YELLOW}NOTE: Postinstall hooks can execute arbitrary code during package installation.${NC}"
        echo -e "   ${YELLOW}Review these hooks carefully for malicious behavior.${NC}"
        echo
    fi

    # Report Trufflehog activity by risk level
    if [[ -s "$TEMP_DIR/trufflehog_activity.txt" ]]; then
        # Create temporary files for categorizing trufflehog findings by risk level
        local trufflehog_high_file="$TEMP_DIR/trufflehog_high_temp"
        local trufflehog_medium_file="$TEMP_DIR/trufflehog_medium_temp"

        # Categorize Trufflehog findings by risk level
        while IFS= read -r entry; do
            local file_path="${entry%%:*}"
            local risk_level="${entry#*:}"
            risk_level="${risk_level%%:*}"
            local activity_info="${entry#*:*:}"

            case "$risk_level" in
                "HIGH")
                    echo "$file_path:$activity_info" >> "$trufflehog_high_file"
                    ;;
                "MEDIUM")
                    echo "$file_path:$activity_info" >> "$trufflehog_medium_file"
                    ;;
                "LOW")
                    echo "Trufflehog pattern: $file_path:$activity_info" >> "$TEMP_DIR/low_risk_findings.txt"
                    ;;
            esac
        done < "$TEMP_DIR/trufflehog_activity.txt"

        # Report HIGH RISK Trufflehog activity
        if [[ -s "$trufflehog_high_file" ]]; then
            print_status "$RED" "🚨 HIGH RISK: Trufflehog/secret scanning activity detected:"
            while IFS= read -r entry; do
                local file_path="${entry%:*}"
                local activity_info="${entry#*:}"
                echo "   - Activity: $activity_info"
                echo "     Found in: $file_path"
                show_file_preview "$file_path" "HIGH RISK: $activity_info"
                high_risk=$((high_risk+1))
            done < "$trufflehog_high_file"
            echo -e "   ${RED}NOTE: These patterns indicate likely malicious credential harvesting.${NC}"
            echo -e "   ${RED}Immediate investigation and remediation required.${NC}"
            echo
        fi

        # Report MEDIUM RISK Trufflehog activity
        if [[ -s "$trufflehog_medium_file" ]]; then
            print_status "$YELLOW" "⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:"
            while IFS= read -r entry; do
                local file_path="${entry%:*}"
                local activity_info="${entry#*:}"
                echo "   - Pattern: $activity_info"
                echo "     Found in: $file_path"
                show_file_preview "$file_path" "MEDIUM RISK: $activity_info"
                medium_risk=$((medium_risk+1))
            done < "$trufflehog_medium_file"
            echo -e "   ${YELLOW}NOTE: These may be legitimate security tools or framework code.${NC}"
            echo -e "   ${YELLOW}Manual review recommended to determine if they are malicious.${NC}"
            echo
        fi

        # Clean up temporary categorization files
        [[ -f "$trufflehog_high_file" ]] && rm -f "$trufflehog_high_file"
        [[ -f "$trufflehog_medium_file" ]] && rm -f "$trufflehog_medium_file"
    fi

    # Report Shai-Hulud repositories
    if [[ -s "$TEMP_DIR/shai_hulud_repos.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Shai-Hulud repositories detected:"
        while IFS= read -r entry; do
            local repo_path="${entry%:*}"
            local repo_info="${entry#*:}"
            echo "   - Repository: $repo_path"
            echo "     $repo_info"
            echo -e "     ${BLUE}┌─ Repository Investigation Commands:${NC}"
            echo -e "     ${BLUE}│${NC}  cd '$repo_path'"
            echo -e "     ${BLUE}│${NC}  git log --oneline -10"
            echo -e "     ${BLUE}│${NC}  git remote -v"
            echo -e "     ${BLUE}│${NC}  ls -la"
            echo -e "     ${BLUE}└─${NC}"
            echo
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/shai_hulud_repos.txt"
        echo -e "   ${YELLOW}NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration.${NC}"
        echo -e "   ${YELLOW}These should be deleted immediately after investigation.${NC}"
        echo
    fi

    # Store namespace warnings as LOW risk findings for later reporting
    if [[ -s "$TEMP_DIR/namespace_warnings.txt" ]]; then
        while IFS= read -r entry; do
            local file_path="${entry%%:*}"
            local namespace_info="${entry#*:}"
            echo "Namespace warning: $namespace_info (found in $(basename "$file_path"))" >> "$TEMP_DIR/low_risk_findings.txt"
        done < "$TEMP_DIR/namespace_warnings.txt"
    fi

    # Report package integrity issues
    if [[ -s "$TEMP_DIR/integrity_issues.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Package integrity issues detected:"
        while IFS= read -r entry; do
            local file_path="${entry%%:*}"
            local issue_info="${entry#*:}"
            echo "   - Issue: $issue_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Package integrity issue: $issue_info"
            medium_risk=$((medium_risk+1))
        done < "$TEMP_DIR/integrity_issues.txt"
        echo -e "   ${YELLOW}NOTE: These issues may indicate tampering with package dependencies.${NC}"
        echo -e "   ${YELLOW}Verify package versions and regenerate lockfiles if necessary.${NC}"
        echo
    fi

    # Report typosquatting warnings (only in paranoid mode)
    if [[ "$paranoid_mode" == "true" && -s "$TEMP_DIR/typosquatting_warnings.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK (PARANOID): Potential typosquatting/homoglyph attacks detected:"
        local typo_count=0
        local total_typo_count
        total_typo_count=$(wc -l < "$TEMP_DIR/typosquatting_warnings.txt")

        while IFS= read -r entry && [[ $typo_count -lt 5 ]]; do
            local file_path="${entry%%:*}"
            local warning_info="${entry#*:}"
            echo "   - Warning: $warning_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Potential typosquatting: $warning_info"
            medium_risk=$((medium_risk+1))
            typo_count=$((typo_count+1))
        done < "$TEMP_DIR/typosquatting_warnings.txt"

        if [[ $total_typo_count -gt 5 ]]; then
            echo "   - ... and $((total_typo_count - 5)) more typosquatting warnings (truncated for brevity)"
        fi
        echo -e "   ${YELLOW}NOTE: These packages may be impersonating legitimate packages.${NC}"
        echo -e "   ${YELLOW}Verify package names carefully and check if they should be legitimate packages.${NC}"
        echo
    fi

    # Report network exfiltration warnings (only in paranoid mode)
    if [[ "$paranoid_mode" == "true" && -s "$TEMP_DIR/network_exfiltration_warnings.txt" ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
        local net_count=0
        local total_net_count
        total_net_count=$(wc -l < "$TEMP_DIR/network_exfiltration_warnings.txt")

        while IFS= read -r entry && [[ $net_count -lt 5 ]]; do
            local file_path="${entry%%:*}"
            local warning_info="${entry#*:}"
            echo "   - Warning: $warning_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Network exfiltration pattern: $warning_info"
            medium_risk=$((medium_risk+1))
            net_count=$((net_count+1))
        done < "$TEMP_DIR/network_exfiltration_warnings.txt"

        if [[ $total_net_count -gt 5 ]]; then
            echo "   - ... and $((total_net_count - 5)) more network warnings (truncated for brevity)"
        fi
        echo -e "   ${YELLOW}NOTE: These patterns may indicate data exfiltration or communication with C2 servers.${NC}"
        echo -e "   ${YELLOW}Review network connections and data flows carefully.${NC}"
        echo
    fi

    total_issues=$((high_risk + medium_risk))
    local low_risk_count=0
    if [[ -s "$TEMP_DIR/low_risk_findings.txt" ]]; then
        low_risk_count=$(wc -l < "$TEMP_DIR/low_risk_findings.txt" 2>/dev/null || echo "0")
    fi

    # Summary
    print_status "$BLUE" "=============================================="
    if [[ $total_issues -eq 0 ]]; then
        print_status "$GREEN" "✅ No indicators of Shai-Hulud compromise detected."
        print_status "$GREEN" "Your system appears clean from this specific attack."

        # Show low risk findings if any (informational only)
        if [[ $low_risk_count -gt 0 ]]; then
            echo
            print_status "$BLUE" "ℹ️  LOW RISK FINDINGS (informational only):"
            while IFS= read -r finding; do
                echo "   - $finding"
            done < "$TEMP_DIR/low_risk_findings.txt"
            echo -e "   ${BLUE}NOTE: These are likely legitimate framework code or dependencies.${NC}"
        fi
    else
        print_status "$RED" "   SUMMARY:"
        print_status "$RED" "   High Risk Issues: $high_risk"
        print_status "$YELLOW" "   Medium Risk Issues: $medium_risk"
        if [[ $low_risk_count -gt 0 ]]; then
            print_status "$BLUE" "   Low Risk (informational): $low_risk_count"
        fi
        print_status "$BLUE" "   Total Critical Issues: $total_issues"
        echo
        print_status "$YELLOW" "⚠️  IMPORTANT:"
        print_status "$YELLOW" "   - High risk issues likely indicate actual compromise"
        print_status "$YELLOW" "   - Medium risk issues require manual investigation"
        print_status "$YELLOW" "   - Low risk issues are likely false positives from legitimate code"
        if [[ "$paranoid_mode" == "true" ]]; then
            print_status "$YELLOW" "   - Issues marked (PARANOID) are general security checks, not Shai-Hulud specific"
        fi
        print_status "$YELLOW" "   - Consider running additional security scans"
        print_status "$YELLOW" "   - Review your npm audit logs and package history"

        if [[ $low_risk_count -gt 0 ]] && [[ $total_issues -lt 5 ]]; then
            echo
            print_status "$BLUE" "ℹ️  LOW RISK FINDINGS (likely false positives):"
            while IFS= read -r finding; do
                echo "   - $finding"
            done < "$TEMP_DIR/low_risk_findings.txt"
            echo -e "   ${BLUE}NOTE: These are typically legitimate framework patterns.${NC}"
        fi
    fi
    print_status "$BLUE" "=============================================="
}

# Function: main
# Purpose: Main entry point - parse arguments, load data, run all checks, generate report
# Args: Command line arguments (--paranoid, --help, --parallelism N, directory_path)
# Modifies: All global arrays via detection functions
# Returns: Exit code 0 for clean, 1 for high-risk findings, 2 for medium-risk findings
main() {
    local paranoid_mode=false
    local scan_dir=""
    local save_log=""

    # Load compromised packages from external file
    load_compromised_packages

    # Create temporary directory for file-based findings storage
    create_temp_dir

    # Set up signal handling for clean termination of background processes
    trap 'cleanup_and_exit' INT TERM

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --paranoid)
                paranoid_mode=true
                ;;
            --check-semver-ranges)
                CHECK_SEMVER_RANGES=true
                ;;
            --help|-h)
                usage
                ;;
            --parallelism)
                re='^[0-9]+$'
                if ! [[ $2 =~ $re ]] ; then
                    echo "${RED}error: Not a number${NC}" >&2;
                    usage
                fi
                PARALLELISM=$2
                shift
                ;;
            --save-log)
                if [[ -z "$2" || "$2" == -* ]]; then
                    echo "${RED}error: --save-log requires a file path${NC}" >&2;
                    usage
                fi
                save_log="$2"
                shift
                ;;
            --use-git-grep)
                if [[ "$HAS_GIT_GREP" != "true" ]]; then
                    echo "${RED}Error: --use-git-grep specified but git is not installed${NC}" >&2
                    exit 1
                fi
                GREP_TOOL="git-grep"
                ;;
            --use-ripgrep)
                if [[ "$HAS_RIPGREP" != "true" ]]; then
                    echo "${RED}Error: --use-ripgrep specified but ripgrep (rg) is not installed${NC}" >&2
                    exit 1
                fi
                GREP_TOOL="ripgrep"
                ;;
            --use-grep)
                GREP_TOOL="grep"
                ;;
            -*)
                echo "Unknown option: $1"
                usage
                ;;
            *)
                if [[ -z "$scan_dir" ]]; then
                    scan_dir="$1"
                else
                    echo "Too many arguments"
                    usage
                fi
                ;;
        esac
        shift
    done

    if [[ -z "$scan_dir" ]]; then
        usage
    fi

    if [[ ! -d "$scan_dir" ]]; then
        print_status "$RED" "Error: Directory '$scan_dir' does not exist."
        exit 1
    fi

    # Convert to absolute path
    if ! scan_dir=$(cd "$scan_dir" && pwd); then
        print_status "$RED" "Error: Unable to access directory '$scan_dir' or convert to absolute path."
        exit 1
    fi

    # Select grep tool (auto-detect or use flag override)
    select_grep_tool

    # Initialize timing
    SCAN_START_TIME=$(date +%s%N 2>/dev/null || echo "$(date +%s)000000000")

    print_status "$GREEN" "Starting Shai-Hulud detection scan..."
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "Scanning directory: $scan_dir (with paranoid mode enabled)"
    else
        print_status "$BLUE" "Scanning directory: $scan_dir"
    fi
    echo

    # Collect all files in a single pass for performance optimization
    print_status "$ORANGE" "[Stage 1/6] Collecting file inventory for analysis"
    collect_all_files "$scan_dir"

    # Show summary of collected files
    local total_files=$(wc -l < "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || echo "0")
    print_stage_complete "File collection ($total_files files)"

    # Run core Shai-Hulud detection checks (sequential for reliability)
    print_status "$ORANGE" "[Stage 2/6] Core detection (workflows, hashes, packages, hooks)"
    check_workflow_files "$scan_dir"
    check_file_hashes "$scan_dir"
    check_packages "$scan_dir"
    check_semver_ranges "$scan_dir"
    check_postinstall_hooks "$scan_dir"
    print_stage_complete "Core detection"

    # Content analysis
    print_status "$ORANGE" "[Stage 3/6] Content analysis (patterns, crypto, trufflehog, git)"
    check_content "$scan_dir"
    check_crypto_theft_patterns "$scan_dir"
    check_trufflehog_activity "$scan_dir"
    check_git_branches "$scan_dir"
    print_stage_complete "Content analysis"

    # Repository analysis
    print_status "$ORANGE" "[Stage 4/6] Repository analysis (repos, integrity, bun, workflows)"
    check_shai_hulud_repos "$scan_dir"
    check_package_integrity "$scan_dir"
    check_bun_attack_files "$scan_dir"
    check_new_workflow_patterns "$scan_dir"
    print_stage_complete "Repository analysis"

    # Advanced pattern detection
    print_status "$ORANGE" "[Stage 5/6] Advanced detection (discussions, runners, destructive)"
    check_discussion_workflows "$scan_dir"
    check_github_runners "$scan_dir"
    check_destructive_patterns "$scan_dir"
    check_preinstall_bun_patterns "$scan_dir"
    print_stage_complete "Advanced detection"

    # Final checks
    print_status "$ORANGE" "[Stage 6/6] Final checks (actions runner, malicious repo descriptions)"
    check_github_actions_runner "$scan_dir"
    check_malicious_repo_descriptions "$scan_dir"
    print_stage_complete "Final checks"

    # Run additional security checks only in paranoid mode
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "[Paranoid] Running extra security checks..."
        check_typosquatting "$scan_dir"
        check_network_exfiltration "$scan_dir"
        print_stage_complete "Paranoid mode checks"
    fi

    # Generate report
    print_status "$BLUE" "Generating report..."
    generate_report "$paranoid_mode"

    # Write log file if requested
    if [[ -n "$save_log" ]]; then
        write_log_file "$save_log"
    fi

    print_stage_complete "Total scan time"

    # Return appropriate exit code based on findings
    if [[ $high_risk -gt 0 ]]; then
        exit 1  # High risk findings detected
    elif [[ $medium_risk -gt 0 ]]; then
        exit 2  # Medium risk findings detected
    else
        exit 0  # Clean - no significant findings
    fi
}

# Run main function with all arguments
main "$@"

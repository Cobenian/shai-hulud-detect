#!/usr/bin/env bash

# Shai-Hulud NPM Supply Chain Attack Detection Script
# Detects indicators of compromise from supply chain attacks between
# September 2025 and February 2026
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

# Bulk-scan mode state (see --bulk). BULK_MODE is set during argument parsing;
# BULK_ROOTS holds the parent directories under which projects are discovered and
# each scanned on its own; BULK_OUTPUT is the directory the aggregate report goes to.
BULK_MODE=false
BULK_ROOTS=()
BULK_OUTPUT=""
# --bulk-list: just print the projects --bulk would scan (one absolute path per line) and exit.
BULK_LIST=false
# How many directory levels below each bulk root to descend looking for projects.
# 1 = treat each immediate subdirectory as a project (flat). Higher values let the
# scanner see through "bucket" folders (e.g. ~/dev/apps/<project>, ~/work/clients/<client>/<project>)
# to the real projects underneath. A directory that already looks like a project is
# always taken whole regardless of depth, so monorepos are never split; the cap only
# limits how far we keep descending through nested bucket folders.
BULK_DEPTH=3
# Non-hidden directory basenames that --bulk project discovery never descends into
# (hidden dirs like .git/.venv/.cache are skipped separately). Leading/trailing spaces
# matter: membership is tested with the pattern *" $name "*.
_BULK_NOISE_DIRS=" node_modules vendor bower_components jspm_packages dist build _build out target coverage venv env virtualenv __pycache__ site-packages Pods Carthage deps obj bin "
# Absolute path of the resolved --bulk-output directory, set early in run_bulk_scan so
# discovery can skip its own output target if --bulk-output happens to be inside one of
# the scan roots. Empty when --bulk is not in use.
BULK_OUTPUT_ABS=""
# Path of a file accumulating stderr from `find` during bulk discovery. We capture
# permission-denied (and any other discovery-time) errors here so we can surface them
# at the end of the run instead of silently dropping them. Empty when --bulk is not in use.
BULK_UNREADABLE_LOG=""

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
    touch "$TEMP_DIR/sandworm_mode_workflows.txt"
    touch "$TEMP_DIR/axios_attack_indicators.txt"
    touch "$TEMP_DIR/mini_shai_hulud_indicators.txt"
    touch "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt"
    touch "$TEMP_DIR/megalodon_indicators.txt"
    touch "$TEMP_DIR/web3_mcp_indicators.txt"
    touch "$TEMP_DIR/polymarket_indicators.txt"
    touch "$TEMP_DIR/sl4x0_indicators.txt"
    touch "$TEMP_DIR/art_template_indicators.txt"
    touch "$TEMP_DIR/durabletask_indicators.txt"
    touch "$TEMP_DIR/pypi_manifests.txt"
    touch "$TEMP_DIR/pypi_lockfiles.txt"
    touch "$TEMP_DIR/pypi_deps_normalized.txt"
    touch "$TEMP_DIR/pypi_compromised_lookup.txt"
    touch "$TEMP_DIR/pypi_matched_deps.txt"
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
    "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c" # May 2026 Mini Shai-Hulud: router_init.js (StepSecurity IOC)
    "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96" # May 2026 Mini Shai-Hulud: tanstack_runner.js (StepSecurity IOC)
    "7c12d8614c624c70d6dd6fc2ee289332474abaa38f70ebe2cdef064923ca3a9b" # May 2026 Mini Shai-Hulud: malicious @tanstack/setup package.json (StepSecurity IOC)
    "a68dd1e6a6e35ec3771e1f94fe796f55dfe65a2b94560516ff4ac189390dfa1c" # May 2026 Mini Shai-Hulud (atool/AntV wave, May 19): 498KB obfuscated Bun bundle payload (SafeDep IOC)
    "d8e3973a0b3c5359d1f53a22491b56bdd31dee13a51c01c7126bc6694584512f" # 2025-2026 art-template hijack: stage-2 jia.js / art.js loader (SafeDep IOC)
    "f31bdd069fe7966ae11be1f78ee5dd44445938856dd1df12379e0e84a6851f5c" # 2025-2026 art-template hijack: stage-4 loader 49554fde7424c31c.js (SafeDep IOC)
    "069ac1dc7f7649b76bc72a11ac700f373804bfd81dab7e561157b703999f44ce" # May 19, 2026 durabletask PyPI: stage-2 rope.pyz payload (SafeDep IOC)
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

# =============================================================================
# Ecosystem abstraction
# =============================================================================
# The detector supports multiple package ecosystems. Each ecosystem declares:
#   - Marker files (presence indicates the ecosystem is in use)
#   - Path patterns to exclude when looking for markers (e.g. node_modules)
# detect_ecosystems() populates ACTIVE_ECOSYSTEMS based on the scan tree.
# Override via --ecosystem=<list> on the command line.
declare -A ECOSYSTEM_MARKERS=(
    ["npm"]="package.json|package-lock.json|yarn.lock|pnpm-lock.yaml"
    ["pypi"]="pyproject.toml|requirements.txt|requirements-dev.txt|requirements-prod.txt|Pipfile|Pipfile.lock|poetry.lock|uv.lock|setup.py|setup.cfg"
)
declare -A ECOSYSTEM_EXCLUDE_PATHS=(
    ["npm"]="node_modules"
    ["pypi"]="node_modules|\\.venv|/venv/|\\.tox|site-packages"
)
declare -a SUPPORTED_ECOSYSTEMS=("npm" "pypi")
declare -a ACTIVE_ECOSYSTEMS=()
ECOSYSTEM_OVERRIDE=""  # set by --ecosystem flag; empty = auto-detect

# Dispatch table: ecosystem -> space-separated list of check function names.
# This is the extension point for adding new ecosystems (hex, go, cargo, gem...).
# To add a new ecosystem:
#   1. Add a marker pattern to ECOSYSTEM_MARKERS
#   2. Add an exclude-paths pattern to ECOSYSTEM_EXCLUDE_PATHS
#   3. Add the ecosystem name to SUPPORTED_ECOSYSTEMS
#   4. Write a parser + check_<eco>_packages function
#   5. Add a row here mapping the ecosystem to its check function(s)
#   6. Teach load_compromised_packages to recognize the new "<eco>:" prefix
#   7. Extend collect_all_files with the relevant manifest filenames
# Nothing in main() needs to change - the dispatcher walks ACTIVE_ECOSYSTEMS
# and invokes whatever functions this table lists for each active ecosystem.
declare -A ECOSYSTEM_CHECK_FUNCTIONS=(
    ["npm"]="check_packages check_semver_ranges"
    ["pypi"]="check_pypi_packages"
)

# Function: ecosystem_active
# Purpose: O(1) check whether an ecosystem is in the active set
# Args: $1 = ecosystem name (e.g. "npm" or "pypi")
# Returns: 0 if active, 1 otherwise
ecosystem_active() {
    local target="$1"
    local eco
    for eco in "${ACTIVE_ECOSYSTEMS[@]}"; do
        [[ "$eco" == "$target" ]] && return 0
    done
    return 1
}

# Function: detect_ecosystems
# Purpose: Populate ACTIVE_ECOSYSTEMS based on marker files in the scan tree,
#          unless overridden by --ecosystem flag.
# Args: None (consumes ECOSYSTEM_OVERRIDE and $TEMP_DIR/all_files_raw.txt)
# Modifies: ACTIVE_ECOSYSTEMS
detect_ecosystems() {
    ACTIVE_ECOSYSTEMS=()

    if [[ -n "$ECOSYSTEM_OVERRIDE" ]]; then
        if [[ "$ECOSYSTEM_OVERRIDE" == "all" ]]; then
            ACTIVE_ECOSYSTEMS=("${SUPPORTED_ECOSYSTEMS[@]}")
            return 0
        fi
        local IFS=','
        local eco
        for eco in $ECOSYSTEM_OVERRIDE; do
            eco="${eco// /}"
            # Validate
            local valid=false
            local s
            for s in "${SUPPORTED_ECOSYSTEMS[@]}"; do
                [[ "$eco" == "$s" ]] && valid=true
            done
            if [[ "$valid" == "true" ]]; then
                ACTIVE_ECOSYSTEMS+=("$eco")
            else
                print_status "$RED" "Error: unknown ecosystem '$eco' in --ecosystem. Supported: ${SUPPORTED_ECOSYSTEMS[*]}, all"
                exit 1
            fi
        done
        return 0
    fi

    # Auto-detect from marker files in the file inventory
    local eco markers exclude
    for eco in "${SUPPORTED_ECOSYSTEMS[@]}"; do
        markers="${ECOSYSTEM_MARKERS[$eco]}"
        exclude="${ECOSYSTEM_EXCLUDE_PATHS[$eco]}"
        # Match any line whose basename is one of the marker files, excluding
        # paths that contain ecosystem-irrelevant directories.
        if grep -E "/($markers)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null | \
           grep -vE "/($exclude)/" 2>/dev/null | head -n1 | grep -q .; then
            ACTIVE_ECOSYSTEMS+=("$eco")
        fi
    done
}

# Function: ecosystem_banner
# Purpose: Print a one-line summary of detected ecosystems and their marker counts
# Args: None
ecosystem_banner() {
    if [[ ${#ACTIVE_ECOSYSTEMS[@]} -eq 0 ]]; then
        print_status "$YELLOW" "   No package-manifest markers detected. Content-pattern checks will still run."
        return 0
    fi
    local eco markers exclude count summary=""
    for eco in "${ACTIVE_ECOSYSTEMS[@]}"; do
        markers="${ECOSYSTEM_MARKERS[$eco]}"
        exclude="${ECOSYSTEM_EXCLUDE_PATHS[$eco]}"
        count=$(grep -E "/($markers)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null | \
                grep -vE "/($exclude)/" 2>/dev/null | wc -l | tr -d ' ')
        if [[ -z "$summary" ]]; then
            summary="$eco ($count marker file(s))"
        else
            summary="$summary, $eco ($count marker file(s))"
        fi
    done
    print_status "$GREEN" "   Detected ecosystems: $summary"
}

# Associative arrays for O(1) lookups (Bash 5.0+ feature)
declare -A COMPROMISED_PACKAGES_MAP    # "ecosystem:package:version" -> 1
declare -A COMPROMISED_NAMESPACES_MAP  # "@namespace" -> 1 (npm only)
declare -A COMPROMISED_VERSIONS_BY_NAME # "package_name" -> "version1 version2 ..." (npm only, for semver range checking)

# Function: load_compromised_packages
# Purpose: Load compromised package database from external file or fallback list
# Args: None (reads from compromised-packages.txt in script directory)
# Modifies: COMPROMISED_PACKAGES_MAP, COMPROMISED_VERSIONS_BY_NAME (global associative arrays)
# Returns: Populates COMPROMISED_PACKAGES_MAP for O(1) lookups, COMPROMISED_VERSIONS_BY_NAME for semver range checking
load_compromised_packages() {
    local packages_file="$SCRIPT_DIR/compromised-packages.txt"
    local count=0

    # Entries may be ecosystem-prefixed ("pypi:name:version", "npm:name:version")
    # or bare ("name:version"), in which case they default to npm. The internal
    # map key is always "ecosystem:name:version" for unambiguous lookups.
    local pypi_count=0 npm_count=0

    if [[ -f "$packages_file" ]]; then
        local -a raw_lines
        mapfile -t raw_lines < <(
            grep -v '^[[:space:]]*#' "$packages_file" | \
            grep -vE '^[[:space:]]*$' | \
            tr -d $'\r'
        )

        local line eco pkg_name pkg_version key
        for line in "${raw_lines[@]}"; do
            if [[ "$line" == pypi:* ]]; then
                eco="pypi"
                pkg_name="${line#pypi:}"
                pkg_name="${pkg_name%:*}"
                pkg_version="${line##*:}"
                # Validate version shape (PyPI versions vary widely; accept any non-empty)
                [[ -z "$pkg_version" || "$pkg_version" == "$line" ]] && continue
                key="pypi:$pkg_name:$pkg_version"
                COMPROMISED_PACKAGES_MAP["$key"]=1
                ((pypi_count++)) || true
                ((count++)) || true
            elif [[ "$line" == npm:* ]]; then
                eco="npm"
                pkg_name="${line#npm:}"
                pkg_name="${pkg_name%:*}"
                pkg_version="${line##*:}"
                [[ -z "$pkg_version" || "$pkg_version" == "$line" ]] && continue
                # Require semver-ish version for npm
                [[ "$pkg_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]] || continue
                key="npm:$pkg_name:$pkg_version"
                COMPROMISED_PACKAGES_MAP["$key"]=1
                COMPROMISED_VERSIONS_BY_NAME["$pkg_name"]+="$pkg_version "
                ((npm_count++)) || true
                ((count++)) || true
            elif [[ "$line" =~ ^[@a-zA-Z][^:]+:[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                # Bare entry -> npm
                pkg_name="${line%:*}"
                pkg_version="${line#*:}"
                key="npm:$pkg_name:$pkg_version"
                COMPROMISED_PACKAGES_MAP["$key"]=1
                COMPROMISED_VERSIONS_BY_NAME["$pkg_name"]+="$pkg_version "
                ((npm_count++)) || true
                ((count++)) || true
            fi
        done

        print_status "$BLUE" "📦 Loaded $count compromised packages from $packages_file (npm: $npm_count, pypi: $pypi_count)"
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
        local pkg
        for pkg in "${fallback_packages[@]}"; do
            COMPROMISED_PACKAGES_MAP["npm:$pkg"]=1
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
#       $2 = ecosystem (default: npm)
# Returns: 0 if compromised, 1 if not
is_compromised_package() {
    local eco="${2:-npm}"
    [[ -v COMPROMISED_PACKAGES_MAP["$eco:$1"] ]]
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
    echo "  --check-host       Also scan host paths (\$HOME) for May 2026 Mini Shai-Hulud"
    echo "                     dead-man's-switch artifacts (gh-token-monitor service/plist/token)."
    echo "                     Off by default. CRITICAL: revoking a monitored GitHub token while"
    echo "                     the service is active is designed to trigger a destructive wipe;"
    echo "                     stop and remove the service before rotating credentials."
    echo "  --ecosystem LIST   Restrict ecosystem-specific checks to a comma-separated list."
    echo "                     Supported values: npm, pypi, all (default: auto-detect from"
    echo "                     marker files). Content-pattern checks always run regardless."
    echo "  --parallelism N    Set the number of threads to use for parallelized steps (current: ${PARALLELISM})"
    echo "  --save-log FILE    Save all detected file paths to FILE, grouped by severity"
    echo "                     Output format: # HIGH / # MEDIUM / # LOW headers with file paths"
    echo ""
    echo "BULK MODE (scan many projects in one run):"
    echo "  --bulk             Treat the positional argument(s) as PARENT directories and scan"
    echo "                     every project found underneath as its own unit, writing per-project"
    echo "                     logs plus an aggregate Markdown report. Project discovery descends"
    echo "                     through 'bucket' folders (e.g. ~/dev/apps/<project>, clients/<c>/<p>)"
    echo "                     down to directories that look like a project (a .git dir or a"
    echo "                     package.json / pyproject.toml / requirements*.txt / Cargo.toml /"
    echo "                     go.mod / Gemfile / composer.json ...). A monorepo is scanned as one"
    echo "                     unit (discovery stops at the first project marker). Folders with no"
    echo "                     projects under them are scanned as-is. node_modules/.git/dist/build/"
    echo "                     .venv/... and hidden directories are not descended into. Multiple"
    echo "                     parent directories may be given; the detector's own repo is skipped."
    echo "                     --paranoid / --check-semver-ranges / --ecosystem / --parallelism"
    echo "                     are passed through to every per-project scan."
    echo "  --bulk-depth N     How many levels below each --bulk parent to descend looking for"
    echo "                     projects (default: ${BULK_DEPTH}). Use 1 for the old flat behaviour"
    echo "                     (each immediate subdirectory is one project)."
    echo "  --bulk-list        With --bulk: print the projects that would be scanned (one absolute"
    echo "                     path per line) and exit, without scanning or writing a report."
    echo "  --bulk-output DIR  Directory for the bulk report (default: ./shai-hulud-bulk-report-<timestamp>)."
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
    echo "  $0 --bulk ~/dev ~/Desktop/Projects          # Scan every project found under both dirs"
    echo "  $0 --bulk --paranoid --bulk-output audit ~/dev   # Bulk + paranoid, custom out dir"
    echo "  $0 --bulk --bulk-depth 1 ~/projects         # Flat: one scan per immediate subdir"
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
            -name "formatter_*.yml" -o \
            -name "router_init.js" -o -name "tanstack_runner.js" -o \
            -name "gh-token-monitor.sh" -o -name "com.user.gh-token-monitor.plist" -o \
            -name "gh-token-monitor.service" -o \
            -name "kitty-monitor.sh" -o -name "com.user.kitty-monitor.plist" -o \
            -name "kitty-monitor.service" -o -name "cat.py" -o \
            -name "b02e30.js" -o -name "6ad264.js" -o \
            -name "49554fde7424c31c.js" -o -name "rope.pyz" -o \
            -name "pgmonitor.py" -o -name "pgsql-monitor.service" -o \
            -name "template-web.js" -o \
            -name "pyproject.toml" -o -name "Pipfile" -o -name "Pipfile.lock" -o \
            -name "poetry.lock" -o -name "uv.lock" -o \
            -name "requirements.txt" -o -name "requirements-*.txt" -o -name "*-requirements.txt" -o \
            -name "setup.py" -o -name "setup.cfg" \
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
    grep -E "(router_init|tanstack_runner)\.js$" "$TEMP_DIR/all_files_raw.txt" > "$TEMP_DIR/mini_shai_hulud_artifact_files.txt" 2>/dev/null || touch "$TEMP_DIR/mini_shai_hulud_artifact_files.txt"

    # PyPI manifests/lockfiles. Exclude virtualenv / site-packages / node_modules trees
    # so we don't trip over copies of dependency manifests bundled inside installed packages.
    grep -E "/(pyproject\.toml|Pipfile|setup\.py|setup\.cfg|requirements[^/]*\.txt|[^/]*-requirements\.txt)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null | \
        grep -vE "/(node_modules|\.venv|venv|\.tox|site-packages)/" > "$TEMP_DIR/pypi_manifests.txt" || touch "$TEMP_DIR/pypi_manifests.txt"
    grep -E "/(poetry\.lock|uv\.lock|Pipfile\.lock)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null | \
        grep -vE "/(node_modules|\.venv|venv|\.tox|site-packages)/" > "$TEMP_DIR/pypi_lockfiles.txt" || touch "$TEMP_DIR/pypi_lockfiles.txt"

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

# Function: check_sandworm_mode_workflows
# Purpose: Detect February 2026 SANDWORM_MODE workflow propagation indicators
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/sandworm_mode_workflows.txt (temp file)
# Returns: Populates sandworm_mode_workflows.txt with paths to suspicious workflows
check_sandworm_mode_workflows() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for SANDWORM_MODE workflow IOCs..."

    # Create file list for valid workflow files
    while IFS= read -r file; do
        [[ -f "$file" ]] && echo "$file"
    done < "$TEMP_DIR/github_workflows.txt" > "$TEMP_DIR/valid_sandworm_workflows.txt"

    # Check if we have any workflow files
    if [[ ! -s "$TEMP_DIR/valid_sandworm_workflows.txt" ]]; then
        return 0
    fi

    # IOC 1: Malicious action usage
    tr '\n' '\0' < "$TEMP_DIR/valid_sandworm_workflows.txt" | \
        xargs -0 -I {} grep -l -E "uses:[[:space:]]*ci-quality/code-quality-check@v1|ci-quality/code-quality-check@v1" {} 2>/dev/null | \
        while IFS= read -r file; do
            echo "$file:SANDWORM_MODE malicious action usage (ci-quality/code-quality-check@v1)" >> "$TEMP_DIR/sandworm_mode_workflows.txt"
        done || true

    # IOC 2: Threat actor aliases and propagation references in workflow files
    tr '\n' '\0' < "$TEMP_DIR/valid_sandworm_workflows.txt" | \
        xargs -0 -I {} grep -li -E "official334|javaorg|dist/propagate-core\.js|official334@proton|javaorg@proton" {} 2>/dev/null | \
        while IFS= read -r file; do
            echo "$file:SANDWORM_MODE threat-actor IOC reference in workflow" >> "$TEMP_DIR/sandworm_mode_workflows.txt"
        done || true

    # IOC 3: Injected quality workflow file with campaign references
    while IFS= read -r file; do
        local workflow_file
        workflow_file=$(basename "$file")
        if [[ "$workflow_file" == "quality.yml" || "$workflow_file" == "quality.yaml" ]]; then
            if grep -qiE "ci-quality/code-quality-check|official334|javaorg|dist/propagate-core\.js" "$file" 2>/dev/null; then
                echo "$file:SANDWORM_MODE injected workflow pattern (quality.yml + campaign IOC)" >> "$TEMP_DIR/sandworm_mode_workflows.txt"
            fi
        fi
    done < "$TEMP_DIR/valid_sandworm_workflows.txt"

    # Deduplicate by full finding line
    if [[ -s "$TEMP_DIR/sandworm_mode_workflows.txt" ]]; then
        sort -u "$TEMP_DIR/sandworm_mode_workflows.txt" -o "$TEMP_DIR/sandworm_mode_workflows.txt"
    fi
}

# Function: check_axios_attack_indicators
# Purpose: Detect March 2026 axios supply chain attack indicators (C2, XOR key, plain-crypto-js, artifacts)
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/axios_attack_indicators.txt (temp file)
# Returns: Populates axios_attack_indicators.txt with paths to suspicious files
check_axios_attack_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for axios supply chain attack IOCs..."

    # IOC 1: C2 domain and IP
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "sfrclak.com" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack C2 domain (sfrclak.com)" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
        fast_grep_files_fixed "sfrclak[.]com" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack C2 domain (sfrclak[.]com defanged)" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
        fast_grep_files_fixed "142.11.206.73" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack C2 IP (142.11.206.73)" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
    fi

    # IOC 2: XOR key used in obfuscated dropper
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "OrDeR_7077" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack XOR key (OrDeR_7077)" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
    fi

    # IOC 3: Distinctive User-Agent string from RAT beaconing
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "msie 8.0; windows nt 5.1; trident/4.0" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack RAT User-Agent string detected" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
    fi

    # IOC 4: plain-crypto-js as a dependency (any version - entirely an attack package)
    if [[ -s "$TEMP_DIR/package_files.txt" ]]; then
        fast_grep_files_fixed "plain-crypto-js" < "$TEMP_DIR/package_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Malicious dependency plain-crypto-js (axios supply chain attack)" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
    fi

    # IOC 5: Filesystem artifacts (RAT persistence)
    local -a artifact_names=("com.apple.act.mond" "ld.py")
    local artifact
    for artifact in "${artifact_names[@]}"; do
        find "$scan_dir" -name "$artifact" -type f 2>/dev/null | while IFS= read -r file; do
            echo "$file:Axios attack filesystem artifact ($artifact)" >> "$TEMP_DIR/axios_attack_indicators.txt"
        done
    done

    # IOC 6: Attacker account references in config/code
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_i "ifstap@proton\.me|nrwise@proton\.me" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Axios attack threat actor email reference" >> "$TEMP_DIR/axios_attack_indicators.txt"
            done
    fi

    # Deduplicate
    if [[ -s "$TEMP_DIR/axios_attack_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/axios_attack_indicators.txt" -o "$TEMP_DIR/axios_attack_indicators.txt"
    fi
}

# Function: check_mini_shai_hulud_indicators
# Purpose: Detect May 2026 Mini Shai-Hulud "TheBeautifulSandsOfTime" TanStack campaign
#          (router_init.js / tanstack_runner.js payloads, dead-man's-switch, C2 domains,
#          orphan-commit optionalDependencies, wipe-threat token description)
# Args: $1 = scan_dir (directory to scan)
#       $2 = check_host ("true"/"false") - scan host paths for dead-man's-switch persistence
# Modifies: $TEMP_DIR/mini_shai_hulud_indicators.txt, mini_shai_hulud_host_artifacts.txt
check_mini_shai_hulud_indicators() {
    local scan_dir=$1
    local check_host=${2:-false}
    print_status "$BLUE" "   Checking for Mini Shai-Hulud IOCs (May 11 TanStack + May 19 atool/AntV waves)..."

    # IOC 1: Payload file names anywhere in the tree (router_init.js, tanstack_runner.js
    # from May 11; index.js can't be flagged generically since legit packages use it,
    # but its presence is caught structurally via the preinstall hook in IOC 7).
    if [[ -s "$TEMP_DIR/mini_shai_hulud_artifact_files.txt" ]]; then
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                local basename_file
                basename_file=$(basename "$file")
                echo "$file:Mini Shai-Hulud payload file present ($basename_file)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            fi
        done < "$TEMP_DIR/mini_shai_hulud_artifact_files.txt"
    fi

    # IOC 2: Wipe-threat token description string (DO NOT REVOKE - triggers wipe routine)
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud wipe-threat token description string" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
    fi

    # IOC 3: Marker / beacon strings left on attacker-created exfil repos.
    # May 11: "A Mini Shai-Hulud has Appeared" + two specific repo names.
    # May 19: "niagA oG eW ereH :duluH-iahS" (character-reversed "Shai-Hulud: Here We Go Again"),
    #         stamped on every exfil repo created by the wave.
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "A Mini Shai-Hulud has Appeared" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud marker repo description string (May 11 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        fast_grep_files_fixed "siridar-ghola-567" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud marker repo name (siridar-ghola-567)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        fast_grep_files_fixed "tleilaxu-ornithopter-43" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud marker repo name (tleilaxu-ornithopter-43)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        fast_grep_files_fixed "niagA oG eW ereH :duluH-iahS" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud beacon string from exfil repos (May 19 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
    fi

    # IOC 4: C2 domains observed in the attack (May 11 + May 19).
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        local c2_domain
        for c2_domain in \
            "api.masscan.cloud" "git-tanstack.com" "filev2.getsession.org" "seed1.getsession.org" \
            "t.m-kosche.com"
        do
            fast_grep_files_fixed "$c2_domain" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Mini Shai-Hulud C2 domain ($c2_domain)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
                done
        done
    fi

    # IOC 5: Threat actor account references and malicious commit SHAs.
    # May 11: voicproducoes account + one antv-router commit SHA.
    # May 19: atool account (npm publisher) + three antvis/G2 orphan commit SHAs + forged-author email.
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "voicproducoes" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud threat actor reference (voicproducoes, May 11 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        # atool: match in JSON publisher context (quoted) to avoid false-positive on bare "atool" text.
        fast_grep_files_fixed '"_npmUser":{"name":"atool"' < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud threat actor (atool, May 19 wave - npm publisher metadata)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        # Forged author email used on impostor antvis/G2 commits.
        fast_grep_files_fixed "huiyu.zjt@ant.com" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud forged-author email (huiyu.zjt@ant.com, May 19 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        # Malicious commit SHAs across both waves.
        local bad_sha
        for bad_sha in \
            "79ac49eedf774dd4b0cfa308722bc463cfe5885c" \
            "1916faa365f2788b6e193514872d51a242876569" \
            "7cb42f57561c321ecb09b4552802ae0ac55b3a7a" \
            "dc3d62a2181beb9f326952a2d212900c94f2e13d"
        do
            fast_grep_files_fixed "$bad_sha" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Mini Shai-Hulud malicious orphan-commit SHA reference ($bad_sha)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
                done
        done
        # firedalazer: GitHub commit-search dead-drop keyword (May 19 wave). The payload polls
        # commits matching this exact word to receive RSA-PSS signed C2 commands.
        fast_grep_files_fixed "firedalazer" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud C2 dead-drop keyword (firedalazer, May 19 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
    fi

    # IOC 6: Campaign-specific cryptographic constants (May 11 wave).
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        fast_grep_files_fixed "0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud PBKDF2 master key constant" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        fast_grep_files_fixed "svksjrhjkcejg" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud PBKDF2 salt constant" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
    fi

    # IOC 7: Structural package.json signals - malicious optionalDependencies / prepare-or-preinstall script.
    if [[ -s "$TEMP_DIR/package_files.txt" ]]; then
        # May 11: orphan-commit github: ref to the attacker's tanstack/router fork.
        fast_grep_files_fixed "github:tanstack/router#79ac49ee" < "$TEMP_DIR/package_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud malicious optionalDependencies (May 11: tanstack/router orphan commit)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        # May 19: orphan-commit github: refs to antvis/G2 (any of the three known SHAs).
        local antvis_sha
        for antvis_sha in "1916faa365" "7cb42f5756" "dc3d62a218"; do
            fast_grep_files_fixed "github:antvis/G2#$antvis_sha" < "$TEMP_DIR/package_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Mini Shai-Hulud malicious optionalDependencies (May 19: antvis/G2 orphan commit $antvis_sha...)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
                done
        done
        # Prepare/preinstall script that invokes the payload (May 11: tanstack_runner.js;
        # May 19: bun run index.js).
        fast_grep_files_fixed "bun run tanstack_runner.js" < "$TEMP_DIR/package_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud prepare script invokes tanstack_runner.js (May 11 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
        # bun run index.js as a preinstall is a strong signal in non-Bun-targeted projects.
        # Match it as a preinstall script value specifically; "scripts": { "preinstall": "bun run index.js" }.
        if fast_grep_files_fixed '"preinstall": "bun run index.js"' < "$TEMP_DIR/package_files.txt" > "$TEMP_DIR/_mini_sh_preinstall_bun.tmp"; then
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud preinstall script invokes bun run index.js (May 19 wave install vector)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done < "$TEMP_DIR/_mini_sh_preinstall_bun.tmp"
        fi
        rm -f "$TEMP_DIR/_mini_sh_preinstall_bun.tmp"
        # The synthetic @tanstack/setup package name (attacker-created, May 11 wave).
        fast_grep_files_fixed "@tanstack/setup" < "$TEMP_DIR/package_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Mini Shai-Hulud reference to fake @tanstack/setup package (May 11 wave)" >> "$TEMP_DIR/mini_shai_hulud_indicators.txt"
            done
    fi

    # IOC 8: Dead-man's-switch host-level persistence (opt-in via --check-host).
    # Both waves install a polling daemon that wipes the host if its monitored token
    # is revoked. May 11 wave: "gh-token-monitor". May 19 wave: "kitty-monitor".
    # CRITICAL: Revoking the monitored token is designed to TRIGGER A WIPE — do not
    # rotate credentials until the service is stopped and removed.
    if [[ "$check_host" == "true" ]]; then
        print_status "$BLUE" "   Checking host paths for dead-man's-switch artifacts..."
        local host_paths=(
            # May 11 wave (gh-token-monitor)
            "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
            "$HOME/.config/systemd/user/gh-token-monitor.service"
            "$HOME/.local/bin/gh-token-monitor.sh"
            "$HOME/.config/gh-token-monitor/token"
            "$HOME/.config/gh-token-monitor"
            # May 19 wave (kitty-monitor + dead-drop fetcher)
            "$HOME/Library/LaunchAgents/com.user.kitty-monitor.plist"
            "$HOME/.config/systemd/user/kitty-monitor.service"
            "$HOME/.local/bin/kitty-monitor.sh"
            "$HOME/.config/kitty-monitor/token"
            "$HOME/.config/kitty-monitor"
            "$HOME/.local/share/kitty/cat.py"
            "/var/tmp/.gh_update_state"
        )
        local host_path
        for host_path in "${host_paths[@]}"; do
            if [[ -e "$host_path" ]]; then
                local variant="gh-token-monitor"
                [[ "$host_path" == *"kitty"* || "$host_path" == *"gh_update_state"* ]] && variant="kitty-monitor (May 19 wave)"
                echo "$host_path:Mini Shai-Hulud dead-man's-switch artifact ($variant)" >> "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt"
            fi
        done
    fi

    # Also catch dead-man's-switch artifacts that happen to live inside the scan dir
    # (e.g. a backup of a compromised home directory, or a staged install kit).
    # Covers both the May 11 (gh-token-monitor) and May 19 (kitty-monitor + cat.py) variants.
    local in_tree_artifact
    while IFS= read -r in_tree_artifact; do
        if [[ -f "$in_tree_artifact" ]]; then
            echo "$in_tree_artifact:Mini Shai-Hulud dead-man's-switch artifact in scan tree" >> "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt"
        fi
    done < <(grep -E "(gh-token-monitor\.(sh|service)|com\.user\.gh-token-monitor\.plist|kitty-monitor\.(sh|service)|com\.user\.kitty-monitor\.plist|/kitty/cat\.py)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || true)

    # Deduplicate both result files
    if [[ -s "$TEMP_DIR/mini_shai_hulud_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/mini_shai_hulud_indicators.txt" -o "$TEMP_DIR/mini_shai_hulud_indicators.txt"
    fi
    if [[ -s "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt" ]]; then
        sort -u "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt" -o "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt"
    fi
}

# =============================================================================
# PyPI ecosystem support
# =============================================================================
# Pure-bash/awk parsers for Python manifests and lockfiles. Each parser reads
# a single file and emits one normalized "name:version" line per exact-pinned
# dependency it finds. Names are PEP 503 normalized (lowercase, runs of
# [-_.] collapsed to a single hyphen). Range specifiers (>=, ^, ~=, etc.)
# are intentionally ignored in manifests; lockfiles always have exact versions
# so transitive compromises are caught there.

# Function: parse_requirements_txt
# Args: stdin = requirements.txt contents
# Output: normalized name:version lines for "name==version" pins
parse_requirements_txt() {
    awk '
        function normalize(n,    out) {
            out = tolower(n)
            gsub(/[._]+/, "-", out)
            return out
        }
        {
            # Strip inline comment, trim whitespace
            sub(/[ \t]+#.*$/, "")
            gsub(/^[ \t]+|[ \t]+$/, "")
            if (length($0) == 0) next
            if (substr($0,1,1) == "#") next
            if (substr($0,1,1) == "-") next            # options, -r, -e
            if ($0 ~ /^https?:/ || $0 ~ /^git\+/ || $0 ~ /^file:/) next
            # Strip env markers
            sub(/[ \t]*;.*$/, "")
            # Strip extras: name[a,b]==1.0 -> name==1.0
            sub(/\[[^]]*\]/, "")
            gsub(/[ \t]/, "")
            # Match name==version pin (allow trailing comma-separated specifiers but
            # only take the == component)
            if (match($0, /^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!*-]+/)) {
                pair = substr($0, RSTART, RLENGTH)
                eq = index(pair, "==")
                name = substr(pair, 1, eq - 1)
                ver  = substr(pair, eq + 2)
                # PEP 440 local-version segment (e.g. 1.0+local) - strip + for matching
                # against PyPI canonical versions (best-effort)
                printf("%s:%s\n", normalize(name), ver)
            }
        }
    '
}

# Function: parse_pyproject_toml
# Args: $1 = path to pyproject.toml
# Output: normalized name:version lines for PEP 621 + Poetry exact pins
parse_pyproject_toml() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
        function normalize(n,    out) {
            out = tolower(n)
            gsub(/[._]+/, "-", out)
            return out
        }
        function process_pep508_array_chunk(s,    pos, dep, eq, name, ver) {
            # Pull out every "..."-quoted dep specifier on this line
            while (1) {
                pos = match(s, /"[^"]+"/)
                if (pos == 0) break
                dep = substr(s, pos + 1, RLENGTH - 2)
                s = substr(s, pos + RLENGTH)
                # Strip extras and env markers, collapse whitespace
                sub(/\[[^]]*\]/, "", dep)
                sub(/[ \t]*;.*$/, "", dep)
                gsub(/[ \t]/, "", dep)
                # Match exact pin name==version
                if (match(dep, /^[A-Za-z0-9_.-]+==[A-Za-z0-9_.+!*-]+$/)) {
                    eq = index(dep, "==")
                    name = substr(dep, 1, eq - 1)
                    ver = substr(dep, eq + 2)
                    printf("%s:%s\n", normalize(name), ver)
                }
            }
        }
        BEGIN {
            section = ""
            in_pep621_deps_array = 0
            in_poetry_deps = 0
        }
        # Track section headers (TOML [section.path])
        /^\[/ {
            line = $0
            sub(/[ \t]+#.*$/, "", line)
            sub(/[ \t]+$/, "", line)
            section = line
            in_pep621_deps_array = 0
            in_poetry_deps = 0
            if (section ~ /^\[tool\.poetry\.dependencies\]$/ ||
                section ~ /^\[tool\.poetry\.dev-dependencies\]$/ ||
                section ~ /^\[tool\.poetry\.group\.[^.]+\.dependencies\]$/) {
                in_poetry_deps = 1
            }
            next
        }
        # PEP 621: dependencies = [ ... ] inside [project] or [project.optional-dependencies]
        section == "[project]" && /^[ \t]*dependencies[ \t]*=[ \t]*\[/ {
            chunk = $0
            sub(/^[^[]*\[/, "", chunk)
            process_pep508_array_chunk(chunk)
            if (chunk ~ /\]/) {
                in_pep621_deps_array = 0
            } else {
                in_pep621_deps_array = 1
            }
            next
        }
        in_pep621_deps_array {
            chunk = $0
            process_pep508_array_chunk(chunk)
            if (chunk ~ /\]/) in_pep621_deps_array = 0
            next
        }
        # Poetry: name = "version" inside [tool.poetry.dependencies]
        in_poetry_deps && /^[ \t]*[A-Za-z0-9_.-]+[ \t]*=[ \t]*/ {
            line = $0
            sub(/[ \t]+#.*$/, "", line)
            # Extract key
            key = line
            sub(/[ \t]*=.*/, "", key)
            gsub(/[ \t]/, "", key)
            if (tolower(key) == "python") next
            # Value can be a bare string "1.2.3" or a table { version = "1.2.3", ... }
            val = line
            sub(/^[^=]*=[ \t]*/, "", val)
            ver = ""
            if (match(val, /^"[^"]+"/)) {
                ver = substr(val, RSTART + 1, RLENGTH - 2)
            } else if (match(val, /version[ \t]*=[ \t]*"[^"]+"/)) {
                inner = substr(val, RSTART, RLENGTH)
                sub(/^version[ \t]*=[ \t]*"/, "", inner)
                sub(/".*$/, "", inner)
                ver = inner
            }
            # Only emit if version is an exact-looking number (no ^, ~, *, >, <, =)
            if (ver != "" && ver !~ /[\^~*<>= ,]/) {
                printf("%s:%s\n", normalize(key), ver)
            }
            next
        }
    ' "$file"
}

# Function: parse_pipfile
# Args: $1 = path to Pipfile
# Output: normalized name:version lines for "name = \"==X.Y.Z\"" pins
parse_pipfile() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
        function normalize(n,    out) {
            out = tolower(n)
            gsub(/[._]+/, "-", out)
            return out
        }
        BEGIN { in_pkgs = 0 }
        /^\[/ {
            line = $0
            sub(/[ \t]+$/, "", line)
            if (line == "[packages]" || line == "[dev-packages]") {
                in_pkgs = 1
            } else {
                in_pkgs = 0
            }
            next
        }
        in_pkgs && /^[ \t]*[A-Za-z0-9_.-]+[ \t]*=/ {
            line = $0
            sub(/[ \t]+#.*$/, "", line)
            key = line
            sub(/[ \t]*=.*/, "", key)
            gsub(/[ \t]/, "", key)
            val = line
            sub(/^[^=]*=[ \t]*/, "", val)
            ver = ""
            if (match(val, /^"==[A-Za-z0-9_.+!-]+"/)) {
                ver = substr(val, RSTART + 3, RLENGTH - 4)
            } else if (match(val, /version[ \t]*=[ \t]*"==[A-Za-z0-9_.+!-]+"/)) {
                inner = substr(val, RSTART, RLENGTH)
                sub(/^version[ \t]*=[ \t]*"==/, "", inner)
                sub(/".*$/, "", inner)
                ver = inner
            }
            if (ver != "") printf("%s:%s\n", normalize(key), ver)
        }
    ' "$file"
}

# Function: parse_lock_blocks
# Args: $1 = path to poetry.lock or uv.lock (both use [[package]] blocks)
# Output: normalized name:version lines, one per package
parse_lock_blocks() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
        function normalize(n,    out) {
            out = tolower(n)
            gsub(/[._]+/, "-", out)
            return out
        }
        function flush() {
            if (in_block && name != "" && version != "") {
                printf("%s:%s\n", name, version)
            }
            name = ""
            version = ""
        }
        BEGIN { in_block = 0; name = ""; version = "" }
        /^\[\[package\]\]/ {
            flush()
            in_block = 1
            next
        }
        /^\[/ {
            flush()
            in_block = 0
            next
        }
        in_block && /^name[ \t]*=[ \t]*"[^"]+"/ {
            v = $0
            sub(/^name[ \t]*=[ \t]*"/, "", v)
            sub(/".*$/, "", v)
            name = normalize(v)
            next
        }
        in_block && /^version[ \t]*=[ \t]*"[^"]+"/ {
            v = $0
            sub(/^version[ \t]*=[ \t]*"/, "", v)
            sub(/".*$/, "", v)
            version = v
            next
        }
        END { flush() }
    ' "$file"
}

# Function: parse_pipfile_lock
# Args: $1 = path to Pipfile.lock (JSON)
# Output: normalized name:version lines from "default" and "develop" sections
parse_pipfile_lock() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    awk '
        function normalize(n,    out) {
            out = tolower(n)
            gsub(/[._]+/, "-", out)
            return out
        }
        BEGIN { name = "" }
        # A package entry: indented "name": {
        /^[ \t]{6,}"[A-Za-z0-9_.-]+":[ \t]*\{[ \t]*$/ {
            line = $0
            sub(/^[ \t]+"/, "", line)
            sub(/":.*$/, "", line)
            name = normalize(line)
            next
        }
        name != "" && /"version":[ \t]*"==[A-Za-z0-9_.+!-]+"/ {
            v = $0
            sub(/.*"version":[ \t]*"==/, "", v)
            sub(/".*$/, "", v)
            printf("%s:%s\n", name, v)
        }
        # Reset name when leaving the entry block
        /^[ \t]{4,6}\}/ { name = "" }
    ' "$file"
}

# Function: extract_pypi_deps
# Args: $1 = path to a Python manifest or lockfile
# Output: normalized name:version lines
# Dispatches to the right parser based on basename. Unknown filenames are ignored.
extract_pypi_deps() {
    local file="$1"
    local base
    base=$(basename "$file")
    case "$base" in
        requirements*.txt|*-requirements.txt)
            parse_requirements_txt < "$file"
            ;;
        pyproject.toml)
            parse_pyproject_toml "$file"
            ;;
        Pipfile)
            parse_pipfile "$file"
            ;;
        Pipfile.lock)
            parse_pipfile_lock "$file"
            ;;
        poetry.lock|uv.lock)
            parse_lock_blocks "$file"
            ;;
        # setup.py / setup.cfg deliberately not parsed in v1 (best-effort, fragile).
        # Users get lockfile-level coverage which is authoritative.
    esac
}

# Function: check_pypi_packages
# Purpose: Scan PyPI manifests and lockfiles for compromised packages
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/compromised_found.txt (shared with npm check)
check_pypi_packages() {
    local scan_dir=$1

    # Build the PyPI compromised lookup once (sorted for set intersection)
    awk -F: '
        /^[[:space:]]*#/ || NF < 3 { next }
        $1 == "pypi" { print $2":"$3 }
    ' "$SCRIPT_DIR/compromised-packages.txt" | LC_ALL=C sort > "$TEMP_DIR/pypi_compromised_lookup.txt"

    if [[ ! -s "$TEMP_DIR/pypi_compromised_lookup.txt" ]]; then
        # No PyPI entries in the database - nothing to do
        return 0
    fi

    local manifest_count lockfile_count
    manifest_count=$(wc -l < "$TEMP_DIR/pypi_manifests.txt" 2>/dev/null | tr -d ' ' || echo "0")
    lockfile_count=$(wc -l < "$TEMP_DIR/pypi_lockfiles.txt" 2>/dev/null | tr -d ' ' || echo "0")

    if [[ "$manifest_count" == "0" && "$lockfile_count" == "0" ]]; then
        return 0
    fi

    print_status "$BLUE" "   Checking $manifest_count PyPI manifest(s) and $lockfile_count lockfile(s)..."

    # Aggregate normalized deps: "file_path|name:version"
    : > "$TEMP_DIR/pypi_all_deps.txt"
    local file
    while IFS= read -r file; do
        [[ -z "$file" || ! -f "$file" ]] && continue
        extract_pypi_deps "$file" | while IFS= read -r dep; do
            [[ -n "$dep" ]] && echo "$file|$dep"
        done >> "$TEMP_DIR/pypi_all_deps.txt"
    done < <(cat "$TEMP_DIR/pypi_manifests.txt" "$TEMP_DIR/pypi_lockfiles.txt" 2>/dev/null)

    if [[ ! -s "$TEMP_DIR/pypi_all_deps.txt" ]]; then
        return 0
    fi

    # Fast set intersection against the PyPI compromised list
    cut -d'|' -f2 "$TEMP_DIR/pypi_all_deps.txt" | LC_ALL=C sort | uniq > "$TEMP_DIR/pypi_deps_only.txt"
    LC_ALL=C comm -12 "$TEMP_DIR/pypi_compromised_lookup.txt" "$TEMP_DIR/pypi_deps_only.txt" > "$TEMP_DIR/pypi_matched_deps.txt"

    if [[ -s "$TEMP_DIR/pypi_matched_deps.txt" ]]; then
        while IFS= read -r matched_dep; do
            { grep -F "|$matched_dep" "$TEMP_DIR/pypi_all_deps.txt" || true; } | while IFS='|' read -r file_path dep; do
                [[ -n "$file_path" ]] && \
                    echo "$file_path:[PyPI] ${dep/:/@}" >> "$TEMP_DIR/compromised_found.txt"
            done
        done < "$TEMP_DIR/pypi_matched_deps.txt"
    fi
}

# Function: check_megalodon_indicators
# Purpose: Detect May 18, 2026 Megalodon GitHub-repo-backdooring campaign IoCs.
#          Megalodon's primary vector is workflow-file injection into 5,561 GitHub repos
#          (mass variant: ci.yml named "SysDiag"; targeted Tiledesk variant:
#          docker-community-worker-push-latest.yml named "Optimize-Build"). The only
#          on-disk artifacts we can see are (a) the workflow files themselves when a
#          compromised repo is checked out locally, and (b) the C2 IP / known commit SHA
#          as literal strings anywhere in scanned code.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/megalodon_indicators.txt
check_megalodon_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for Megalodon GitHub-repo backdooring IOCs (May 18, 2026)..."

    # IOC 1: Workflow files carrying the specific Megalodon workflow names.
    # `name: SysDiag` and `name: Optimize-Build` are unique enough to be HIGH-confidence
    # signals on their own — no legitimate workflow uses these names.
    if [[ -s "$TEMP_DIR/github_workflows.txt" ]]; then
        # Build a clean list of accessible workflow files (mirror the SANDWORM pattern).
        : > "$TEMP_DIR/valid_megalodon_workflows.txt"
        while IFS= read -r f; do
            [[ -f "$f" ]] && echo "$f"
        done < "$TEMP_DIR/github_workflows.txt" > "$TEMP_DIR/valid_megalodon_workflows.txt"

        if [[ -s "$TEMP_DIR/valid_megalodon_workflows.txt" ]]; then
            # Match `name: SysDiag` (with or without quotes, leading whitespace tolerant).
            tr '\n' '\0' < "$TEMP_DIR/valid_megalodon_workflows.txt" | \
                xargs -0 -I {} grep -l -E "^[[:space:]]*name:[[:space:]]*[\"']?SysDiag[\"']?[[:space:]]*$" {} 2>/dev/null | \
                while IFS= read -r file; do
                    echo "$file:Megalodon workflow file (name: SysDiag — mass-variant injection)" >> "$TEMP_DIR/megalodon_indicators.txt"
                done || true
            # Match `name: Optimize-Build` (Tiledesk-targeted variant).
            tr '\n' '\0' < "$TEMP_DIR/valid_megalodon_workflows.txt" | \
                xargs -0 -I {} grep -l -E "^[[:space:]]*name:[[:space:]]*[\"']?Optimize-Build[\"']?[[:space:]]*$" {} 2>/dev/null | \
                while IFS= read -r file; do
                    echo "$file:Megalodon workflow file (name: Optimize-Build — Tiledesk-targeted variant)" >> "$TEMP_DIR/megalodon_indicators.txt"
                done || true
        fi
    fi

    # Megalodon's C2 IP and commit SHA can appear in YAML workflow files (where the
    # attack lives natively) as well as in JS/TS/JSON code, so search both. Build a
    # combined file list once for the two literal-string IoCs below.
    : > "$TEMP_DIR/_megalodon_search_files.txt"
    [[ -s "$TEMP_DIR/code_files.txt" ]] && cat "$TEMP_DIR/code_files.txt" >> "$TEMP_DIR/_megalodon_search_files.txt"
    [[ -s "$TEMP_DIR/yaml_files.txt" ]] && cat "$TEMP_DIR/yaml_files.txt" >> "$TEMP_DIR/_megalodon_search_files.txt"
    [[ -s "$TEMP_DIR/script_files.txt" ]] && cat "$TEMP_DIR/script_files.txt" >> "$TEMP_DIR/_megalodon_search_files.txt"

    # IOC 2: C2 IP literal. Match the bare IP and the IP:port form. Match the defanged
    # form too in case it appears in advisories/notes the user has checked into the repo.
    if [[ -s "$TEMP_DIR/_megalodon_search_files.txt" ]]; then
        local c2_ip
        for c2_ip in "216.126.225.129" "216.126.225.129:8443" "216.126.225[.]129"; do
            fast_grep_files_fixed "$c2_ip" < "$TEMP_DIR/_megalodon_search_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Megalodon C2 IP reference ($c2_ip)" >> "$TEMP_DIR/megalodon_indicators.txt"
                done
        done
    fi

    # IOC 3: Known Tiledesk malicious commit SHA. Anywhere in code/config (lockfiles,
    # CI configs, vendored copies — anywhere a contaminated source tree might reference it).
    if [[ -s "$TEMP_DIR/_megalodon_search_files.txt" ]]; then
        fast_grep_files_fixed "acac5a9854650c4ae2883c4740bf87d34120c038" < "$TEMP_DIR/_megalodon_search_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Megalodon malicious commit SHA (Tiledesk variant)" >> "$TEMP_DIR/megalodon_indicators.txt"
            done
    fi
    rm -f "$TEMP_DIR/_megalodon_search_files.txt"

    # Deduplicate
    if [[ -s "$TEMP_DIR/megalodon_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/megalodon_indicators.txt" -o "$TEMP_DIR/megalodon_indicators.txt"
    fi
}

# Function: check_web3_mcp_indicators
# Purpose: Detect May 20, 2026 Web3/DeFi MCP-server typosquatting campaign content IoCs.
#          The 10 specific malicious package versions are caught by the standard package-
#          version check via compromised-packages.txt. This function adds the C2 / fallback-
#          webhook URLs as literal grep IoCs so that contaminated install logs, vendored
#          copies of the postinstall script, or staged payloads still surface even if the
#          package itself has already been npm-uninstalled.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/web3_mcp_indicators.txt
check_web3_mcp_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for Web3/DeFi MCP-server typosquat IOCs (May 20, 2026)..."

    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        # Primary C2: dynamic-webhook config fetched from an attacker-controlled GitHub Pages site.
        local web3_indicator
        for web3_indicator in \
            "ddjidd564.github.io/defi-security-best-practices/config.json" \
            "ddjidd564.github.io" \
            "ddjidd564[.]github[.]io" \
            "webhook.site/8d334534-1c63-4f4f-a0d7-95c446c8b233" \
            "8d334534-1c63-4f4f-a0d7-95c446c8b233"
        do
            fast_grep_files_fixed "$web3_indicator" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Web3/DeFi MCP-typosquat C2 reference ($web3_indicator)" >> "$TEMP_DIR/web3_mcp_indicators.txt"
                done
        done
    fi

    # Deduplicate
    if [[ -s "$TEMP_DIR/web3_mcp_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/web3_mcp_indicators.txt" -o "$TEMP_DIR/web3_mcp_indicators.txt"
    fi
}

# Function: check_polymarket_indicators
# Purpose: Detect May 21, 2026 Polymarket wallet-drainer typosquat content IoCs.
#          Nine packages from npm publisher `polymarketdev` impersonate Polymarket
#          trading tools; their postinstall hook prompts a fake "wallet onboarding"
#          UI, captures raw private keys, and exfiltrates them to a Cloudflare-
#          Workers C2. Local artifacts under ~/.polybot/. The 18 specific
#          name:version pairs are caught by the standard package-version check;
#          this function adds the C2 URL, the payload SHA-256, the publisher
#          fingerprint, and the local-artifact paths as separate content IoCs
#          so contaminated post-uninstall traces still surface.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/polymarket_indicators.txt
check_polymarket_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for Polymarket wallet-drainer IOCs (May 21, 2026)..."

    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        # IOC 1: C2 host + exfil endpoint (Cloudflare Worker subdomain).
        local poly_indicator
        for poly_indicator in \
            "polymarketbot.polymarketdev.workers.dev" \
            "polymarketbot.polymarketdev[.]workers[.]dev" \
            "/v1/wallets/keys"
        do
            fast_grep_files_fixed "$poly_indicator" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:Polymarket C2 reference ($poly_indicator)" >> "$TEMP_DIR/polymarket_indicators.txt"
                done
        done

        # IOC 2: Payload SHA-256 mentioned as a literal string (advisories, runbooks,
        # incident-response notes the user has checked into the repo).
        fast_grep_files_fixed "e01b85c1437085a519217338fe4ee5ed7858c28a10f8c1477b2f1857c3386edb" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Polymarket payload SHA-256 literal reference" >> "$TEMP_DIR/polymarket_indicators.txt"
            done

        # IOC 3: Threat-actor publisher fingerprint in package.json metadata that npm
        # caches after install. Same JSON-context-quoted approach used for the May 19
        # atool wave to avoid false-positive matches on the bare word "polymarketdev".
        fast_grep_files_fixed '"_npmUser":{"name":"polymarketdev"' < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Polymarket threat-actor publisher (polymarketdev)" >> "$TEMP_DIR/polymarket_indicators.txt"
            done

        # IOC 4: GitHub source repo the campaign was built from.
        fast_grep_files_fixed "texsellix/polymarket-trading-bot" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:Polymarket attacker GitHub source repo reference (texsellix/polymarket-trading-bot)" >> "$TEMP_DIR/polymarket_indicators.txt"
            done
    fi

    # IOC 5: Local artifact files the payload writes — staged stolen wallet keys.
    # These directories are exactly what the dropper creates; presence is enough.
    local poly_artifact
    for poly_artifact in \
        "$scan_dir/.polybot/device.json" \
        "$scan_dir/.polybot/wallets.json"
    do
        if [[ -f "$poly_artifact" ]]; then
            echo "$poly_artifact:Polymarket local artifact (staged stolen wallet keys)" >> "$TEMP_DIR/polymarket_indicators.txt"
        fi
    done
    # Also catch artifacts that live inside the scan tree at any depth (e.g. a backup
    # of a compromised home dir, a developer's local notes, a staged install kit).
    local in_tree_poly
    while IFS= read -r in_tree_poly; do
        if [[ -f "$in_tree_poly" ]]; then
            echo "$in_tree_poly:Polymarket local artifact in scan tree (staged stolen wallet keys)" >> "$TEMP_DIR/polymarket_indicators.txt"
        fi
    done < <(grep -E "/\.polybot/(device|wallets)\.json$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || true)

    # Deduplicate
    if [[ -s "$TEMP_DIR/polymarket_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/polymarket_indicators.txt" -o "$TEMP_DIR/polymarket_indicators.txt"
    fi
}

# Function: check_sl4x0_indicators
# Purpose: Detect the June 2025 → March 2026 sl4x0 dependency-confusion campaign.
#          Distinct from the typosquat / publisher-compromise campaigns: 92+ packages
#          across 32 throwaway accounts (all *@sl4x0.xyz) impersonate internal Fortune-
#          500 package names with inflated version numbers (9.9.x, 99.9.9) to win
#          dependency resolution. Payload is DNS-only reconnaissance (no persistence,
#          no credential theft), so SafeDep characterises it as likely-security-research /
#          bug-bounty rather than destructive — but it still runs on install and leaks
#          developer identity (username + hostname + cwd) to a third party.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/sl4x0_indicators.txt
check_sl4x0_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for sl4x0 dependency-confusion campaign IOCs..."

    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        # IOC 1: C2 exfiltration domain (bare and defanged forms).
        local sl4x0_indicator
        for sl4x0_indicator in \
            "oob.sl4x0.xyz" \
            "oob[.]sl4x0[.]xyz" \
            "sl4x0.xyz" \
            "sl4x0[.]xyz"
        do
            fast_grep_files_fixed "$sl4x0_indicator" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:sl4x0 C2/domain reference ($sl4x0_indicator)" >> "$TEMP_DIR/sl4x0_indicators.txt"
                done
        done

        # IOC 2: Publisher email-domain fingerprint. All 32 attacker accounts use
        # @sl4x0.xyz email addresses in their npm publisher metadata. Catches every
        # package the campaign has ever published — including the 70+ that npm has
        # since removed — as long as a copy exists in node_modules.
        fast_grep_files_fixed "@sl4x0.xyz" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:sl4x0 publisher email-domain fingerprint (@sl4x0.xyz)" >> "$TEMP_DIR/sl4x0_indicators.txt"
            done

        # IOC 3: Fabricated GitHub organization name embedded in package.json metadata.
        # `slaxorg` is referenced in the campaign's package.json `repository` fields but
        # the org does not actually exist on GitHub.
        fast_grep_files_fixed "slaxorg" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:sl4x0 fabricated GitHub org reference (slaxorg)" >> "$TEMP_DIR/sl4x0_indicators.txt"
            done
    fi

    # IOC 4: Unique hex-named payload files inside any package. `b02e30.js` and
    # `6ad264.js` are the campaign's two helper modules with effectively-unique names;
    # presence of either at `<pkg>/lib/<name>.js` is a high-confidence signal.
    # The all_files_raw collection picks them up via the find -name additions; we
    # filter the categorisation here.
    local in_tree_sl4x0
    while IFS= read -r in_tree_sl4x0; do
        if [[ -f "$in_tree_sl4x0" ]]; then
            local sl4x0_base
            sl4x0_base=$(basename "$in_tree_sl4x0")
            echo "$in_tree_sl4x0:sl4x0 hex-named payload helper ($sl4x0_base)" >> "$TEMP_DIR/sl4x0_indicators.txt"
        fi
    done < <(grep -E "/lib/(b02e30|6ad264)\.js$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || true)

    # Deduplicate
    if [[ -s "$TEMP_DIR/sl4x0_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/sl4x0_indicators.txt" -o "$TEMP_DIR/sl4x0_indicators.txt"
    fi
}

# Function: check_art_template_indicators
# Purpose: Detect the March 2025 → May 2026 art-template npm hijack (UNC6691 / iOS
#          browser exploit kit). Stage-1 loader is appended to lib/template-web.js
#          in the package's browser bundle; it chain-loads external scripts that
#          deploy an iOS exploit kit. No preinstall/postinstall — payload activates
#          only in browser context. The only on-disk artifacts are the modified
#          template-web.js (containing references to external C2 domains) and the
#          updated package.json metadata pointing at the attacker's GitHub account.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/art_template_indicators.txt
check_art_template_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for art-template npm hijack IOCs (March 2025 - May 2026)..."

    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        # C2 domains and exploit-kit URLs (bare + defanged).
        local art_indicator
        for art_indicator in \
            "v3.jiathis.com" \
            "v3.jiathis[.]com" \
            "git.youzzjizz.com" \
            "git.youzzjizz[.]com" \
            "utaq.cfww.shop" \
            "utaq.cfww[.]shop" \
            "l1ewsu3yjkqeroy.xyz" \
            "l1ewsu3yjkqeroy[.]xyz" \
            "/api/ip-sync/sync"
        do
            fast_grep_files_fixed "$art_indicator" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:art-template hijack C2 reference ($art_indicator)" >> "$TEMP_DIR/art_template_indicators.txt"
                done
        done

        # Threat-actor publisher / GitHub account fingerprints in package.json metadata.
        local art_actor
        for art_actor in \
            '"_npmUser":{"name":"v4v5qc"' \
            '"_npmUser":{"name":"npmpacketmaintainmember7"' \
            '"_npmUser":{"name":"daughtrymom"' \
            "github.com/goofychris/" \
            "eb8org@gmail.com" \
            "npmpacketmaintainmember7@proton.me"
        do
            fast_grep_files_fixed "$art_actor" < "$TEMP_DIR/code_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:art-template hijack threat-actor fingerprint ($art_actor)" >> "$TEMP_DIR/art_template_indicators.txt"
                done
        done

        # Obfuscation seed (string-decode key) — unique enough to flag as a literal match.
        fast_grep_files_fixed "cecd08aa6ff548c2" < "$TEMP_DIR/code_files.txt" | \
            while IFS= read -r file; do
                echo "$file:art-template hijack obfuscation seed (cecd08aa6ff548c2)" >> "$TEMP_DIR/art_template_indicators.txt"
            done
    fi

    # Deduplicate
    if [[ -s "$TEMP_DIR/art_template_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/art_template_indicators.txt" -o "$TEMP_DIR/art_template_indicators.txt"
    fi
}

# Function: check_durabletask_indicators
# Purpose: Detect the May 19, 2026 durabletask PyPI compromise (multi-cloud
#          credential stealer with AWS SSM + Kubernetes worm capabilities). Runtime
#          dropper injected into durabletask/__init__.py and four sibling files;
#          downloads rope.pyz from check.git-service.com (primary) or
#          t.m-kosche.com (secondary — shared with the May 19 Mini Shai-Hulud
#          atool/AntV wave, suggesting actor/toolkit overlap with TeamPCP).
#          Slavic-folklore beacon strings (Koschei, Baba Yaga, FIRESCALE) embedded
#          in commit messages and exfil-repo naming.
# Args: $1 = scan_dir
# Modifies: $TEMP_DIR/durabletask_indicators.txt
check_durabletask_indicators() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for durabletask PyPI IOCs (May 19, 2026)..."

    # durabletask is a PyPI package — the malicious code lives in .py files, which
    # are categorised as script_files.txt (not code_files.txt). Search both so the
    # C2/beacon literals are caught whether they appear in JS, JSON, Python, or shell.
    : > "$TEMP_DIR/_durabletask_search_files.txt"
    [[ -s "$TEMP_DIR/code_files.txt" ]] && cat "$TEMP_DIR/code_files.txt" >> "$TEMP_DIR/_durabletask_search_files.txt"
    [[ -s "$TEMP_DIR/script_files.txt" ]] && cat "$TEMP_DIR/script_files.txt" >> "$TEMP_DIR/_durabletask_search_files.txt"
    [[ -s "$TEMP_DIR/yaml_files.txt" ]] && cat "$TEMP_DIR/yaml_files.txt" >> "$TEMP_DIR/_durabletask_search_files.txt"

    if [[ -s "$TEMP_DIR/_durabletask_search_files.txt" ]]; then
        # IOC 1: Primary C2 (the secondary t.m-kosche.com is already caught by
        # check_mini_shai_hulud_indicators).
        local dt_indicator
        for dt_indicator in \
            "check.git-service.com" \
            "check.git-service[.]com" \
            "/api/public/version" \
            "/v1/models" \
            "/rope.pyz" \
            "/audio.mp3"
        do
            fast_grep_files_fixed "$dt_indicator" < "$TEMP_DIR/_durabletask_search_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:durabletask C2 reference ($dt_indicator)" >> "$TEMP_DIR/durabletask_indicators.txt"
                done
        done

        # IOC 2: Slavic-folklore beacon strings used in commit messages and exfil-repo
        # naming. Unique enough that a literal match has near-zero FP risk.
        local dt_beacon
        for dt_beacon in "FIRESCALE" "BABA-YAGA-KOSCHEI" "PUSH UR T3MPRR"; do
            fast_grep_files_fixed "$dt_beacon" < "$TEMP_DIR/_durabletask_search_files.txt" | \
                while IFS= read -r file; do
                    echo "$file:durabletask beacon string ($dt_beacon)" >> "$TEMP_DIR/durabletask_indicators.txt"
                done
        done
    fi
    rm -f "$TEMP_DIR/_durabletask_search_files.txt"

    # IOC 3: Stage-2 payload file (rope.pyz) anywhere in the tree. Hash check via
    # MALICIOUS_HASHLIST will provide stronger confirmation; this is a faster
    # filename-only flag for the same artifact.
    local in_tree_dt
    while IFS= read -r in_tree_dt; do
        if [[ -f "$in_tree_dt" ]]; then
            echo "$in_tree_dt:durabletask stage-2 payload filename (rope.pyz)" >> "$TEMP_DIR/durabletask_indicators.txt"
        fi
    done < <(grep -E "/rope\.pyz$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || true)

    # IOC 4: Persistence artifacts — systemd unit and binary the payload installs.
    # Match both system-wide and user-local installation paths.
    local dt_persist
    for dt_persist in \
        "$scan_dir/etc/systemd/system/pgsql-monitor.service" \
        "$scan_dir/usr/bin/pgmonitor.py" \
        "$HOME/.config/systemd/user/pgsql-monitor.service" \
        "$HOME/.local/bin/pgmonitor.py" \
        "$HOME/.cache/.sys-update-check" \
        "$HOME/.cache/.sys-update-check-k8s"
    do
        if [[ -e "$dt_persist" ]]; then
            echo "$dt_persist:durabletask persistence artifact (pgsql-monitor / pgmonitor / sys-update-check)" >> "$TEMP_DIR/durabletask_indicators.txt"
        fi
    done
    # Also catch any of those artifact names anywhere in the scan tree (backups, install kits).
    local in_tree_dt_persist
    while IFS= read -r in_tree_dt_persist; do
        if [[ -f "$in_tree_dt_persist" ]]; then
            echo "$in_tree_dt_persist:durabletask persistence artifact in scan tree" >> "$TEMP_DIR/durabletask_indicators.txt"
        fi
    done < <(grep -E "/(pgsql-monitor\.service|pgmonitor\.py)$" "$TEMP_DIR/all_files_raw.txt" 2>/dev/null || true)

    # Deduplicate
    if [[ -s "$TEMP_DIR/durabletask_indicators.txt" ]]; then
        sort -u "$TEMP_DIR/durabletask_indicators.txt" -o "$TEMP_DIR/durabletask_indicators.txt"
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
        # Priority 1: Known malicious file patterns (always check). Includes May 19 atool
        # wave indicators (cat.py — kitty-monitor dead-drop fetcher, index.js — preinstall payload).
        grep -E "(setup_bun\.js|bun_environment\.js|actionsSecrets\.json|trufflehog|router_init\.js|tanstack_runner\.js|kitty-monitor\.sh|cat\.py|49554fde7424c31c\.js|rope\.pyz|template-web\.js|pgmonitor\.py)" "$TEMP_DIR/code_files.txt" 2>/dev/null || true

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

    # Create optimized lookup table from compromised packages (sorted for join).
    # Filter to npm-only entries: bare "name:version" lines OR "npm:name:version".
    # PyPI-prefixed lines and comments are excluded.
    awk -F: '
        /^[[:space:]]*#/ || NF < 2 { next }
        $1 == "npm" && NF >= 3 { print $2":"$3; next }
        $1 == "pypi" { next }
        /^[@a-zA-Z]/ { print $1":"$2 }
    ' "$SCRIPT_DIR/compromised-packages.txt" | LC_ALL=C sort > "$TEMP_DIR/compromised_lookup.txt"

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
                # Check if this package:version is compromised using O(1) lookup (npm)
                if [[ -v COMPROMISED_PACKAGES_MAP["npm:$pkg_name:$pkg_version"] ]]; then
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
    print_status "$BLUE" "   Checking for typosquatting in package.json files..."

    # PERF: Pre-filter package_files.txt to exclude node_modules / vendor / build.
    # Typosquatting is a name-similarity heuristic that's meaningful for YOUR
    # declared dependencies, not for the thousands of transitive deps already
    # resolved inside node_modules. Scanning node_modules here triggers
    # hundreds of thousands of `echo | grep` subshells (length, alpha, unicode,
    # 6 confusables, and 26 popular-package comparisons per package name) and
    # produces noisy false positives on legitimate ecosystem packages whose
    # names happen to look like popular ones (react-*, eslint-*, babel-*).
    # This filter matches industry convention (npm audit, socket.dev) of
    # checking only top-level project manifests.
    if [[ -s "$TEMP_DIR/package_files.txt" ]]; then
        grep -vE "/(node_modules|vendor|\.git|dist|build|_build|deps|\.next|coverage|site-packages|\.venv|venv)/" \
            "$TEMP_DIR/package_files.txt" 2>/dev/null > "$TEMP_DIR/typosquatting_targets.txt" || \
            touch "$TEMP_DIR/typosquatting_targets.txt"
    else
        touch "$TEMP_DIR/typosquatting_targets.txt"
    fi
    local target_count
    target_count=$(wc -l < "$TEMP_DIR/typosquatting_targets.txt" 2>/dev/null | tr -d ' ')
    local total_count
    total_count=$(wc -l < "$TEMP_DIR/package_files.txt" 2>/dev/null | tr -d ' ')
    print_status "$BLUE" "   Scanning $target_count manifest(s) for typosquatting (filtered from $total_count total)..."

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
    # Use the pre-filtered target list (excludes node_modules / vendor / build artifacts).
    # See PERF note at top of function.
    done < <(tr '\n' '\0' < "$TEMP_DIR/typosquatting_targets.txt")
}

# Function: check_network_exfiltration
# Purpose: Detect network exfiltration patterns including suspicious domains and IPs
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/network_exfiltration_warnings.txt (temp file)
# Returns: Populates network_exfiltration_warnings.txt with hardcoded IPs and suspicious domains
check_network_exfiltration() {
    local scan_dir=$1
    print_status "$BLUE" "   Checking for network exfiltration patterns..."

    # PERF: Pre-filter the file list to exclude node_modules, vendor, dist, build,
    # and minified bundles BEFORE looping. Without this, large projects with
    # node_modules can spawn 70,000+ git grep subprocesses (~5-10ms each) on
    # files that the per-check filters would skip anyway. The DNS / WebSocket /
    # X-header / btoa checks below were also previously unfiltered, so this
    # pre-filter also closes that gap.
    #
    # Skip patterns mirror the per-check filters already present below plus
    # build/dist artifacts that contain bundled vendor code. ".git" is also
    # excluded so we don't scan packed git objects.
    if [[ -s "$TEMP_DIR/code_files.txt" ]]; then
        grep -vE "/(node_modules|vendor|\.git|dist|build|_build|deps|\.next|coverage|site-packages|\.venv|venv)/" \
            "$TEMP_DIR/code_files.txt" 2>/dev/null > "$TEMP_DIR/network_exfil_targets.txt" || \
            touch "$TEMP_DIR/network_exfil_targets.txt"
    else
        touch "$TEMP_DIR/network_exfil_targets.txt"
    fi
    local target_count
    target_count=$(wc -l < "$TEMP_DIR/network_exfil_targets.txt" 2>/dev/null | tr -d ' ')
    local total_count
    total_count=$(wc -l < "$TEMP_DIR/code_files.txt" 2>/dev/null | tr -d ' ')
    print_status "$BLUE" "   Scanning $target_count files for network exfiltration (filtered from $total_count total)..."

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
                    # FIX: Escape literal dots in the domain before interpolating into the regex.
                    # Without this, "t.me" matches "time"/"theme", "ix.io" matches "ixaio", etc.,
                    # producing a flood of false positives in any file containing those words.
                    # Keep $domain itself unescaped for the human-readable error messages below.
                    local domain_esc="${domain//./\\.}"
                    # Use word boundaries and URL patterns to avoid false positives like "timeZone" containing "t.me"
                    # Updated pattern to catch property values like hostname: 'webhook.site'
                    if grep -qE "https?://[^[:space:]]*$domain_esc|[[:space:]:,\"\']$domain_esc[[:space:]/\"\',;]" "$file" 2>/dev/null; then
                        # Additional check - make sure it's not just a comment or documentation
                        local suspicious_usage
                        suspicious_usage=$(grep -E "https?://[^[:space:]]*$domain_esc|[[:space:]:,\"\']$domain_esc[[:space:]/\"\',;]" "$file" 2>/dev/null | grep -vE "^[[:space:]]*#|^[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null || true) || true
                        if [[ -n "$suspicious_usage" ]]; then
                            # Get line number and context
                            # FIX: grep -n prefixes lines with "NNN:" so we must account for that in comment filtering
                            local line_info
                            line_info=$(grep -nE "https?://[^[:space:]]*$domain_esc|[[:space:]:,\"\']$domain_esc[[:space:]/\"\',;]" "$file" 2>/dev/null | grep -vE "^[0-9]+:[[:space:]]*#|^[0-9]+:[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null || true) || true
                            local line_num
                            line_num=$(echo "$line_info" | cut -d: -f1 2>/dev/null || true) || true

                            # Check if it's a minified file or has very long lines
                            if [[ "$file" == *".min.js"* ]] || [[ $(echo "$suspicious_usage" | wc -c 2>/dev/null || true) -gt 150 ]]; then
                                # Extract just around the domain
                                local snippet
                                snippet=$(echo "$suspicious_usage" | grep -o ".\{0,20\}$domain_esc.\{0,20\}" 2>/dev/null | head -1 2>/dev/null || true) || true
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
    # Use the pre-filtered target list (excludes node_modules / vendor / build artifacts).
    # This is the perf fix that prevents 70k+ wasted git grep subprocesses on large projects.
    done < <(tr '\n' '\0' < "$TEMP_DIR/network_exfil_targets.txt")
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
        [[ -s "$TEMP_DIR/sandworm_mode_workflows.txt" ]] && cut -d: -f1 "$TEMP_DIR/sandworm_mode_workflows.txt" || true
        [[ -s "$TEMP_DIR/axios_attack_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/axios_attack_indicators.txt" || true
        [[ -s "$TEMP_DIR/mini_shai_hulud_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/mini_shai_hulud_indicators.txt" || true
        [[ -s "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt" ]] && cut -d: -f1 "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt" || true
        [[ -s "$TEMP_DIR/megalodon_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/megalodon_indicators.txt" || true
        [[ -s "$TEMP_DIR/web3_mcp_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/web3_mcp_indicators.txt" || true
        [[ -s "$TEMP_DIR/polymarket_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/polymarket_indicators.txt" || true
        [[ -s "$TEMP_DIR/sl4x0_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/sl4x0_indicators.txt" || true
        [[ -s "$TEMP_DIR/art_template_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/art_template_indicators.txt" || true
        [[ -s "$TEMP_DIR/durabletask_indicators.txt" ]] && cut -d: -f1 "$TEMP_DIR/durabletask_indicators.txt" || true
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

    if [[ -s "$TEMP_DIR/sandworm_mode_workflows.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: February 2026 SANDWORM_MODE workflow indicators detected:"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Workflow contains SANDWORM_MODE campaign IOC"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/sandworm_mode_workflows.txt"
    fi

    if [[ -s "$TEMP_DIR/axios_attack_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: March 2026 axios supply chain attack indicators detected:"
        print_status "$RED" "    ⚠️  WARNING: Compromised axios versions drop a cross-platform RAT!"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Axios supply chain attack indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/axios_attack_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Downgrade to axios@1.14.0, remove plain-crypto-js, rotate all credentials"
    fi

    if [[ -s "$TEMP_DIR/mini_shai_hulud_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime indicators detected:"
        print_status "$RED" "    ⚠️  WARNING: TeamPCP campaign — hijacked release pipelines + dead-man's-switch payload!"
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Mini Shai-Hulud supply chain attack indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/mini_shai_hulud_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Pin @tanstack/* to last-known-good versions, audit CI logs"
        print_status "$RED" "                         for orphan-commit github: refs, rotate GitHub/npm tokens AFTER"
        print_status "$RED" "                         confirming no gh-token-monitor service is active (see below)."
    fi

    if [[ -s "$TEMP_DIR/megalodon_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: May 18, 2026 Megalodon GitHub-repo backdooring indicators detected:"
        print_status "$RED" "    ⚠️  Workflow injected on a stolen GitHub PAT / deploy key. Exfiltrates CI secrets."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Megalodon GitHub-repo backdooring indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/megalodon_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Remove the malicious workflow file, rotate all GitHub PATs"
        print_status "$RED" "                         and deploy keys on the repo, audit recent workflow runs for"
        print_status "$RED" "                         exfiltrated secrets, rotate any CI/cloud credentials touched."
    fi

    if [[ -s "$TEMP_DIR/web3_mcp_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: May 20, 2026 Web3/DeFi MCP-server typosquat C2 indicators detected:"
        print_status "$RED" "    ⚠️  Payload exfiltrates ~/.ssh, ~/.ethereum, ~/.bitcoin, ~/.env, shell history,"
        print_status "$RED" "        ~/.git-credentials on install AND on every MCP tool invocation."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Web3/DeFi MCP-server typosquat C2 reference"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/web3_mcp_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Uninstall the offending package, rotate SSH keys, wallet"
        print_status "$RED" "                         seeds/keystores, GitHub credentials, and any secret found in"
        print_status "$RED" "                         your .env files. Assume shell history was harvested."
    fi

    if [[ -s "$TEMP_DIR/sl4x0_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: sl4x0 dependency-confusion campaign indicators detected:"
        print_status "$RED" "    ⚠️  Postinstall hook reads OS username + hostname + cwd basename and DNS-exfils"
        print_status "$RED" "        them to oob.sl4x0.xyz. No persistence, no file/credential theft observed,"
        print_status "$RED" "        but developer identity has been leaked to a third party."
        print_status "$RED" "    📋 NOTE: Account naming (*poc) and minimal payload suggest likely security"
        print_status "$RED" "            research / bug bounty rather than destructive intent — but the code"
        print_status "$RED" "            DID execute on install. Treat findings as confirmed exposure."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: sl4x0 dependency-confusion indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/sl4x0_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Uninstall the offending package(s), audit DNS egress logs"
        print_status "$RED" "                         for queries to *.oob.sl4x0.xyz to confirm whether the"
        print_status "$RED" "                         payload ever ran, and investigate how the internal package"
        print_status "$RED" "                         name leaked (private registry config, lockfile commit, etc.)."
    fi

    if [[ -s "$TEMP_DIR/art_template_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: art-template npm hijack indicators detected (UNC6691 / iOS exploit kit):"
        print_status "$RED" "    ⚠️  Browser-bundle injection — payload activates only when the package is loaded"
        print_status "$RED" "        via <script> tag or bundled for client-side rendering. Node.js-only consumers"
        print_status "$RED" "        are unaffected unless they explicitly load the browser bundle."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: art-template hijack indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/art_template_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Downgrade art-template to 4.13.2 or earlier, rebuild any"
        print_status "$RED" "                         browser bundles produced after 2025-03-12, and audit any end-user"
        print_status "$RED" "                         iOS Safari sessions that loaded the affected pages."
    fi

    if [[ -s "$TEMP_DIR/durabletask_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: May 19, 2026 durabletask PyPI compromise indicators detected:"
        print_status "$RED" "    ⚠️  Multi-cloud credential stealer with AWS SSM + Kubernetes worm capabilities."
        print_status "$RED" "        Targets AWS / Azure / GCP creds, Kubernetes/Vault secrets, password-manager"
        print_status "$RED" "        vaults, SSH keys, npm/PyPI/Cargo tokens, Terraform state, MCP configs."
        print_status "$RED" "        Secondary C2 is t.m-kosche.com — same C2 as the May 19 Mini Shai-Hulud"
        print_status "$RED" "        atool/AntV wave (likely TeamPCP toolkit overlap)."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: durabletask PyPI compromise indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/durabletask_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Pin durabletask to <=1.4.0 or remove, disable pgsql-monitor"
        print_status "$RED" "                         systemd unit (systemctl --user stop pgsql-monitor.service),"
        print_status "$RED" "                         delete /usr/bin/pgmonitor.py and ~/.cache/.sys-update-check*,"
        print_status "$RED" "                         rotate AWS/GCP/Azure/Kubernetes/Vault/GitHub credentials, and"
        print_status "$RED" "                         audit AWS SSM + kubectl exec history for lateral movement."
    fi

    if [[ -s "$TEMP_DIR/polymarket_indicators.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: May 21, 2026 Polymarket wallet-drainer indicators detected:"
        print_status "$RED" "    ⚠️  Fake \"wallet onboarding\" prompt captures raw private keys and exfiltrates"
        print_status "$RED" "        them (plus env vars and .env files) to a Cloudflare Workers C2."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            show_file_preview "$file" "HIGH RISK: Polymarket wallet-drainer indicator"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/polymarket_indicators.txt"
        print_status "$RED" "    📋 IMMEDIATE ACTION: Uninstall any polymarket-* package from the polymarketdev"
        print_status "$RED" "                         publisher, delete ~/.polybot/, and treat any crypto wallet"
        print_status "$RED" "                         whose keys you entered into the onboarding prompt as fully"
        print_status "$RED" "                         compromised — move funds to a fresh wallet immediately."
    fi

    if [[ -s "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: Mini Shai-Hulud dead-man's-switch artifacts detected:"
        print_status "$RED" "    ⚠️  CRITICAL WARNING: Revoking a monitored GitHub token while gh-token-monitor"
        print_status "$RED" "                         is active is designed to TRIGGER A DESTRUCTIVE WIPE of"
        print_status "$RED" "                         the host. Stop and remove the service BEFORE rotating"
        print_status "$RED" "                         any GitHub credentials."
        while IFS= read -r line; do
            local file="${line%%:*}"
            local reason="${line#*:}"
            echo "   - $file"
            echo "     Reason: $reason"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/mini_shai_hulud_host_artifacts.txt"
        print_status "$RED" "    📋 SAFE REMEDIATION ORDER:"
        print_status "$RED" "       1. Disable the LaunchAgent/systemd service (launchctl unload / systemctl --user stop+disable)"
        print_status "$RED" "       2. Delete monitor files: gh-token-monitor.{sh,service,plist} and ~/.config/gh-token-monitor"
        print_status "$RED" "       3. Verify no monitor process is running (ps aux | grep gh-token-monitor)"
        print_status "$RED" "       4. THEN rotate the affected GitHub tokens and audit token audit logs"
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

# =============================================================================
# Bulk scan mode (--bulk): scan many projects in one run, write an aggregate report
# =============================================================================
# Implementation note: each project is scanned by re-invoking this script as a
# subprocess (one fresh process per project). That keeps every per-project scan
# isolated from the others' global state / temp dirs and lets us reuse the
# existing --save-log contract and exit codes verbatim instead of refactoring
# the whole scanner to be re-entrant.

# Function: _bulk_count_section
# Purpose: Count the non-empty entries in one section of a --save-log file.
# Args: $1 = path to a --save-log file, $2 = section name ("HIGH"|"MEDIUM"|"LOW")
# Output: number of flagged paths in that section (0 if file missing/empty)
_bulk_count_section() {
    [[ -f "$1" ]] || { echo 0; return 0; }
    awk -v want="$2" '
        $0 == "# HIGH"   { sec = "HIGH";   next }
        $0 == "# MEDIUM" { sec = "MEDIUM"; next }
        $0 == "# LOW"    { sec = "LOW";    next }
        sec == want && length($0) > 0 { c++ }
        END { print c + 0 }
    ' "$1"
}

# Function: _bulk_section_lines
# Purpose: Print the non-empty entries of one section of a --save-log file, one per line.
# Args: $1 = path to a --save-log file, $2 = section name ("HIGH"|"MEDIUM"|"LOW")
_bulk_section_lines() {
    [[ -f "$1" ]] || return 0
    awk -v want="$2" '
        $0 == "# HIGH"   { sec = "HIGH";   next }
        $0 == "# MEDIUM" { sec = "MEDIUM"; next }
        $0 == "# LOW"    { sec = "LOW";    next }
        sec == want && length($0) > 0 { print }
    ' "$1"
}

# Function: _bulk_is_in_output_dir
# Purpose: Hardening (b) — is the given absolute path the resolved --bulk-output
#          directory, or somewhere inside it? Used by discovery to refuse to scan
#          the bulk output directory if it happens to live inside a scan root.
# Args: $1 = absolute path to test
# Returns: 0 if equal to or inside BULK_OUTPUT_ABS, 1 otherwise
_bulk_is_in_output_dir() {
    local candidate="$1"
    [[ -z "$BULK_OUTPUT_ABS" ]] && return 1
    [[ "$candidate" == "$BULK_OUTPUT_ABS" ]] && return 0
    [[ "$candidate" == "$BULK_OUTPUT_ABS"/* ]] && return 0
    return 1
}

# Function: _bulk_resolve_abs
# Purpose: Resolve a (possibly non-existent) path to an absolute path, without
#          requiring the directory to exist yet. Used to resolve --bulk-output
#          *before* discovery runs so we can exclude it from the scan, even when
#          the output dir will only be created after discovery succeeds.
# Args: $1 = path (absolute or relative to PWD)
# Output: absolute path on stdout (no symlink/.. canonicalization beyond basic PWD prefixing)
_bulk_resolve_abs() {
    local p="$1"
    [[ -z "$p" ]] && return 0
    if [[ "$p" == /* ]]; then
        printf '%s\n' "$p"
    else
        printf '%s/%s\n' "$PWD" "$p"
    fi
}

# Function: _bulk_collect_unreadable
# Purpose: Hardening (a) — collect every directory the bulk run could not read.
#          Combines two sources:
#            * the stderr accumulator from `find` (covers the case where find
#              itself couldn't read a directory's contents — usually because a
#              parent has mode 000 / 600);
#            * a parallel ".cd" accumulator written by the discovery loop when
#              an individual child is visible to find but not readable/enterable
#              (the more common chmod-000-on-one-subdir case).
#          Output is one absolute path per line, sorted and de-duplicated.
# Args: $1 = path to the stderr log (the ".cd" accumulator is "$1.cd")
# Output: zero or more absolute paths to stdout
_bulk_collect_unreadable() {
    local log="$1"
    {
        if [[ -s "$log" ]]; then
            # find error formats we handle:
            #   macOS/BSD:  "find: /path: Permission denied"
            #   GNU/Linux:  "find: '/path': Permission denied"
            grep -E ": Permission denied$" "$log" 2>/dev/null | \
                sed -E -e 's/^find:[[:space:]]+//' \
                       -e "s/^['\"]//" \
                       -e "s/['\"]?: Permission denied$//"
        fi
        if [[ -s "$log.cd" ]]; then
            cat "$log.cd"
        fi
    } 2>/dev/null | LC_ALL=C sort -u
}

# Function: _bulk_dir_is_project
# Purpose: Heuristic — does this directory look like the root of a single project?
#          (a git checkout, or a directory holding a recognised package manifest/lockfile)
# Args: $1 = directory path
# Returns: 0 if it looks like a project root, 1 otherwise
_bulk_dir_is_project() {
    local d="$1" f
    [[ -e "$d/.git" ]] && return 0          # .git dir (normal checkout) or file (git worktree)
    for f in "$d"/package.json "$d"/package-lock.json "$d"/pnpm-lock.yaml "$d"/yarn.lock "$d"/npm-shrinkwrap.json \
             "$d"/pyproject.toml "$d"/setup.py "$d"/setup.cfg "$d"/Pipfile* "$d"/poetry.lock "$d"/uv.lock "$d"/requirements*.txt \
             "$d"/Cargo.toml "$d"/go.mod "$d"/composer.json "$d"/Gemfile "$d"/build.gradle* "$d"/pom.xml "$d"/Package.swift; do
        [[ -e "$f" ]] && return 0
    done
    return 1
}

# Function: _bulk_discover
# Purpose: Print, one absolute path per line, the scan targets found under $1.
#          A directory is taken as a single target if it looks like a project root
#          (so a monorepo is scanned whole), if it has no project anywhere beneath it
#          (a plain content folder, scanned as-is), or if the depth cap is reached.
#          Otherwise it is treated as a "bucket" and its children are descended into.
#          node_modules / vendor / build dirs / hidden dirs are never descended into.
# Args: $1 = directory, $2 = current depth (0 = a bulk root), $3 = max depth
# Returns: 0 if this subtree surfaced at least one project root; 1 if it was emitted as
#          a leaf (no project found). The caller uses this to decide if $1 is a bucket.
_bulk_discover() {
    local dir="$1" depth="$2" maxdepth="$3"

    # Hardening (b): never descend into the --bulk-output directory if it happens to
    # be inside one of the scan roots. Otherwise an output-inside-scan-root setup
    # would self-reference: previous run's report files become next run's scan targets.
    if [[ -n "$BULK_OUTPUT_ABS" ]] && _bulk_is_in_output_dir "$dir"; then
        return 1
    fi

    if _bulk_dir_is_project "$dir"; then
        printf '%s\n' "$dir"
        return 0
    fi
    if [[ "$depth" -ge "$maxdepth" ]]; then
        printf '%s\n' "$dir"          # depth cap: take as-is, but don't call it a project
        return 1
    fi

    # Child directories worth descending into (skip hidden + well-known noise dirs).
    # find's stderr is captured (not discarded) so permission-denied paths can be
    # surfaced at the end of the run — see hardening (a) in run_bulk_scan.
    local -a kids=()
    local k bn k_orig
    while IFS= read -r k; do
        [[ -d "$k" ]] || continue
        bn="$(basename "$k")"
        [[ "$bn" == .* ]] && continue                       # hidden dirs (.git, .cache, .venv, ...)
        [[ "$_BULK_NOISE_DIRS" == *" $bn "* ]] && continue  # node_modules / vendor / build / ...
        # Hardening (a): detect the common case of a chmod-000 (or chmod 700 owned by
        # someone else) subdirectory. find listed the directory entry but we can't
        # actually enter it, so log it and move on instead of silently dropping it.
        if ! [[ -r "$k" && -x "$k" ]]; then
            [[ -n "$BULK_UNREADABLE_LOG" ]] && printf '%s\n' "$k" >> "$BULK_UNREADABLE_LOG.cd"
            continue
        fi
        k_orig="$k"
        k="$(cd "$k" 2>/dev/null && pwd || true)"
        if [[ -z "$k" || ! -d "$k" ]]; then
            [[ -n "$BULK_UNREADABLE_LOG" ]] && printf '%s\n' "$k_orig" >> "$BULK_UNREADABLE_LOG.cd"
            continue
        fi
        # Skip the resolved output directory and anything inside it.
        [[ -n "$BULK_OUTPUT_ABS" ]] && _bulk_is_in_output_dir "$k" && continue
        kids+=("$k")
    done < <(find "$dir" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) 2>>"${BULK_UNREADABLE_LOG:-/dev/null}" | LC_ALL=C sort)

    if [[ ${#kids[@]} -eq 0 ]]; then
        printf '%s\n' "$dir"          # nothing underneath — scan $dir as-is
        return 1
    fi

    # Descend; buffer what the children surface. If any of them surfaced a project, $dir
    # is a "bucket" → emit the children's targets. If none did, $dir is one content unit.
    local found_project=1 out_k buf=""             # found_project: 1 = no (shell truth), 0 = yes
    for k in "${kids[@]}"; do
        # `if` so `set -e` tolerates the non-zero "leaf" return while we capture both
        # the printed targets ($out_k) and the rc.
        if out_k="$(_bulk_discover "$k" "$((depth + 1))" "$maxdepth")"; then
            found_project=0
        fi
        buf+="$out_k"$'\n'
    done

    if [[ "$found_project" -eq 0 ]]; then
        printf '%s' "$buf"
        return 0
    fi
    printf '%s\n' "$dir"
    return 1
}

# Function: _bulk_write_report
# Purpose: Render the aggregate Markdown report from the per-project result rows.
# Args: $1  = report path
#       $2  = rows file (TSV: sev_key emoji label name path H M L rc findings_rel console_rel)
#       $3  = skipped file (TSV: name path)
#       $4  = unreadable-dirs file (one absolute path per line; may be empty)
#       $5  = comma-joined resolved scan roots
#       $6  = paranoid_mode ("true"/"false")
#       $7  = absolute path to this script
#       $8..$14 = n_total n_high n_error n_medium n_low n_clean n_skipped
#       $15..   = per-project child flags (e.g. --paranoid --parallelism 8)
# Modifies: writes $1
_bulk_write_report() {
    local report="$1" rows_file="$2" skipped_file="$3" unreadable_file="$4"
    local resolved_roots="$5"
    local paranoid_mode="$6" self_script="$7"
    local n_total="$8" n_high="$9" n_error="${10}" n_medium="${11}" n_low="${12}" n_clean="${13}" n_skipped="${14}"
    shift 14
    local child_flags_str="$*"
    local per_repo_dir; per_repo_dir="$(dirname "$report")/per-repo"
    local now; now="$(date '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || date '+%Y-%m-%d %H:%M:%S' 2>/dev/null || date)"
    local mode_desc="standard checks"
    [[ "$paranoid_mode" == "true" ]] && mode_desc="paranoid (adds typosquatting + network-exfiltration checks)"

    {
        echo "# Shai-Hulud Bulk Scan — Aggregate Report"
        echo
        echo "| Field | Value |"
        echo "|---|---|"
        echo "| Generated | $now |"
        echo "| Detector | \`$self_script\` |"
        echo "| Mode | $mode_desc |"
        echo "| Per-project flags | \`$child_flags_str\` |"
        echo "| Scan roots | $resolved_roots |"
        echo "| Project discovery | descended up to ${BULK_DEPTH} level(s) below each root (monorepos scanned as one unit) |"
        echo "| Projects scanned | $n_total |"
        echo "| Projects skipped | $n_skipped |"
        echo
        echo "## Result summary"
        echo
        echo "| Outcome | Count |"
        echo "|---|---:|"
        echo "| 🔴 HIGH RISK | $n_high |"
        echo "| ⚠️ Scan errors | $n_error |"
        echo "| 🟡 MEDIUM RISK | $n_medium |"
        echo "| ℹ️ Clean (low-risk notes) | $n_low |"
        echo "| ✅ Clean | $n_clean |"
        echo "| ⏭️ Skipped | $n_skipped |"
        echo
        echo "Each project below was scanned with \`shai-hulud-detector.sh\`; the **Outcome** is"
        echo "that scan's exit status (\`1\` = high-risk indicators, \`2\` = medium-risk, \`0\` = clean)."
        echo "**High / Med / Low** count the distinct file paths the detector flagged at each"
        echo "severity (from its \`--save-log\` output). A *scan error* means the per-project scan"
        echo "did not run to completion — inspect that project's console log under \`per-repo/\`."
        if [[ "$n_high" -gt 0 ]]; then
            echo
            echo "> ⚠️ **$n_high project(s) flagged HIGH RISK.** Until you have ruled out compromise,"
            echo "> treat them accordingly: review the flagged files, rotate any credentials those"
            echo "> projects could reach, inspect \`git status\` / \`git log\` / installed lockfiles for"
            echo "> the indicators described in the detector README, and avoid running \`npm install\`"
            echo "> / \`bun install\` in them again until cleared."
        fi
        echo
        echo "## Per-project results"
        echo
        echo "| Outcome | Project | Path | High | Med | Low | Logs |"
        echo "|---|---|---|---:|---:|---:|---|"
        if [[ -s "$rows_file" ]]; then
            while IFS=$'\t' read -r sev emoji label name path h m l rc flog clog; do
                printf '| %s %s | `%s` | `%s` | %s | %s | %s | [findings](%s) · [console](%s) |\n' \
                    "$emoji" "$label" "$name" "$path" "$h" "$m" "$l" "$flog" "$clog"
            done < <(LC_ALL=C sort -t$'\t' -k1,1n -k4,4 "$rows_file")
        fi
        echo
        echo "## Findings detail"
        echo
        if [[ $((n_high + n_medium + n_error)) -eq 0 ]]; then
            echo "_No high-, medium- or error-level results — see “Clean projects” below._"
            echo
        fi
        if [[ -s "$rows_file" ]]; then
            while IFS=$'\t' read -r sev emoji label name path h m l rc flog clog; do
                [[ "$sev" -ge 4 ]] && continue   # clean projects: summarised in their own section
                echo "### $emoji \`$name\` — $label"
                echo
                echo "- **Path:** \`$path\`"
                echo "- **Detector exit code:** \`$rc\`"
                echo "- **Flagged paths:** $h high · $m medium · $l low"
                echo "- **Logs:** [\`$flog\`]($flog) · [\`$clog\`]($clog)"
                echo
                local _section _count _abs_flog _abs_clog
                _abs_flog="$per_repo_dir/$(basename "$flog")"
                _abs_clog="$per_repo_dir/$(basename "$clog")"
                for _section in HIGH MEDIUM LOW; do
                    _count=$(_bulk_count_section "$_abs_flog" "$_section")
                    [[ "$_count" -gt 0 ]] || continue
                    echo "**$_section — $_count flagged path(s):**"
                    echo
                    echo '```'
                    _bulk_section_lines "$_abs_flog" "$_section"
                    echo '```'
                    echo
                done
                if [[ -f "$_abs_clog" ]]; then
                    echo "<details><summary>Detector console output for <code>$name</code></summary>"
                    echo
                    echo '```text'
                    if [[ "$sev" -eq 1 ]]; then
                        # scan error / unusual exit: the tail is where the failure shows up
                        tail -n 80 "$_abs_clog"
                    else
                        # the report section (banner -> end of output), capped
                        awk '
                            /SHAI-HULUD.*REPORT/ { found = 1 }
                            found {
                                print; n++
                                if (n >= 400) { print "... (truncated — see per-repo console log) ..."; exit }
                            }
                        ' "$_abs_clog"
                    fi
                    echo '```'
                    echo
                    echo "</details>"
                    echo
                fi
            done < <(LC_ALL=C sort -t$'\t' -k1,1n -k4,4 "$rows_file")
        fi
        echo "## Clean projects"
        echo
        echo "No high- or medium-risk indicators. Any low-risk informational matches are noted"
        echo "in parentheses and detailed in that project's \`per-repo/\` log (low-risk matches are"
        echo "typically legitimate framework patterns, not compromise)."
        echo
        local _printed_clean=0
        if [[ -s "$rows_file" ]]; then
            while IFS=$'\t' read -r sev emoji label name path h m l rc flog clog; do
                [[ "$sev" -eq 3 || "$sev" -eq 4 ]] || continue
                _printed_clean=1
                if [[ "$l" -gt 0 ]]; then
                    echo "- ✅ \`$name\` — clean ($l low-risk note(s); see [\`$clog\`]($clog))"
                else
                    echo "- ✅ \`$name\`"
                fi
            done < <(LC_ALL=C sort -t$'\t' -k4,4 "$rows_file")
        fi
        [[ "$_printed_clean" -eq 1 ]] || echo "_(none)_"
        if [[ -s "$skipped_file" ]]; then
            echo
            echo "## Skipped"
            echo
            while IFS=$'\t' read -r sname spath; do
                echo "- \`$sname\` — \`$spath\`"
                echo "  Skipped automatically: this is the Shai-Hulud detector's own repository — its"
                echo "  \`test-cases/\` directory and \`compromised-packages.txt\` contain intentional"
                echo "  malicious fixtures that would otherwise dominate the report. To scan it anyway,"
                echo "  run \`./shai-hulud-detector.sh .\` from inside it."
            done < "$skipped_file"
        fi
        # Hardening (a): list directories that `find` couldn't read during discovery.
        # These are NOT silent skips — a real audit should know which directories were
        # invisible to it. The scan exit code is unaffected; this is informational only.
        if [[ -n "$unreadable_file" && -s "$unreadable_file" ]]; then
            local _n_unread
            _n_unread="$(wc -l < "$unreadable_file" 2>/dev/null | tr -d ' ')"
            echo
            echo "## Unreadable directories ($_n_unread)"
            echo
            echo "These directories were encountered during discovery but could not be read by the"
            echo "scanning user (permission denied). They were skipped entirely — none of their"
            echo "contents were examined for compromised packages or attack indicators. If any of"
            echo "them might contain projects you intended to audit, re-run the scan with the"
            echo "appropriate read access (or as the directory owner)."
            echo
            while IFS= read -r _u; do
                [[ -n "$_u" ]] && echo "- \`$_u\`"
            done < "$unreadable_file"
        fi
        echo
        echo "## Re-running this scan"
        echo
        echo '```sh'
        echo "$self_script --bulk --bulk-depth $BULK_DEPTH $child_flags_str <parent-dir> [more-parent-dirs ...]"
        echo '```'
        echo
        echo "Bulk exit codes: \`1\` = at least one project HIGH RISK · \`2\` = at least one MEDIUM RISK ·"
        echo "\`3\` = at least one scan errored · \`0\` = all clean."
        echo
        echo "_Generated by \`shai-hulud-detector.sh --bulk\`._"
    } > "$report"
}

# Function: run_bulk_scan
# Purpose: --bulk implementation. For each parent directory, scan every immediate
#          (non-hidden) subdirectory by re-invoking this script, then write per-project
#          logs plus a single aggregate Markdown report.
# Args: $1 = paranoid_mode ("true"/"false")
#       $2 = output directory ("" => ./shai-hulud-bulk-report-<timestamp>)
#       $3.. = parent directories whose immediate subdirectories each get scanned
# Returns: 1 if any project HIGH RISK; else 2 if any MEDIUM; else 3 if any scan errored;
#          else 0. (Mirrors the single-scan convention, with 3 added for scan errors.)
run_bulk_scan() {
    local paranoid_mode="$1"; shift
    local out_dir="$1"; shift
    local roots=("$@")

    if [[ ${#roots[@]} -eq 0 ]]; then
        print_status "$RED" "Error: --bulk requires at least one parent directory to scan."
        usage
    fi

    # Absolute path to this script — re-invocation must work regardless of CWD.
    local self_script="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"
    [[ -f "$self_script" ]] || self_script="${BASH_SOURCE[0]}"
    # Re-invoke through the *same* bash that is running us (we already passed the Bash 5
    # check), not via the #! line, so per-project scans don't fall back to an old /bin/bash.
    local self_bash="${BASH:-bash}"
    local self_repo=""
    [[ -d "$SCRIPT_DIR" ]] && self_repo="$(cd "$SCRIPT_DIR" 2>/dev/null && pwd || true)"

    # Flags propagated to every per-project scan.
    local child_flags=()
    [[ "$paranoid_mode" == "true" ]] && child_flags+=("--paranoid")
    [[ "$CHECK_SEMVER_RANGES" == "true" ]] && child_flags+=("--check-semver-ranges")
    [[ -n "$ECOSYSTEM_OVERRIDE" ]] && child_flags+=("--ecosystem" "$ECOSYSTEM_OVERRIDE")
    child_flags+=("--parallelism" "$PARALLELISM")
    case "$GREP_TOOL" in
        git-grep) child_flags+=("--use-git-grep") ;;
        ripgrep)  child_flags+=("--use-ripgrep")  ;;
        grep)     child_flags+=("--use-grep")     ;;
    esac

    # Hardening (b): resolve --bulk-output to an absolute path BEFORE discovery so
    # _bulk_discover can refuse to descend into it. The directory itself is created
    # later (only once we've confirmed there is work to do); resolution here just
    # gives us a stable path to compare candidates against.
    local _bulk_out_input="$out_dir"
    [[ -n "$_bulk_out_input" ]] || _bulk_out_input="shai-hulud-bulk-report-$(date +%Y%m%d-%H%M%S)"
    BULK_OUTPUT_ABS="$(_bulk_resolve_abs "$_bulk_out_input")"

    # Hardening (a): set up two accumulators so permission-denied directories
    # surfaced during discovery can be reported instead of silently dropped.
    # The .log file collects find's stderr (for cases where find itself can't
    # read a directory); the .log.cd file collects entries that are visible to
    # find but fail at our subsequent `cd`/readability check.
    BULK_UNREADABLE_LOG="$TEMP_DIR/bulk_unreadable.log"
    : > "$BULK_UNREADABLE_LOG"
    : > "$BULK_UNREADABLE_LOG.cd"

    # Discover scan targets under each --bulk parent. The parent itself is always treated
    # as a bucket: we look at its immediate children and let _bulk_discover() decide, per
    # child, whether to take it whole (a project / a monorepo / a plain folder) or descend
    # further (a sub-bucket like ~/dev/apps/). BULK_DEPTH caps how deep that descent goes.
    [[ "$BULK_LIST" == "true" ]] || print_status "$ORANGE" "Discovering projects under ${#roots[@]} root(s) (max depth ${BULK_DEPTH})..."
    local targets=()
    declare -A _seen=()
    local root child child_bn discovered tgt
    for root in "${roots[@]}"; do
        if [[ ! -d "$root" ]]; then
            print_status "$YELLOW" "⚠️  Skipping parent '$root' — not a directory."
            continue
        fi
        root="$(cd "$root" && pwd)"
        local _child_orig
        while IFS= read -r child; do
            [[ -d "$child" ]] || continue                       # follows symlinks; drops broken links
            child_bn="$(basename "$child")"
            [[ "$child_bn" == .* ]] && continue                 # hidden dirs
            [[ "$_BULK_NOISE_DIRS" == *" $child_bn "* ]] && continue
            # Hardening (a): record dirs we can't read/enter instead of silently dropping.
            if ! [[ -r "$child" && -x "$child" ]]; then
                [[ -n "$BULK_UNREADABLE_LOG" ]] && printf '%s\n' "$child" >> "$BULK_UNREADABLE_LOG.cd"
                continue
            fi
            _child_orig="$child"
            child="$(cd "$child" 2>/dev/null && pwd || true)"   # canonicalise; skip if unreadable
            if [[ -z "$child" || ! -d "$child" ]]; then
                [[ -n "$BULK_UNREADABLE_LOG" ]] && printf '%s\n' "$_child_orig" >> "$BULK_UNREADABLE_LOG.cd"
                continue
            fi
            # Hardening (b): skip the resolved output dir / anything inside it.
            _bulk_is_in_output_dir "$child" && continue
            discovered="$(_bulk_discover "$child" 1 "$BULK_DEPTH" || true)"   # one abs path per line; rc informational
            while IFS= read -r tgt; do
                [[ -n "$tgt" ]] || continue
                [[ -n "${_seen[$tgt]:-}" ]] && continue
                _seen["$tgt"]=1
                targets+=("$tgt")
            done <<< "$discovered"
        done < <(find "$root" -mindepth 1 -maxdepth 1 \( -type d -o -type l \) 2>>"$BULK_UNREADABLE_LOG" | LC_ALL=C sort)
    done

    # Hardening (a): collect the list of paths that find couldn't read so we can
    # surface them after the bulk run (and so --bulk-list can print them too).
    local -a unreadable_dirs=()
    local _u
    while IFS= read -r _u; do
        [[ -n "$_u" ]] && unreadable_dirs+=("$_u")
    done < <(_bulk_collect_unreadable "$BULK_UNREADABLE_LOG")

    if [[ ${#targets[@]} -eq 0 ]]; then
        print_status "$YELLOW" "No projects found under: ${roots[*]} — nothing to do."
        # Hardening (a): still warn if some directories were unreadable, since that
        # is exactly the kind of run where the user might wrongly conclude there's
        # nothing to scan when in fact projects existed behind locked permissions.
        if [[ ${#unreadable_dirs[@]} -gt 0 ]]; then
            print_status "$YELLOW" "⚠️  Skipped ${#unreadable_dirs[@]} director$([[ ${#unreadable_dirs[@]} -eq 1 ]] && echo "y" || echo "ies") during discovery (permission denied):"
            for _u in "${unreadable_dirs[@]}"; do
                print_status "$YELLOW" "   - $_u"
            done
            print_status "$YELLOW" "   Re-run with read access to include them, or skip this warning by running as the directory owner."
        fi
        exit 0
    fi

    # Stable, predictable ordering for the run and the report (independent of root order).
    local _sorted; _sorted="$(printf '%s\n' "${targets[@]}" | LC_ALL=C sort)"
    targets=()
    while IFS= read -r tgt; do [[ -n "$tgt" ]] && targets+=("$tgt"); done <<< "$_sorted"

    # --bulk-list: just report what would be scanned (after the same self-repo skip) and stop.
    # Hardening (a): if `find` couldn't read any directory during discovery, surface
    # those paths on stderr so the user sees what was missed before kicking off a
    # full bulk scan against the same tree.
    if [[ "$BULK_LIST" == "true" ]]; then
        for tgt in "${targets[@]}"; do
            [[ -n "$self_repo" && "$tgt" == "$self_repo" ]] && continue
            printf '%s\n' "$tgt"
        done
        if [[ ${#unreadable_dirs[@]} -gt 0 ]]; then
            printf '\nSkipped %d director%s during discovery (permission denied):\n' \
                "${#unreadable_dirs[@]}" "$([[ ${#unreadable_dirs[@]} -eq 1 ]] && echo "y" || echo "ies")" >&2
            for _u in "${unreadable_dirs[@]}"; do
                printf '  - %s\n' "$_u" >&2
            done
        fi
        exit 0
    fi

    # Now that we know there is work to do, create the output directory.
    [[ -n "$out_dir" ]] || out_dir="shai-hulud-bulk-report-$(date +%Y%m%d-%H%M%S)"
    # Resolve to an absolute path for error messages (the default is CWD-relative).
    local _out_abs="$out_dir"
    [[ "$_out_abs" == /* ]] || _out_abs="$PWD/$_out_abs"
    if ! mkdir -p "$out_dir" 2>/dev/null; then
        print_status "$RED" "Error: cannot create bulk output directory: $_out_abs"
        exit 1
    fi
    out_dir="$(cd "$out_dir" 2>/dev/null && pwd)" || {
        print_status "$RED" "Error: bulk output directory is not accessible: $_out_abs"
        exit 1
    }
    local per_repo_dir="$out_dir/per-repo"
    mkdir -p "$per_repo_dir"
    local report="$out_dir/aggregate-report.md"

    # Pretty-printed roots for the report header.
    local resolved_roots="" r
    for r in "${roots[@]}"; do
        [[ -d "$r" ]] || continue
        resolved_roots+="${resolved_roots:+, }$(cd "$r" && pwd)"
    done

    print_status "$GREEN" "Bulk scan: ${#targets[@]} project director$([[ ${#targets[@]} -eq 1 ]] && echo "y" || echo "ies") to process."
    print_status "$BLUE"  "Roots:             $resolved_roots"
    print_status "$BLUE"  "Per-project flags: ${child_flags[*]}"
    print_status "$BLUE"  "Output directory:  $out_dir"
    echo

    local rows_file="$TEMP_DIR/bulk_rows.tsv"
    local skipped_file="$TEMP_DIR/bulk_skipped.tsv"
    local raw_tmp="$TEMP_DIR/bulk_console_raw.txt"
    : > "$rows_file"
    : > "$skipped_file"

    local n_total=0 n_high=0 n_error=0 n_medium=0 n_low=0 n_clean=0 n_skipped=0
    local idx=0 t name repo_log console_log rc h m l sev emoji label color

    for t in "${targets[@]}"; do
        idx=$((idx + 1))
        name="$(basename "$t")"

        # The detector's own repo is full of intentional malicious fixtures — skip it.
        if [[ -n "$self_repo" && "$t" == "$self_repo" ]]; then
            printf '%b[%2d/%d]%b %bSKIP%b  %s — detector self-repo (intentional test fixtures)\n' \
                "$BLUE" "$idx" "${#targets[@]}" "$NC" "$YELLOW" "$NC" "$name"
            n_skipped=$((n_skipped + 1))
            printf '%s\t%s\n' "$name" "$t" >> "$skipped_file"
            continue
        fi

        repo_log="$per_repo_dir/$name.findings.log"
        console_log="$per_repo_dir/$name.console.txt"
        if [[ -e "$repo_log" || -e "$console_log" ]]; then
            repo_log="$per_repo_dir/${idx}-$name.findings.log"
            console_log="$per_repo_dir/${idx}-$name.console.txt"
        fi

        printf '%b[%2d/%d]%b SCAN  %s ... ' "$BLUE" "$idx" "${#targets[@]}" "$NC" "$name"

        rc=0
        "$self_bash" "$self_script" "${child_flags[@]}" --save-log "$repo_log" "$t" > "$raw_tmp" 2>&1 || rc=$?
        # Strip ANSI colour codes so the saved console log is plain text.
        sed $'s/\x1b[^m]*m//g' "$raw_tmp" > "$console_log" 2>/dev/null || cp "$raw_tmp" "$console_log" 2>/dev/null || true

        h=$(_bulk_count_section "$repo_log" "HIGH")
        m=$(_bulk_count_section "$repo_log" "MEDIUM")
        l=$(_bulk_count_section "$repo_log" "LOW")
        n_total=$((n_total + 1))

        if [[ -f "$repo_log" ]] && grep -q "SHAI-HULUD.*REPORT" "$console_log" 2>/dev/null; then
            case "$rc" in
                1) sev=0; emoji="🔴"; label="HIGH RISK";   color="$RED";    n_high=$((n_high + 1)) ;;
                2) sev=2; emoji="🟡"; label="MEDIUM RISK"; color="$YELLOW"; n_medium=$((n_medium + 1)) ;;
                0) if [[ "$l" -gt 0 ]]; then
                       sev=3; emoji="ℹ️"; label="clean (low-risk notes)"; color="$BLUE"; n_low=$((n_low + 1))
                   else
                       sev=4; emoji="✅"; label="clean"; color="$GREEN"; n_clean=$((n_clean + 1))
                   fi ;;
                *) sev=1; emoji="⚠️"; label="completed, exit $rc"; color="$YELLOW"; n_error=$((n_error + 1)) ;;
            esac
        else
            sev=1; emoji="⚠️"; label="SCAN ERROR (exit $rc)"; color="$RED"; n_error=$((n_error + 1))
        fi

        printf '%b%s %s%b  (H:%s M:%s L:%s)\n' "$color" "$emoji" "$label" "$NC" "$h" "$m" "$l"

        printf '%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$sev" "$emoji" "$label" "$name" "$t" "$h" "$m" "$l" "$rc" \
            "per-repo/$(basename "$repo_log")" "per-repo/$(basename "$console_log")" >> "$rows_file"
    done

    # Hardening (a): persist the unreadable directories to a file the report writer
    # can include in the aggregate Markdown.
    local unreadable_file="$TEMP_DIR/bulk_unreadable_dirs.txt"
    : > "$unreadable_file"
    if [[ ${#unreadable_dirs[@]} -gt 0 ]]; then
        for _u in "${unreadable_dirs[@]}"; do
            printf '%s\n' "$_u" >> "$unreadable_file"
        done
    fi

    echo
    print_status "$GREEN" "All scans complete — writing aggregate report..."
    _bulk_write_report "$report" "$rows_file" "$skipped_file" "$unreadable_file" "$resolved_roots" "$paranoid_mode" "$self_script" \
        "$n_total" "$n_high" "$n_error" "$n_medium" "$n_low" "$n_clean" "$n_skipped" "${child_flags[@]}"

    echo
    print_status "$BLUE"  "============================================================"
    print_status "$BLUE"  "  BULK SCAN SUMMARY"
    print_status "$BLUE"  "============================================================"
    print_status "$BLUE"  "  Scanned: $n_total      Skipped: $n_skipped"
    if [[ "$n_high"   -gt 0 ]]; then print_status "$RED"    "  🔴 HIGH RISK ............. $n_high";   else print_status "$GREEN" "  🔴 HIGH RISK ............. 0"; fi
    if [[ "$n_error"  -gt 0 ]]; then print_status "$YELLOW" "  ⚠️  Scan errors .......... $n_error"; else print_status "$GREEN" "  ⚠️  Scan errors .......... 0"; fi
    if [[ "$n_medium" -gt 0 ]]; then print_status "$YELLOW" "  🟡 MEDIUM RISK ........... $n_medium"; else print_status "$GREEN" "  🟡 MEDIUM RISK ........... 0"; fi
    print_status "$BLUE"  "  ℹ️  Clean (low-risk notes) $n_low"
    print_status "$GREEN" "  ✅ Clean ................. $n_clean"
    # Hardening (a): tell the user how many directories were unreadable during
    # discovery (and therefore not scanned). The full list is in the aggregate report.
    if [[ ${#unreadable_dirs[@]} -gt 0 ]]; then
        print_status "$YELLOW" "  ⚠️  Unreadable (permission denied): ${#unreadable_dirs[@]}"
        for _u in "${unreadable_dirs[@]}"; do
            print_status "$YELLOW" "        - $_u"
        done
        print_status "$YELLOW" "     Listed under \"Unreadable directories\" in the aggregate report."
    fi
    print_status "$BLUE"  "============================================================"
    print_status "$GREEN" "  📄 Aggregate report: $report"
    print_status "$BLUE"  "  📁 Per-project logs: $per_repo_dir/"
    print_status "$BLUE"  "============================================================"
    echo

    if   [[ "$n_high"   -gt 0 ]]; then return 1
    elif [[ "$n_medium" -gt 0 ]]; then return 2
    elif [[ "$n_error"  -gt 0 ]]; then return 3
    else return 0
    fi
}

# Function: main
# Purpose: Main entry point - parse arguments, load data, run all checks, generate report
# Args: Command line arguments (--paranoid, --help, --parallelism N, directory_path)
# Modifies: All global arrays via detection functions
# Returns: Exit code 0 for clean, 1 for high-risk findings, 2 for medium-risk findings
main() {
    local paranoid_mode=false
    local check_host=false
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
            --check-host)
                check_host=true
                ;;
            --ecosystem)
                if [[ -z "$2" || "$2" == -* ]]; then
                    echo "${RED}error: --ecosystem requires a value (npm, pypi, all, or comma-separated list)${NC}" >&2
                    usage
                fi
                ECOSYSTEM_OVERRIDE="$2"
                shift
                ;;
            --ecosystem=*)
                ECOSYSTEM_OVERRIDE="${1#--ecosystem=}"
                if [[ -z "$ECOSYSTEM_OVERRIDE" ]]; then
                    echo "${RED}error: --ecosystem= requires a value${NC}" >&2
                    usage
                fi
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
            --bulk)
                BULK_MODE=true
                ;;
            --bulk-depth)
                re='^[1-9][0-9]*$'
                if ! [[ $2 =~ $re ]]; then
                    echo "${RED}error: --bulk-depth requires a positive integer${NC}" >&2
                    usage
                fi
                BULK_DEPTH=$2
                shift
                ;;
            --bulk-depth=*)
                BULK_DEPTH="${1#--bulk-depth=}"
                if ! [[ $BULK_DEPTH =~ ^[1-9][0-9]*$ ]]; then
                    echo "${RED}error: --bulk-depth= requires a positive integer${NC}" >&2
                    usage
                fi
                ;;
            --bulk-list)
                BULK_LIST=true
                ;;
            --bulk-output)
                if [[ -z "$2" || "$2" == -* ]]; then
                    echo "${RED}error: --bulk-output requires a directory path${NC}" >&2;
                    usage
                fi
                BULK_OUTPUT="$2"
                shift
                ;;
            --bulk-output=*)
                BULK_OUTPUT="${1#--bulk-output=}"
                if [[ -z "$BULK_OUTPUT" ]]; then
                    echo "${RED}error: --bulk-output= requires a directory path${NC}" >&2
                    usage
                fi
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
                    BULK_ROOTS+=("$1")
                elif [[ "$BULK_MODE" == "true" ]]; then
                    # In --bulk mode every positional argument is another parent directory.
                    BULK_ROOTS+=("$1")
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

    # --bulk: enumerate each parent directory's immediate subdirectories, scan each as
    # its own project, and write an aggregate report. run_bulk_scan re-invokes this
    # script once per subdirectory so every per-repo scan gets a clean state.
    if [[ "$BULK_MODE" == "true" ]]; then
        run_bulk_scan "$paranoid_mode" "$BULK_OUTPUT" "${BULK_ROOTS[@]}"
        exit $?
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

    # Auto-detect (or honor override of) active ecosystems for ecosystem-specific checks.
    # npm checks always run; ecosystem detection only gates additive checks like PyPI.
    detect_ecosystems
    ecosystem_banner

    # Run core Shai-Hulud detection checks (sequential for reliability).
    # Ecosystem-specific checks are dispatched via the ECOSYSTEM_CHECK_FUNCTIONS
    # table so adding a new ecosystem requires zero changes in main(). Auto-detect
    # mode always activates "npm" when any package.json / npm lockfile exists in
    # the tree, preserving the prior CI/CD contract for bare invocations.
    # Explicit --ecosystem=<list> respects the user's choice. Content-pattern
    # checks below (workflows, hashes, postinstall hooks, mini-shai-hulud, axios,
    # sandworm, etc.) always run regardless of ecosystem - they target attack
    # artifacts, not packages.
    print_status "$ORANGE" "[Stage 2/6] Core detection (workflows, hashes, packages, hooks)"
    check_workflow_files "$scan_dir"
    check_file_hashes "$scan_dir"
    local _eco _fn
    for _eco in "${ACTIVE_ECOSYSTEMS[@]}"; do
        # ${!arr[@]} -> keys; -v test on the assoc array
        if [[ -v ECOSYSTEM_CHECK_FUNCTIONS[$_eco] ]]; then
            for _fn in ${ECOSYSTEM_CHECK_FUNCTIONS[$_eco]}; do
                "$_fn" "$scan_dir"
            done
        fi
    done
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
    print_status "$ORANGE" "[Stage 5/6] Advanced detection (discussions, sandworm, axios, mini-shai-hulud, megalodon, web3-mcp, runners, destructive)"
    check_discussion_workflows "$scan_dir"
    check_sandworm_mode_workflows "$scan_dir"
    check_axios_attack_indicators "$scan_dir"
    check_mini_shai_hulud_indicators "$scan_dir" "$check_host"
    check_megalodon_indicators "$scan_dir"
    check_web3_mcp_indicators "$scan_dir"
    check_polymarket_indicators "$scan_dir"
    check_sl4x0_indicators "$scan_dir"
    check_art_template_indicators "$scan_dir"
    check_durabletask_indicators "$scan_dir"
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

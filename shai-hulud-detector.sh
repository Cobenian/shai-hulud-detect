#!/bin/bash

# Shai-Hulud NPM Supply Chain Attack Detection Script
# Detects indicators of compromise from September 2025 and November 2025 npm attacks
# Includes detection for "Shai-Hulud: The Second Coming" (fake Bun runtime attack)
# Usage: ./shai-hulud-detector.sh <directory_to_scan>

set -eo pipefail

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
    touch "$TEMP_DIR/second_coming_repos.txt"
    touch "$TEMP_DIR/actions_secrets_files.txt"
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
NC='\033[0m' # No Color

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

# Function: load_compromised_packages
# Purpose: Load compromised package database from external file or fallback list
# Args: None (reads from compromised-packages.txt in script directory)
# Modifies: COMPROMISED_PACKAGES (global array)
# Returns: Populates COMPROMISED_PACKAGES with 604+ package:version entries
load_compromised_packages() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local packages_file="$script_dir/compromised-packages.txt"

    COMPROMISED_PACKAGES=()

    if [[ -f "$packages_file" ]]; then
        # Read packages from file, skipping comments and empty lines
        while IFS= read -r line; do
            # Trim potential Windows carriage returns
            line="${line%$'\r'}"
            # Skip comments and empty lines
            [[ "$line" =~ ^[[:space:]]*# ]] && continue
            [[ -z "${line// }" ]] && continue

            # Add valid package:version lines to array
            if [[ "$line" =~ ^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+ ]]; then
                COMPROMISED_PACKAGES+=("$line")
            fi
        done < "$packages_file"

        print_status "$BLUE" "📦 Loaded ${#COMPROMISED_PACKAGES[@]} compromised packages from $packages_file"
    else
        # Fallback to embedded list if file not found
        print_status "$YELLOW" "⚠️  Warning: $packages_file not found, using embedded package list"
        COMPROMISED_PACKAGES=(
            # Core compromised packages - fallback list
            "@ctrl/tinycolor:4.1.0"
            "@ctrl/tinycolor:4.1.1"
            "@ctrl/tinycolor:4.1.2"
            "@ctrl/deluge:1.2.0"
            "angulartics2:14.1.2"
            "koa2-swagger-ui:5.11.1"
            "koa2-swagger-ui:5.11.2"
        )
    fi
}

# Known compromised namespaces - packages in these namespaces may be compromised
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
    echo "Usage: $0 [--paranoid] [--parallelism N] <directory_to_scan>"
    echo
    echo "OPTIONS:"
    echo "  --paranoid         Enable additional security checks (typosquatting, network patterns)"
    echo "                     These are general security features, not specific to Shai-Hulud"
    echo "  --parallelism N    Set the number of threads to use for parallelized steps (current: ${PARALLELISM})"
    echo ""
    echo "EXAMPLES:"
    echo "  $0 /path/to/your/project                    # Core Shai-Hulud detection only"
    echo "  $0 --paranoid /path/to/your/project         # Core + advanced security checks"
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

# Function: check_workflow_files
# Purpose: Detect malicious shai-hulud-workflow.yml files in project directories
# Args: $1 = scan_dir (directory to scan)
# Modifies: WORKFLOW_FILES (global array)
# Returns: Populates WORKFLOW_FILES array with paths to suspicious workflow files
check_workflow_files() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for malicious workflow files..."

    # Look specifically for shai-hulud-workflow.yml files
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/workflow_files.txt"
        fi
    done < <(find "$scan_dir" -name "shai-hulud-workflow.yml" 2>/dev/null || true)
}

# Function: check_bun_attack_files
# Purpose: Detect November 2025 "Shai-Hulud: The Second Coming" Bun attack files
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/bun_setup_files.txt, bun_environment_files.txt, malicious_hashes.txt
# Returns: Populates temp files with paths to suspicious Bun-related malicious files
check_bun_attack_files() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for November 2025 Bun attack files..."

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
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/bun_setup_files.txt"

            # Verify hash if sha256sum or shasum is available
            local file_hash=""
            if command -v sha256sum >/dev/null 2>&1; then
                file_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
            elif command -v shasum >/dev/null 2>&1; then
                file_hash=$(shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)
            fi

            if [[ -n "$file_hash" ]]; then
                for known_hash in "${setup_bun_hashes[@]}"; do
                    if [[ "$file_hash" == "$known_hash" ]]; then
                        echo "$file:SHA256=$file_hash (CONFIRMED MALICIOUS - Koi.ai IOC)" >> "$TEMP_DIR/malicious_hashes.txt"
                        break
                    fi
                done
            fi
        fi
    done < <(find "$scan_dir" -name "setup_bun.js" 2>/dev/null || true)

    # Look for bun_environment.js files (10MB+ obfuscated payload)
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/bun_environment_files.txt"

            # Verify hash if sha256sum or shasum is available
            local file_hash=""
            if command -v sha256sum >/dev/null 2>&1; then
                file_hash=$(sha256sum "$file" 2>/dev/null | cut -d' ' -f1)
            elif command -v shasum >/dev/null 2>&1; then
                file_hash=$(shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)
            fi

            if [[ -n "$file_hash" ]]; then
                for known_hash in "${bun_environment_hashes[@]}"; do
                    if [[ "$file_hash" == "$known_hash" ]]; then
                        echo "$file:SHA256=$file_hash (CONFIRMED MALICIOUS - Koi.ai IOC)" >> "$TEMP_DIR/malicious_hashes.txt"
                        break
                    fi
                done
            fi
        fi
    done < <(find "$scan_dir" -name "bun_environment.js" 2>/dev/null || true)
}

# Function: check_new_workflow_patterns
# Purpose: Detect November 2025 new workflow file patterns and actionsSecrets.json
# Args: $1 = scan_dir (directory to scan)
# Modifies: NEW_WORKFLOW_FILES, ACTIONS_SECRETS_FILES (global arrays)
# Returns: Populates arrays with paths to new attack pattern files
check_new_workflow_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for new workflow patterns..."

    # Look for formatter_123456789.yml workflow files
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/new_workflow_files.txt"
        fi
    done < <(find "$scan_dir" -name "formatter_*.yml" -path "*/.github/workflows/*" 2>/dev/null || true)

    # Look for actionsSecrets.json files (double Base64 encoded secrets)
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            echo "$file" >> "$TEMP_DIR/actions_secrets_files.txt"
        fi
    done < <(find "$scan_dir" -name "actionsSecrets.json" 2>/dev/null || true)
}

# Function: check_discussion_workflows
# Purpose: Detect malicious GitHub Actions workflows with discussion triggers
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/discussion_workflows.txt (temp file)
# Returns: Populates discussion_workflows.txt with paths to suspicious discussion-triggered workflows
check_discussion_workflows() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for malicious discussion workflows..."

    # Look for .yml/.yaml files in .github/workflows/ directories
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            # Check for discussion-based triggers
            if grep -q "on:.*discussion" "$file" 2>/dev/null || grep -q "on:\s*discussion" "$file" 2>/dev/null; then
                echo "$file:Discussion trigger detected" >> "$TEMP_DIR/discussion_workflows.txt"
            fi

            # Check for self-hosted runners combined with dynamic payload execution
            if grep -q "runs-on:.*self-hosted" "$file" 2>/dev/null; then
                if grep -q "\${{ github\.event\..*\.body }}" "$file" 2>/dev/null; then
                    echo "$file:Self-hosted runner with dynamic payload execution" >> "$TEMP_DIR/discussion_workflows.txt"
                fi
            fi

            # Check for specific discussion.yaml filename (exact match from Koi.ai report)
            if [[ "$(basename "$file")" == "discussion.yaml" ]] || [[ "$(basename "$file")" == "discussion.yml" ]]; then
                echo "$file:Suspicious discussion workflow filename" >> "$TEMP_DIR/discussion_workflows.txt"
            fi
        fi
    done < <(find "$scan_dir" -path "*/.github/workflows/*" -name "*.yml" -o -name "*.yaml" 2>/dev/null || true)
}

# Function: check_github_runners
# Purpose: Detect self-hosted GitHub Actions runners installed by malware
# Args: $1 = scan_dir (directory to scan)
# Modifies: $TEMP_DIR/github_runners.txt (temp file)
# Returns: Populates github_runners.txt with paths to suspicious runner installations
check_github_runners() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for malicious GitHub Actions runners..."

    # Check for runner directories in common locations
    local runner_patterns=(
        "~/.dev-env"
        ".dev-env"
        "actions-runner"
        ".runner"
        "_work"
    )

    for pattern in "${runner_patterns[@]}"; do
        # Expand tilde to actual home directory for search
        local search_pattern="$pattern"
        if [[ "$pattern" == "~/"* ]]; then
            search_pattern="${HOME}${pattern#~}"
        fi

        # Look for runner directories
        while IFS= read -r dir; do
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
        done < <(find "$scan_dir" -type d -name "$pattern" 2>/dev/null || true)
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
    print_status "$BLUE" "🔍 Checking for destructive payload patterns..."

    # Destructive patterns targeting user files (from Koi.ai report)
    local destructive_patterns=(
        # File deletion patterns - these are specific enough to avoid false positives
        "rm -rf \$HOME"
        "rm -rf ~"
        "del /s /q"
        "Remove-Item -Recurse"
        "fs\.unlinkSync"
        "fs\.rmSync.*recursive"
        "rimraf"

        # Bulk file operations in home directory - refined patterns
        "find[[:space:]]+[^[:space:]]+.*[[:space:]]+-delete"     # More specific find command structure
        "find \$HOME.*-exec rm"
        "find ~.*-exec rm"
        "\$HOME/\*"
        "~/\*"
    )

    # Conditional destruction patterns - these need context limits to avoid false positives in minified files
    local conditional_patterns=(
        # Limited span patterns with command-specific context for JavaScript/Python
        "if.{1,200}credential.{1,50}(fail|error).{1,50}(rm -|fs\.|rimraf|exec|spawn|child_process)"
        "if.{1,200}token.{1,50}not.{1,20}found.{1,50}(rm -|del |fs\.|rimraf|unlinkSync|rmSync)"
        "if.{1,200}github.{1,50}auth.{1,50}fail.{1,50}(rm -|fs\.|rimraf|exec)"
        "catch.{1,100}(rm -rf|fs\.rm|rimraf|exec.*rm)"
        "error.{1,100}(rm -|del |fs\.|rimraf).{1,100}(\$HOME|~/|home.*(directory|folder|path))"

        # Shell-specific patterns (for .sh, .bat, .ps1 files) - can be broader for actual shell commands
        "if.*credential.*(fail|error).*rm"
        "if.*token.*not.*found.*(delete|rm)"
        "if.*github.*auth.*fail.*rm"
        "catch.*rm -rf"
        "error.*delete.*home"
    )

    # Search for destructive patterns in common script files
    local file_extensions=("*.js" "*.sh" "*.ps1" "*.py" "*.bat" "*.cmd")

    for ext in "${file_extensions[@]}"; do
        while IFS= read -r file; do
            if [[ -f "$file" ]]; then
                # Always check specific destructive patterns (low false positive risk)
                for pattern in "${destructive_patterns[@]}"; do
                    if grep -qi "$pattern" "$file" 2>/dev/null; then
                        echo "$file:Destructive pattern detected: $pattern" >> "$TEMP_DIR/destructive_patterns.txt"
                    fi
                done

                # Check conditional patterns based on file type
                case "$file" in
                    *.sh|*.bat|*.ps1|*.cmd)
                        # Shell scripts: Use broader patterns (last 5 in conditional_patterns array)
                        for i in {6..10}; do
                            if [[ $i -lt ${#conditional_patterns[@]} ]]; then
                                pattern="${conditional_patterns[$i]}"
                                if grep -qi "$pattern" "$file" 2>/dev/null; then
                                    echo "$file:Conditional destruction pattern detected: $pattern" >> "$TEMP_DIR/destructive_patterns.txt"
                                fi
                            fi
                        done
                        ;;
                    *.js|*.py)
                        # JavaScript/Python: Use limited span patterns only (first 5 in conditional_patterns array)
                        for i in {0..4}; do
                            if [[ $i -lt ${#conditional_patterns[@]} ]]; then
                                pattern="${conditional_patterns[$i]}"
                                if grep -qiE "$pattern" "$file" 2>/dev/null; then
                                    echo "$file:Conditional destruction pattern detected: $pattern" >> "$TEMP_DIR/destructive_patterns.txt"
                                fi
                            fi
                        done
                        ;;
                esac
            fi
        done < <(find "$scan_dir" -name "$ext" -type f 2>/dev/null || true | head -100)  # Limit to avoid performance issues
    done
}

# Function: check_preinstall_bun_patterns
# Purpose: Detect fake Bun runtime preinstall patterns in package.json files
# Args: $1 = scan_dir (directory to scan)
# Modifies: PREINSTALL_BUN_PATTERNS (global array)
# Returns: Populates array with files containing suspicious preinstall patterns
check_preinstall_bun_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for fake Bun preinstall patterns..."

    # Look for package.json files with suspicious "preinstall": "node setup_bun.js" pattern
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            # Check if the file contains the malicious preinstall pattern
            if grep -q '"preinstall"[[:space:]]*:[[:space:]]*"node setup_bun\.js"' "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/preinstall_bun_patterns.txt"
            fi
        fi
    done < <(find "$scan_dir" -name "package.json" 2>/dev/null || true)
}

# Function: check_github_actions_runner
# Purpose: Detect SHA1HULUD GitHub Actions runners in workflow files
# Args: $1 = scan_dir (directory to scan)
# Modifies: GITHUB_SHA1HULUD_RUNNERS (global array)
# Returns: Populates array with workflow files containing SHA1HULUD runner references
check_github_actions_runner() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for SHA1HULUD GitHub Actions runners..."

    # Look for workflow files containing SHA1HULUD runner names
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            # Check for SHA1HULUD runner references in YAML files
            if grep -qi "SHA1HULUD" "$file" 2>/dev/null; then
                echo "$file" >> "$TEMP_DIR/github_sha1hulud_runners.txt"
            fi
        fi
    done < <(find "$scan_dir" -name "*.yml" -o -name "*.yaml" 2>/dev/null || true)
}

# Function: check_second_coming_repos
# Purpose: Detect repository descriptions with "Sha1-Hulud: The Second Coming" pattern
# Args: $1 = scan_dir (directory to scan)
# Modifies: SECOND_COMING_REPOS (global array)
# Returns: Populates array with git repositories matching the description pattern
check_second_coming_repos() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for 'Second Coming' repository descriptions..."

    # Look for git repositories with the malicious description
    while IFS= read -r repo_dir; do
        if [[ -d "$repo_dir/.git" ]]; then
            # Check git config for repository description with timeout
            local description
            if command -v timeout >/dev/null 2>&1; then
                # GNU timeout is available
                if description=$(timeout 5s git -C "$repo_dir" config --get --local --null --default "" repository.description 2>/dev/null | tr -d '\0'); then
                    if [[ "$description" == *"Sha1-Hulud: The Second Coming"* ]]; then
                        echo "$repo_dir" >> "$TEMP_DIR/second_coming_repos.txt"
                    fi
                fi
            else
                # Fallback for systems without timeout command (e.g., macOS)
                if description=$(git -C "$repo_dir" config --get --local --null --default "" repository.description 2>/dev/null | tr -d '\0'); then
                    if [[ "$description" == *"Sha1-Hulud: The Second Coming"* ]]; then
                        echo "$repo_dir" >> "$TEMP_DIR/second_coming_repos.txt"
                    fi
                fi
            fi
            # Skip repositories where git command times out or fails
        fi
    done < <(find "$scan_dir" -type d -name ".git" | sed 's|/.git$||' 2>/dev/null || true)
}

# Function: check_file_hashes
# Purpose: Scan files and compare SHA256 hashes against known malicious hash list
# Args: $1 = scan_dir (directory to scan)
# Modifies: MALICIOUS_HASHES (global array)
# Returns: Populates MALICIOUS_HASHES array with "file:hash" entries for matches
check_file_hashes() {
    local scan_dir=$1

    local filesCount
    filesCount=$(count_files "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \))
    filesCount=$((filesCount))

    print_status "$BLUE" "🔍 Checking $filesCount files for known malicious content..."

    local filesChecked
    filesChecked=0

    while IFS=" " read -r file_hash file; do
        if [ -z "${file_hash}" ]; then continue; fi

        # Check for malicious files
        for malicious_hash in "${MALICIOUS_HASHLIST[@]}"; do
            if [[ "$malicious_hash" == "$file_hash" ]]; then
                echo "$file:$file_hash" >> "$TEMP_DIR/malicious_hashes.txt"
            fi
        done

        filesChecked=$((filesChecked+1))
        show_progress "$filesChecked" "$filesCount"
    done < <(\
      find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) -print0 2>/dev/null || true |\
      xargs -0 -P ${PARALLELISM} -I. shasum -a 256 . 2>/dev/null
    )
    echo -ne "\r\033[K"
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
    filesCount=$(count_files "$scan_dir" -name "package.json")
    filesCount=$((filesCount))

    print_status "$BLUE" "🔍 Checking $filesCount package.json files for compromised packages..."

    local filesChecked
    filesChecked=0
    while IFS= read -r -d '' package_file; do
        if [ ! -r "${package_file}" ]; then continue; fi

        while IFS=: read -r package_name package_version; do
            package_version=$(echo "${package_version}" | cut -d'"' -f2)
            package_name=$(echo "${package_name}" | cut -d'"' -f2)

            for malicious_info in "${COMPROMISED_PACKAGES[@]}"; do
                local malicious_name="${malicious_info%:*}"
                local malicious_version="${malicious_info#*:}"

                [[ "${package_name}" == "${malicious_name}" ]] || continue

                if [[ "${package_version}" == "${malicious_version}" ]]; then
                    # Exact match, certainly compromised
                    echo "$package_file:$package_name@$package_version" >> "$TEMP_DIR/compromised_found.txt"
                elif semver_match "${malicious_version}" "${package_version}"; then
                    # Semver pattern match - check lockfile for actual installed version
                    local package_dir
                    package_dir=$(dirname "$package_file")
                    local actual_version
                    actual_version=$(get_lockfile_version "$package_name" "$package_dir" "$scan_dir")

                    if [[ -n "$actual_version" ]]; then
                        # Found actual version in lockfile
                        if [[ "$actual_version" == "$malicious_version" ]]; then
                            # Actual installed version is compromised
                            echo "$package_file:$package_name@$actual_version" >> "$TEMP_DIR/compromised_found.txt"
                        else
                            # Lockfile has safe version but package.json range could update to compromised
                            echo "$package_file:$package_name@$package_version (locked to $actual_version - safe)" >> "$TEMP_DIR/lockfile_safe_versions.txt"
                        fi
                    else
                        # No lockfile or package not found - potential risk on install/update
                        echo "$package_file:$package_name@$package_version" >> "$TEMP_DIR/suspicious_found.txt"
                    fi
                fi
            done
        done < <(awk '/"dependencies":|"devDependencies":/{flag=1;next}/}/{flag=0}flag' "${package_file}")

        # Check for suspicious namespaces
        for namespace in "${COMPROMISED_NAMESPACES[@]}"; do
            if grep -q "\"$namespace/" "$package_file" 2>/dev/null; then
                echo "$package_file:Contains packages from compromised namespace: $namespace" >> "$TEMP_DIR/namespace_warnings.txt"
            fi
        done

        filesChecked=$((filesChecked+1))
        show_progress "$filesChecked" "$filesCount"

    done < <(find "$scan_dir" -name "package.json" -type f -print0 2>/dev/null || true)
    echo -ne "\r\033[K"
}

# Function: check_postinstall_hooks
# Purpose: Detect suspicious postinstall scripts that may execute malicious code
# Args: $1 = scan_dir (directory to scan)
# Modifies: POSTINSTALL_HOOKS (global array)
# Returns: Populates POSTINSTALL_HOOKS array with package.json files containing hooks
check_postinstall_hooks() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for suspicious postinstall hooks..."

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
    done < <(find "$scan_dir" -name "package.json" -print0 2>/dev/null || true)
}

# Function: check_content
# Purpose: Search for suspicious content patterns like webhook.site and malicious endpoints
# Args: $1 = scan_dir (directory to scan)
# Modifies: SUSPICIOUS_CONTENT (global array)
# Returns: Populates SUSPICIOUS_CONTENT array with files containing suspicious patterns
check_content() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for suspicious content patterns..."

    # Search for webhook.site references
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            if grep -l "webhook\.site" "$file" >/dev/null 2>&1; then
                echo "$file:webhook.site reference" >> "$TEMP_DIR/suspicious_content.txt"
            fi
            if grep -l "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" "$file" >/dev/null 2>&1; then
                echo "$file:malicious webhook endpoint" >> "$TEMP_DIR/suspicious_content.txt"
            fi
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" \) -print0 2>/dev/null || true)
}

# Function: check_crypto_theft_patterns
# Purpose: Detect cryptocurrency theft patterns from the Chalk/Debug attack (Sept 8, 2025)
# Args: $1 = scan_dir (directory to scan)
# Modifies: CRYPTO_PATTERNS, HIGH_RISK_CRYPTO (global arrays)
# Returns: Populates arrays with wallet hijacking, XMLHttpRequest tampering, and attacker indicators
check_crypto_theft_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for cryptocurrency theft patterns..."

    # Check for wallet address replacement patterns
    while IFS= read -r -d '' file; do
        if grep -q "0x[a-fA-F0-9]\{40\}" "$file" 2>/dev/null; then
            if grep -q -E "ethereum|wallet|address|crypto" "$file" 2>/dev/null; then
                echo "$file:Ethereum wallet address patterns detected" >> "$TEMP_DIR/crypto_patterns.txt"
            fi
        fi

        # Check for XMLHttpRequest hijacking with context-aware detection
        if grep -q "XMLHttpRequest\.prototype\.send" "$file" 2>/dev/null; then
            # Check if it's in a known legitimate framework path
            if [[ "$file" == *"/react-native/Libraries/Network/"* ]] || [[ "$file" == *"/next/dist/compiled/"* ]]; then
                # Check if there are also crypto patterns in the same file
                if grep -q -E "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help" "$file" 2>/dev/null; then
                    echo "$file:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                else
                    echo "$file:XMLHttpRequest prototype modification detected in framework code - LOW RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                fi
            else
                # Check if there are also crypto patterns in the same file
                if grep -q -E "0x[a-fA-F0-9]{40}|checkethereumw|runmask|webhook\.site|npmjs\.help" "$file" 2>/dev/null; then
                    echo "$file:XMLHttpRequest prototype modification with crypto patterns detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                else
                    echo "$file:XMLHttpRequest prototype modification detected - MEDIUM RISK" >> "$TEMP_DIR/crypto_patterns.txt"
                fi
            fi
        fi

        # Check for specific malicious functions from chalk/debug attack
        if grep -q -E "checkethereumw|runmask|newdlocal|_0x19ca67" "$file" 2>/dev/null; then
            echo "$file:Known crypto theft function names detected" >> "$TEMP_DIR/crypto_patterns.txt"
        fi

        # Check for known attacker wallets
        if grep -q -E "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67" "$file" 2>/dev/null; then
            echo "$file:Known attacker wallet address detected - HIGH RISK" >> "$TEMP_DIR/crypto_patterns.txt"
        fi

        # Check for npmjs.help phishing domain
        if grep -q "npmjs\.help" "$file" 2>/dev/null; then
            echo "$file:Phishing domain npmjs.help detected" >> "$TEMP_DIR/crypto_patterns.txt"
        fi

        # Check for javascript obfuscation patterns
        if grep -q "javascript-obfuscator" "$file" 2>/dev/null; then
            echo "$file:JavaScript obfuscation detected" >> "$TEMP_DIR/crypto_patterns.txt"
        fi

        # Check for cryptocurrency address regex patterns
        if grep -q -E "ethereum.*0x\[a-fA-F0-9\]|bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]" "$file" 2>/dev/null; then
            echo "$file:Cryptocurrency regex patterns detected" >> "$TEMP_DIR/crypto_patterns.txt"
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) -print0 2>/dev/null || true)
}

# Function: check_git_branches
# Purpose: Search for suspicious git branches containing "shai-hulud" in their names
# Args: $1 = scan_dir (directory to scan)
# Modifies: GIT_BRANCHES (global array)
# Returns: Populates GIT_BRANCHES array with branch names and commit hashes
check_git_branches() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for suspicious git branches..."

    while IFS= read -r -d '' git_dir; do
        local repo_dir
        repo_dir=$(dirname "$git_dir")
        if [[ -d "$git_dir/refs/heads" ]]; then
            # Look for actual shai-hulud branch files
            while IFS= read -r branch_file; do
                local branch_name
                branch_name=$(basename "$branch_file")
                local commit_hash
                commit_hash=$(cat "$branch_file" 2>/dev/null || true)
                echo "$repo_dir:Branch '$branch_name' (commit: ${commit_hash:0:8}...)" >> "$TEMP_DIR/git_branches.txt"
            done < <(find "$git_dir/refs/heads" -name "*shai-hulud*" -type f 2>/dev/null || true)
        fi
    done < <(find "$scan_dir" -name ".git" -type d -print0 2>/dev/null || true)
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
    print_status "$BLUE" "🔍 Checking for Trufflehog activity and secret scanning..."

    # Look for trufflehog binary files (always HIGH RISK)
    while IFS= read -r binary_file; do
        if [[ -f "$binary_file" ]]; then
            echo "$binary_file:HIGH:Trufflehog binary found" >> "$TEMP_DIR/trufflehog_activity.txt"
        fi
    done < <(find "$scan_dir" -name "*trufflehog*" -type f 2>/dev/null || true)

    # Look for potential trufflehog activity in files
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            local context=$(get_file_context "$file")
            local content_sample=$(head -20 "$file" | tr '\n' ' ')

            # Check for explicit trufflehog references
            if grep -l "trufflehog\|TruffleHog" "$file" >/dev/null 2>&1; then
                case "$context" in
                    "documentation")
                        # Documentation mentioning trufflehog is usually legitimate
                        continue
                        ;;
                    "node_modules"|"type_definitions"|"build_output")
                        # Framework code mentioning trufflehog is suspicious but not high risk
                        echo "$file:MEDIUM:Contains trufflehog references in $context" >> "$TEMP_DIR/trufflehog_activity.txt"
                        ;;
                    *)
                        # Source code with trufflehog references needs investigation
                        if [[ "$content_sample" == *"subprocess"* ]] && [[ "$content_sample" == *"curl"* ]]; then
                            echo "$file:HIGH:Suspicious trufflehog execution pattern" >> "$TEMP_DIR/trufflehog_activity.txt"
                        else
                            echo "$file:MEDIUM:Contains trufflehog references in source code" >> "$TEMP_DIR/trufflehog_activity.txt"
                        fi
                        ;;
                esac
            fi

            # Check for credential scanning combined with exfiltration
            if grep -l "AWS_ACCESS_KEY\|GITHUB_TOKEN\|NPM_TOKEN" "$file" >/dev/null 2>&1; then
                case "$context" in
                    "type_definitions"|"documentation")
                        # Type definitions and docs mentioning credentials are normal
                        continue
                        ;;
                    "node_modules")
                        # Package manager code mentioning credentials might be legitimate
                        echo "$file:LOW:Credential patterns in node_modules" >> "$TEMP_DIR/trufflehog_activity.txt"
                        ;;
                    "configuration")
                        # Config files mentioning credentials might be legitimate
                        if [[ "$content_sample" == *"DefinePlugin"* ]] || [[ "$content_sample" == *"webpack"* ]]; then
                            continue  # webpack config is legitimate
                        fi
                        echo "$file:MEDIUM:Credential patterns in configuration" >> "$TEMP_DIR/trufflehog_activity.txt"
                        ;;
                    *)
                        # Source code mentioning credentials + exfiltration is suspicious
                        if [[ "$content_sample" == *"webhook.site"* ]] || [[ "$content_sample" == *"curl"* ]] || [[ "$content_sample" == *"https.request"* ]]; then
                            echo "$file:HIGH:Credential patterns with potential exfiltration" >> "$TEMP_DIR/trufflehog_activity.txt"
                        else
                            echo "$file:MEDIUM:Contains credential scanning patterns" >> "$TEMP_DIR/trufflehog_activity.txt"
                        fi
                        ;;
                esac
            fi

            # Check for environment variable scanning (refined logic)
            if grep -l "process\.env\|os\.environ\|getenv" "$file" >/dev/null 2>&1; then
                case "$context" in
                    "type_definitions"|"documentation")
                        # Type definitions and docs are normal
                        continue
                        ;;
                    "node_modules"|"build_output")
                        # Framework code using process.env is normal
                        if is_legitimate_pattern "$file" "$content_sample"; then
                            continue
                        fi
                        echo "$file:LOW:Environment variable access in $context" >> "$TEMP_DIR/trufflehog_activity.txt"
                        ;;
                    "configuration")
                        # Config files using env vars is normal
                        continue
                        ;;
                    *)
                        # Only flag if combined with suspicious patterns
                        if [[ "$content_sample" == *"webhook.site"* ]] && [[ "$content_sample" == *"exfiltrat"* ]]; then
                            echo "$file:HIGH:Environment scanning with exfiltration" >> "$TEMP_DIR/trufflehog_activity.txt"
                        elif [[ "$content_sample" == *"scan"* ]] || [[ "$content_sample" == *"harvest"* ]] || [[ "$content_sample" == *"steal"* ]]; then
                            if ! is_legitimate_pattern "$file" "$content_sample"; then
                                echo "$file:MEDIUM:Potentially suspicious environment variable access" >> "$TEMP_DIR/trufflehog_activity.txt"
                            fi
                        fi
                        ;;
                esac
            fi

            # November 2025 specific TruffleHog patterns from "The Second Coming" attack
            if grep -l "TruffleHog.*scan.*credential\|download.*trufflehog\|trufflehog.*env\|trufflehog.*AWS\|trufflehog.*NPM_TOKEN" "$file" >/dev/null 2>&1; then
                # Look for specific patterns indicating automated TruffleHog credential harvesting
                if [[ "$content_sample" == *"download"* ]] && [[ "$content_sample" == *"trufflehog"* ]] && [[ "$content_sample" == *"scan"* ]]; then
                    echo "$file:HIGH:November 2025 pattern - Automated TruffleHog download and credential scanning" >> "$TEMP_DIR/trufflehog_activity.txt"
                elif [[ "$content_sample" == *"GitHub Action"* ]] && [[ "$content_sample" == *"trufflehog"* ]]; then
                    echo "$file:HIGH:November 2025 pattern - TruffleHog in GitHub Actions for credential theft" >> "$TEMP_DIR/trufflehog_activity.txt"
                elif [[ "$content_sample" == *"environment"* ]] && [[ "$content_sample" == *"token"* ]] && [[ "$content_sample" == *"trufflehog"* ]]; then
                    echo "$file:HIGH:November 2025 pattern - TruffleHog environment token harvesting" >> "$TEMP_DIR/trufflehog_activity.txt"
                else
                    echo "$file:MEDIUM:Potential November 2025 TruffleHog attack pattern" >> "$TEMP_DIR/trufflehog_activity.txt"
                fi
            fi

            # Check for specific command execution patterns used in November 2025 attack
            if grep -l "curl.*trufflehog\|wget.*trufflehog\|bunExecutable.*trufflehog" "$file" >/dev/null 2>&1; then
                echo "$file:HIGH:November 2025 pattern - Dynamic TruffleHog download via curl/wget/Bun" >> "$TEMP_DIR/trufflehog_activity.txt"
            fi
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.py" -o -name "*.sh" -o -name "*.json" \) -print0 2>/dev/null || true)
}

# Function: check_shai_hulud_repos
# Purpose: Detect Shai-Hulud worm repositories and malicious migration patterns
# Args: $1 = scan_dir (directory to scan)
# Modifies: SHAI_HULUD_REPOS (global array)
# Returns: Populates SHAI_HULUD_REPOS array with repository patterns and migration indicators
check_shai_hulud_repos() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for Shai-Hulud repositories and migration patterns..."

    while IFS= read -r -d '' git_dir; do
        local repo_dir
        repo_dir=$(dirname "$git_dir")

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
        if [[ -f "$git_dir/config" ]]; then
            if grep -q "shai-hulud\|Shai-Hulud" "$git_dir/config" 2>/dev/null; then
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
    done < <(find "$scan_dir" -name ".git" -type d -print0 2>/dev/null || true)
}

# Function: check_package_integrity
# Purpose: Verify package lock files for compromised packages and version integrity
# Args: $1 = scan_dir (directory to scan)
# Modifies: INTEGRITY_ISSUES (global array)
# Returns: Populates INTEGRITY_ISSUES with compromised packages found in lockfiles
check_package_integrity() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking package lock files for integrity issues..."

    # Check package-lock.json files
    while IFS= read -r -d '' lockfile; do
        if [[ -f "$lockfile" && -r "$lockfile" ]]; then

            # Transform pnpm-lock.yaml into pseudo-package-lock
            org_file="$lockfile"
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                org_file="$lockfile"
                lockfile=$(mktemp "${TMPDIR:-/tmp}/lockfile.XXXXXXXX")
                TEMP_FILES+=("$lockfile")
                transform_pnpm_yaml "$org_file" > "$lockfile"
            fi

            # Look for compromised packages in lockfiles
            for package_info in "${COMPROMISED_PACKAGES[@]}"; do
                local package_name="${package_info%:*}"
                local malicious_version="${package_info#*:}"

                # Look for package-specific blocks to avoid version misattribution
                local found_version=""

                # Try to find the package in node_modules structure (most accurate for package-lock.json)
                if grep -q "\"node_modules/$package_name\"" "$lockfile" 2>/dev/null; then
                    # Extract version from within the specific package block
                    found_version=$(awk -v pkg="node_modules/$package_name" '
                        $0 ~ "\"" pkg "\"" { in_block=1; brace_count=1 }
                        in_block && /\{/ && !($0 ~ "\"" pkg "\"") { brace_count++ }
                        in_block && /\}/ {
                            brace_count--
                            if (brace_count <= 0) { in_block=0 }
                        }
                        in_block && /\s*"version":/ {
                            gsub(/.*"version"[ \t]*:[ \t]*"/, "", $0)
                            gsub(/".*/, "", $0)
                            print $0
                            exit
                        }
                    ' "$lockfile" 2>/dev/null || true) || true

                # Fallback: for older lockfile formats without node_modules structure
                # Only look for exact version matches on the same line
                elif grep -q "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null; then
                    # Extract version from same line (for simple dependency format)
                    found_version=$(grep "\"$package_name\".*:.*\"[0-9]" "$lockfile" 2>/dev/null | head -1 | awk -F':' '{
                        gsub(/.*"/, "", $2)
                        gsub(/".*/, "", $2)
                        print $2
                    }' 2>/dev/null || true) || true
                fi

                if [[ -n "$found_version" && "$found_version" == "$malicious_version" ]]; then
                    echo "$org_file:Compromised package in lockfile: $package_name@$malicious_version" >> "$TEMP_DIR/integrity_issues.txt"
                fi
            done

            # Check for suspicious integrity hash patterns (may indicate tampering)
            local suspicious_hashes
            suspicious_hashes=$(grep -c '"integrity": "sha[0-9]\+-[A-Za-z0-9+/=]*"' "$lockfile" 2>/dev/null || echo "0")

            # Check for recently modified lockfiles with @ctrl packages (potential worm activity)
            if grep -q "@ctrl" "$lockfile" 2>/dev/null; then
                local file_age
                file_age=$(date -r "$lockfile" +%s 2>/dev/null || echo "0")
                local current_time
                current_time=$(date +%s)
                local age_diff=$((current_time - file_age))

                # Flag if lockfile with @ctrl packages was modified in the last 30 days
                if [[ $age_diff -lt 2592000 ]]; then  # 30 days in seconds
                    echo "$org_file:Recently modified lockfile contains @ctrl packages (potential worm activity)" >> "$TEMP_DIR/integrity_issues.txt"
                fi
            fi

            # Revert virtual package-lock
            if [[ "$(basename "$org_file")" == "pnpm-lock.yaml" ]]; then
                rm "$lockfile"
                lockfile="$org_file"
            fi

        fi
    done < <(find "$scan_dir" \( -name "pnpm-lock.yaml" -o -name "yarn.lock" -o -name "package-lock.json" \) -print0 2>/dev/null || true)
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
    done < <(find "$scan_dir" -name "package.json" -print0 2>/dev/null || true)
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
                if grep -q '[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}' "$file" 2>/dev/null; then
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
                if grep -q 'atob(' "$file" 2>/dev/null || grep -q 'base64.*decode' "$file" 2>/dev/null; then
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
            if grep -q "dns-query" "$file" 2>/dev/null || grep -q "application/dns-message" "$file" 2>/dev/null; then
                echo "$file:DNS-over-HTTPS pattern detected" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
            fi

            # Check for WebSocket connections to unusual endpoints
            if grep -q "ws://" "$file" 2>/dev/null || grep -q "wss://" "$file" 2>/dev/null; then
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
            if grep -q "X-Exfiltrate\|X-Data-Export\|X-Credential" "$file" 2>/dev/null; then
                echo "$file:Suspicious HTTP headers detected" >> "$TEMP_DIR/network_exfiltration_warnings.txt"
            fi

            # Check for data encoding that might hide exfiltration (but be more selective)
            if [[ "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* && "$file" != *".min.js"* ]]; then
                if grep -q "btoa(" "$file" 2>/dev/null; then
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
    done < <(find "$scan_dir" \( -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.mjs" \) -print0 2>/dev/null || true)
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
            show_file_preview "$file" "HIGH RISK: setup_bun.js - Fake Bun runtime installation malware"
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/bun_setup_files.txt"
    fi

    if [[ -s "$TEMP_DIR/bun_environment_files.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: November 2025 Bun environment payload detected:"
        while IFS= read -r file; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: bun_environment.js - 10MB+ obfuscated credential harvesting payload"
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

    if [[ -s "$TEMP_DIR/second_coming_repos.txt" ]]; then
        print_status "$RED" "🚨 HIGH RISK: 'Shai-Hulud: The Second Coming' repositories detected:"
        while IFS= read -r repo_dir; do
            echo "   - $repo_dir"
            echo "     Repository description: Sha1-Hulud: The Second Coming."
            high_risk=$((high_risk+1))
        done < "$TEMP_DIR/second_coming_repos.txt"
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
        print_status "$RED" "🔍 SUMMARY:"
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

    # Load compromised packages from external file
    load_compromised_packages

    # Create temporary directory for file-based findings storage
    create_temp_dir

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --paranoid)
                paranoid_mode=true
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

    print_status "$GREEN" "Starting Shai-Hulud detection scan..."
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "Scanning directory: $scan_dir (with paranoid mode enabled)"
    else
        print_status "$BLUE" "Scanning directory: $scan_dir"
    fi
    echo

    # Run core Shai-Hulud detection checks
    check_workflow_files "$scan_dir"
    check_file_hashes "$scan_dir"
    check_packages "$scan_dir"
    check_postinstall_hooks "$scan_dir"
    check_content "$scan_dir"
    check_crypto_theft_patterns "$scan_dir"
    check_trufflehog_activity "$scan_dir"
    check_git_branches "$scan_dir"
    check_shai_hulud_repos "$scan_dir"
    check_package_integrity "$scan_dir"

    # November 2025 "Shai-Hulud: The Second Coming" attack detection
    check_bun_attack_files "$scan_dir"
    check_new_workflow_patterns "$scan_dir"
    check_discussion_workflows "$scan_dir"
    check_github_runners "$scan_dir"
    check_destructive_patterns "$scan_dir"
    check_preinstall_bun_patterns "$scan_dir"
    check_github_actions_runner "$scan_dir"
    check_second_coming_repos "$scan_dir"

    # Run additional security checks only in paranoid mode
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "🔍+ Checking for typosquatting and homoglyph attacks..."
        check_typosquatting "$scan_dir"
        print_status "$BLUE" "🔍+ Checking for network exfiltration patterns..."
        check_network_exfiltration "$scan_dir"
    fi

    # Generate report
    generate_report "$paranoid_mode"

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

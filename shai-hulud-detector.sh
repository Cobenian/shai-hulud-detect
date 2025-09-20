#!/bin/bash

# Shai-Hulud NPM Supply Chain Attack Detection Script
# Detects indicators of compromise from the September 2025 npm attack
# Usage: ./shai-hulud-detector.sh <directory_to_scan>

set -eo pipefail

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

# Load compromised packages from external file
# This allows for easier maintenance and updates as new compromised packages are discovered
# Currently contains 571+ confirmed package versions from multiple September 2025 npm attacks
load_compromised_packages() {
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    local packages_file="$script_dir/compromised-packages.txt"

    COMPROMISED_PACKAGES=()

    if [[ -f "$packages_file" ]]; then
        # Read packages from file, skipping comments and empty lines
        while IFS= read -r line; do
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

# Global arrays to store findings with risk levels
WORKFLOW_FILES=()
MALICIOUS_HASHES=()
COMPROMISED_FOUND=()
SUSPICIOUS_CONTENT=()
CRYPTO_PATTERNS=()
GIT_BRANCHES=()
POSTINSTALL_HOOKS=()
TRUFFLEHOG_ACTIVITY=()
SHAI_HULUD_REPOS=()
NAMESPACE_WARNINGS=()
LOW_RISK_FINDINGS=()
INTEGRITY_ISSUES=()
TYPOSQUATTING_WARNINGS=()
NETWORK_EXFILTRATION_WARNINGS=()

# Usage function
usage() {
    echo "Usage: $0 [--paranoid] <directory_to_scan>"
    echo
    echo "OPTIONS:"
    echo "  --paranoid    Enable additional security checks (typosquatting, network patterns)"
    echo "                These are general security features, not specific to Shai-Hulud"
    echo
    echo "EXAMPLES:"
    echo "  $0 /path/to/your/project                    # Core Shai-Hulud detection only"
    echo "  $0 --paranoid /path/to/your/project         # Core + advanced security checks"
    exit 1
}

# Print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Show file content preview (simplified for less verbose output)
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

# Check for shai-hulud workflow files
check_workflow_files() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for malicious workflow files..."

    # Look specifically for shai-hulud-workflow.yml files
    while IFS= read -r file; do
        if [[ -f "$file" ]]; then
            WORKFLOW_FILES+=("$file")
        fi
    done < <(find "$scan_dir" -name "shai-hulud-workflow.yml" 2>/dev/null)
}

# Check file hashes against known malicious hash
check_file_hashes() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking file hashes for known malicious content..."

    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            local file_hash
            file_hash=$(shasum -a 256 "$file" 2>/dev/null | cut -d' ' -f1)

            # Check for malicious files
            for malicious_hash in "${MALICIOUS_HASHLIST[@]}"; do
                if [[ "$malicious_hash" == "$file_hash" ]]; then
                    MALICIOUS_HASHES+=("$file:$file_hash")
                fi
            done
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) -print0 2>/dev/null)
}

# Reads pnpm.yaml
# Outputs pseudo-package-lock
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

# Check package.json files for compromised packages
check_packages() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking package.json files for compromised packages..."

    while IFS= read -r -d '' package_file; do
        if [[ -f "$package_file" && -r "$package_file" ]]; then
            # Check for specific compromised packages
            for package_info in "${COMPROMISED_PACKAGES[@]}"; do
                local package_name="${package_info%:*}"
                local malicious_version="${package_info#*:}"

                # Check both dependencies and devDependencies sections
                if grep -q "\"$package_name\":" "$package_file" 2>/dev/null; then
                    local found_version
                    found_version=$(grep -A1 "\"$package_name\":" "$package_file" 2>/dev/null | grep -o '"[0-9]\+\.[0-9]\+\.[0-9]\+"' 2>/dev/null | tr -d '"' | head -1 2>/dev/null) || true
                    if [[ -n "$found_version" && "$found_version" == "$malicious_version" ]]; then
                        COMPROMISED_FOUND+=("$package_file:$package_name@$malicious_version")
                    fi
                fi
            done

            # Check for suspicious namespaces
            for namespace in "${COMPROMISED_NAMESPACES[@]}"; do
                if grep -q "\"$namespace/" "$package_file" 2>/dev/null; then
                    NAMESPACE_WARNINGS+=("$package_file:Contains packages from compromised namespace: $namespace")
                fi
            done

        fi
    done < <(find "$scan_dir" -name "package.json" -print0 2>/dev/null)
}

# Check for suspicious postinstall hooks
check_postinstall_hooks() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for suspicious postinstall hooks..."

    while IFS= read -r -d '' package_file; do
        if [[ -f "$package_file" && -r "$package_file" ]]; then
            # Look for postinstall scripts
            if grep -q "\"postinstall\"" "$package_file" 2>/dev/null; then
                local postinstall_cmd
                postinstall_cmd=$(grep -A1 "\"postinstall\"" "$package_file" 2>/dev/null | grep -o '"[^"]*"' 2>/dev/null | tail -1 2>/dev/null | tr -d '"' 2>/dev/null) || true

                # Check for suspicious patterns in postinstall commands
                if [[ -n "$postinstall_cmd" ]] && ([[ "$postinstall_cmd" == *"curl"* ]] || [[ "$postinstall_cmd" == *"wget"* ]] || [[ "$postinstall_cmd" == *"node -e"* ]] || [[ "$postinstall_cmd" == *"eval"* ]]); then
                    POSTINSTALL_HOOKS+=("$package_file:Suspicious postinstall: $postinstall_cmd")
                fi
            fi
        fi
    done < <(find "$scan_dir" -name "package.json" -print0 2>/dev/null)
}

# Check for suspicious content patterns
check_content() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for suspicious content patterns..."

    # Search for webhook.site references
    while IFS= read -r -d '' file; do
        if [[ -f "$file" && -r "$file" ]]; then
            if grep -l "webhook\.site" "$file" >/dev/null 2>&1; then
                SUSPICIOUS_CONTENT+=("$file:webhook.site reference")
            fi
            if grep -l "bb8ca5f6-4175-45d2-b042-fc9ebb8170b7" "$file" >/dev/null 2>&1; then
                SUSPICIOUS_CONTENT+=("$file:malicious webhook endpoint")
            fi
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.yml" -o -name "*.yaml" \) -print0 2>/dev/null)
}

# Check for cryptocurrency theft patterns (Chalk/Debug attack Sept 8, 2025)
check_crypto_theft_patterns() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for cryptocurrency theft patterns..."

    # Check for wallet address replacement patterns
    while IFS= read -r -d '' file; do
        if grep -q "0x[a-fA-F0-9]\{40\}" "$file" 2>/dev/null; then
            if grep -q -E "ethereum|wallet|address|crypto" "$file" 2>/dev/null; then
                CRYPTO_PATTERNS+=("$file:Ethereum wallet address patterns detected")
            fi
        fi

        # Check for XMLHttpRequest hijacking
        if grep -q "XMLHttpRequest\.prototype\.send" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:XMLHttpRequest prototype modification detected")
        fi

        # Check for specific malicious functions from chalk/debug attack
        if grep -q -E "checkethereumw|runmask|newdlocal|_0x19ca67" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:Known crypto theft function names detected")
        fi

        # Check for known attacker wallets
        if grep -q -E "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:Known attacker wallet address detected - HIGH RISK")
        fi

        # Check for npmjs.help phishing domain
        if grep -q "npmjs\.help" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:Phishing domain npmjs.help detected")
        fi

        # Check for javascript obfuscation patterns
        if grep -q "javascript-obfuscator" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:JavaScript obfuscation detected")
        fi

        # Check for cryptocurrency address regex patterns
        if grep -q -E "ethereum.*0x\[a-fA-F0-9\]|bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]" "$file" 2>/dev/null; then
            CRYPTO_PATTERNS+=("$file:Cryptocurrency regex patterns detected")
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) -print0 2>/dev/null)
}

# Check for shai-hulud git branches
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
                commit_hash=$(cat "$branch_file" 2>/dev/null)
                GIT_BRANCHES+=("$repo_dir:Branch '$branch_name' (commit: ${commit_hash:0:8}...)")
            done < <(find "$git_dir/refs/heads" -name "*shai-hulud*" -type f 2>/dev/null)
        fi
    done < <(find "$scan_dir" -name ".git" -type d -print0 2>/dev/null)
}

# Helper function to determine file context
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

# Helper function to check for legitimate patterns
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

# Check for Trufflehog activity and secret scanning with context awareness
check_trufflehog_activity() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for Trufflehog activity and secret scanning..."

    # Look for trufflehog binary files (always HIGH RISK)
    while IFS= read -r binary_file; do
        if [[ -f "$binary_file" ]]; then
            TRUFFLEHOG_ACTIVITY+=("$binary_file:HIGH:Trufflehog binary found")
        fi
    done < <(find "$scan_dir" -name "*trufflehog*" -type f 2>/dev/null)

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
                        TRUFFLEHOG_ACTIVITY+=("$file:MEDIUM:Contains trufflehog references in $context")
                        ;;
                    *)
                        # Source code with trufflehog references needs investigation
                        if [[ "$content_sample" == *"subprocess"* ]] && [[ "$content_sample" == *"curl"* ]]; then
                            TRUFFLEHOG_ACTIVITY+=("$file:HIGH:Suspicious trufflehog execution pattern")
                        else
                            TRUFFLEHOG_ACTIVITY+=("$file:MEDIUM:Contains trufflehog references in source code")
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
                        TRUFFLEHOG_ACTIVITY+=("$file:LOW:Credential patterns in node_modules")
                        ;;
                    "configuration")
                        # Config files mentioning credentials might be legitimate
                        if [[ "$content_sample" == *"DefinePlugin"* ]] || [[ "$content_sample" == *"webpack"* ]]; then
                            continue  # webpack config is legitimate
                        fi
                        TRUFFLEHOG_ACTIVITY+=("$file:MEDIUM:Credential patterns in configuration")
                        ;;
                    *)
                        # Source code mentioning credentials + exfiltration is suspicious
                        if [[ "$content_sample" == *"webhook.site"* ]] || [[ "$content_sample" == *"curl"* ]] || [[ "$content_sample" == *"https.request"* ]]; then
                            TRUFFLEHOG_ACTIVITY+=("$file:HIGH:Credential patterns with potential exfiltration")
                        else
                            TRUFFLEHOG_ACTIVITY+=("$file:MEDIUM:Contains credential scanning patterns")
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
                        TRUFFLEHOG_ACTIVITY+=("$file:LOW:Environment variable access in $context")
                        ;;
                    "configuration")
                        # Config files using env vars is normal
                        continue
                        ;;
                    *)
                        # Only flag if combined with suspicious patterns
                        if [[ "$content_sample" == *"webhook.site"* ]] && [[ "$content_sample" == *"exfiltrat"* ]]; then
                            TRUFFLEHOG_ACTIVITY+=("$file:HIGH:Environment scanning with exfiltration")
                        elif [[ "$content_sample" == *"scan"* ]] || [[ "$content_sample" == *"harvest"* ]] || [[ "$content_sample" == *"steal"* ]]; then
                            if ! is_legitimate_pattern "$file" "$content_sample"; then
                                TRUFFLEHOG_ACTIVITY+=("$file:MEDIUM:Potentially suspicious environment variable access")
                            fi
                        fi
                        ;;
                esac
            fi
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.py" -o -name "*.sh" -o -name "*.json" \) -print0 2>/dev/null)
}

# Check for Shai-Hulud repositories and migration patterns
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
            SHAI_HULUD_REPOS+=("$repo_dir:Repository name contains 'Shai-Hulud'")
        fi

        # Check for migration pattern repositories (new IoC)
        if [[ "$repo_name" == *"-migration"* ]]; then
            SHAI_HULUD_REPOS+=("$repo_dir:Repository name contains migration pattern")
        fi

        # Check for GitHub remote URLs containing shai-hulud
        if [[ -f "$git_dir/config" ]]; then
            if grep -q "shai-hulud\|Shai-Hulud" "$git_dir/config" 2>/dev/null; then
                SHAI_HULUD_REPOS+=("$repo_dir:Git remote contains 'Shai-Hulud'")
            fi
        fi

        # Check for double base64-encoded data.json (new IoC)
        if [[ -f "$repo_dir/data.json" ]]; then
            local content_sample
            content_sample=$(head -5 "$repo_dir/data.json" 2>/dev/null)
            if [[ "$content_sample" == *"eyJ"* ]] && [[ "$content_sample" == *"=="* ]]; then
                SHAI_HULUD_REPOS+=("$repo_dir:Contains suspicious data.json (possible base64-encoded credentials)")
            fi
        fi
    done < <(find "$scan_dir" -name ".git" -type d -print0 2>/dev/null)
}

# Check package-lock.json and yarn.lock files for integrity issues
check_package_integrity() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking package lock files for integrity issues..."

    # Check package-lock.json files
    while IFS= read -r -d '' lockfile; do
        if [[ -f "$lockfile" && -r "$lockfile" ]]; then

            # Transform pnpm-lock.yaml into pseudo-package-lock
            org_file=$lockfile
            if [[ "$(basename $org_file)" == "pnpm-lock.yaml" ]]; then
                org_file=$lockfile
                lockfile=$(mktemp lockfile.XXXXXXXX)
                transform_pnpm_yaml $org_file > $lockfile
            fi

            # Look for compromised packages in lockfiles
            for package_info in "${COMPROMISED_PACKAGES[@]}"; do
                local package_name="${package_info%:*}"
                local malicious_version="${package_info#*:}"

                if grep -q "\"$package_name\"" "$lockfile" 2>/dev/null; then
                    local found_version
                    found_version=$(grep -A5 "\"$package_name\"" "$lockfile" 2>/dev/null | grep '"version":' 2>/dev/null | head -1 2>/dev/null | grep -o '"[0-9]\+\.[0-9]\+\.[0-9]\+"' 2>/dev/null | tr -d '"' 2>/dev/null) || true
                    if [[ -n "$found_version" && "$found_version" == "$malicious_version" ]]; then
                        INTEGRITY_ISSUES+=("$org_file:Compromised package in lockfile: $package_name@$malicious_version")
                    fi
                fi
            done

            # Check for suspicious integrity hash patterns (may indicate tampering)
            local suspicious_hashes
            suspicious_hashes=$(grep -c '"integrity": "sha[0-9]\+-[A-Za-z0-9+/=]*"' "$lockfile" 2>/dev/null || echo "0")

            # Check for recently modified lockfiles with @ctrl packages (potential worm activity)
            if grep -q "@ctrl" "$lockfile" 2>/dev/null; then
                local file_age
                file_age=$(stat -f "%m" "$lockfile" 2>/dev/null || echo "0")
                local current_time
                current_time=$(date +%s)
                local age_diff=$((current_time - file_age))

                # Flag if lockfile with @ctrl packages was modified in the last 30 days
                if [[ $age_diff -lt 2592000 ]]; then  # 30 days in seconds
                    INTEGRITY_ISSUES+=("$org_file:Recently modified lockfile contains @ctrl packages (potential worm activity)")
                fi
            fi

            # Revert virtual package-lock
            if [[ "$(basename $org_file)" == "pnpm-lock.yaml" ]]; then
                rm $lockfile
                lockfile=$org_file
            fi

        fi
    done < <(find "$scan_dir" \( -name "pnpm-lock.yaml" -o -name "yarn.lock" -o -name "package-lock.json" \) -print0 2>/dev/null)
}

# Check for typosquatting and homoglyph attacks
check_typosquatting() {
    local scan_dir=$1

    # Popular packages commonly targeted for typosquatting
    local popular_packages=(
        "react" "vue" "angular" "express" "lodash" "axios" "typescript"
        "webpack" "babel" "eslint" "jest" "mocha" "chalk" "debug"
        "commander" "inquirer" "yargs" "request" "moment" "underscore"
        "jquery" "bootstrap" "socket.io" "redis" "mongoose" "passport"
    )

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
                    if ($0 ~ /^[a-zA-Z@][a-zA-Z0-9@\/\._-]*$/) print $0
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
                    TYPOSQUATTING_WARNINGS+=("$package_file:Potential Unicode/homoglyph characters in package: $package_name")
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
                        TYPOSQUATTING_WARNINGS+=("$package_file:Potential typosquatting pattern '$pattern' in package: $package_name")
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
                                TYPOSQUATTING_WARNINGS+=("$package_file:Potential typosquatting of '$popular': $package_name (1 character difference)")
                            fi
                        fi
                    fi

                    # Check for common typosquatting patterns
                    if [[ ${#package_name} -eq $((${#popular} - 1)) ]]; then
                        # Missing character check
                        for ((i=0; i<=${#popular}; i++)); do
                            local test_name="${popular:0:$i}${popular:$((i+1))}"
                            if [[ "$package_name" == "$test_name" ]]; then
                                TYPOSQUATTING_WARNINGS+=("$package_file:Potential typosquatting of '$popular': $package_name (missing character)")
                                break
                            fi
                        done
                    fi

                    # Check for extra character
                    if [[ ${#package_name} -eq $((${#popular} + 1)) ]]; then
                        for ((i=0; i<=${#package_name}; i++)); do
                            local test_name="${package_name:0:$i}${package_name:$((i+1))}"
                            if [[ "$test_name" == "$popular" ]]; then
                                TYPOSQUATTING_WARNINGS+=("$package_file:Potential typosquatting of '$popular': $package_name (extra character)")
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
                                    TYPOSQUATTING_WARNINGS+=("$package_file:Suspicious namespace variation: $namespace (similar to $suspicious)")
                                fi
                            fi
                        fi
                    done
                fi

            done <<< "$package_names"
        fi
    done < <(find "$scan_dir" -name "package.json" -print0 2>/dev/null)
}

# Check for network exfiltration patterns
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
                            NETWORK_EXFILTRATION_WARNINGS+=("$file:Hardcoded IP addresses found (minified file): $ips_context")
                        else
                            NETWORK_EXFILTRATION_WARNINGS+=("$file:Hardcoded IP addresses found: $ips_context")
                        fi
                    fi
                fi
            fi

            # Check for suspicious domains (but avoid package-lock.json and vendor files to reduce noise)
            if [[ "$file" != *"package-lock.json"* && "$file" != *"yarn.lock"* && "$file" != *"/vendor/"* && "$file" != *"/node_modules/"* ]]; then
                for domain in "${suspicious_domains[@]}"; do
                    # Use word boundaries and URL patterns to avoid false positives like "timeZone" containing "t.me"
                    if grep -q "https\?://[^[:space:]]*$domain\|[[:space:]]$domain[[:space:/]\"\']" "$file" 2>/dev/null; then
                        # Additional check - make sure it's not just a comment or documentation
                        local suspicious_usage
                        suspicious_usage=$(grep "https\?://[^[:space:]]*$domain\|[[:space:]]$domain[[:space:/]\"\']" "$file" 2>/dev/null | grep -v "^[[:space:]]*#\|^[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null) || true
                        if [[ -n "$suspicious_usage" ]]; then
                            # Get line number and context
                            local line_info
                            line_info=$(grep -n "https\?://[^[:space:]]*$domain\|[[:space:]]$domain[[:space:/]\"\']" "$file" 2>/dev/null | grep -v "^[[:space:]]*#\|^[[:space:]]*//" 2>/dev/null | head -1 2>/dev/null) || true
                            local line_num
                            line_num=$(echo "$line_info" | cut -d: -f1 2>/dev/null) || true

                            # Check if it's a minified file or has very long lines
                            if [[ "$file" == *".min.js"* ]] || [[ $(echo "$suspicious_usage" | wc -c 2>/dev/null) -gt 150 ]]; then
                                # Extract just around the domain
                                local snippet
                                snippet=$(echo "$suspicious_usage" | grep -o ".\{0,20\}$domain.\{0,20\}" 2>/dev/null | head -1 2>/dev/null) || true
                                if [[ -n "$line_num" ]]; then
                                    NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious domain found: $domain at line $line_num: ...${snippet}...")
                                else
                                    NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious domain found: $domain: ...${snippet}...")
                                fi
                            else
                                local snippet
                                snippet=$(echo "$suspicious_usage" | cut -c1-80 2>/dev/null) || true
                                if [[ -n "$line_num" ]]; then
                                    NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious domain found: $domain at line $line_num: ${snippet}...")
                                else
                                    NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious domain found: $domain: ${snippet}...")
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
                    line_num=$(grep -n 'atob\|base64.*decode' "$file" 2>/dev/null | head -1 2>/dev/null | cut -d: -f1 2>/dev/null) || true
                    local snippet

                    # For minified files, try to extract just the relevant part
                    if [[ "$file" == *".min.js"* ]] || [[ $(head -1 "$file" 2>/dev/null | wc -c 2>/dev/null) -gt 500 ]]; then
                        # Extract a small window around the atob call
                        if [[ -n "$line_num" ]]; then
                            snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | grep -o '.\{0,30\}atob.\{0,30\}' 2>/dev/null | head -1 2>/dev/null) || true
                            if [[ -z "$snippet" ]]; then
                                snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | grep -o '.\{0,30\}base64.*decode.\{0,30\}' 2>/dev/null | head -1 2>/dev/null) || true
                            fi
                            NETWORK_EXFILTRATION_WARNINGS+=("$file:Base64 decoding at line $line_num: ...${snippet}...")
                        else
                            NETWORK_EXFILTRATION_WARNINGS+=("$file:Base64 decoding detected")
                        fi
                    else
                        snippet=$(sed -n "${line_num}p" "$file" | cut -c1-80)
                        NETWORK_EXFILTRATION_WARNINGS+=("$file:Base64 decoding at line $line_num: ${snippet}...")
                    fi
                fi
            fi

            # Check for DNS-over-HTTPS patterns
            if grep -q "dns-query" "$file" 2>/dev/null || grep -q "application/dns-message" "$file" 2>/dev/null; then
                NETWORK_EXFILTRATION_WARNINGS+=("$file:DNS-over-HTTPS pattern detected")
            fi

            # Check for WebSocket connections to unusual endpoints
            if grep -q "ws://" "$file" 2>/dev/null || grep -q "wss://" "$file" 2>/dev/null; then
                local ws_endpoints
                ws_endpoints=$(grep -o 'wss\?://[^"'\''[:space:]]*' "$file" 2>/dev/null)
                while IFS= read -r endpoint; do
                    [[ -z "$endpoint" ]] && continue
                    # Flag WebSocket connections that don't seem to be localhost or common development
                    if [[ "$endpoint" != *"localhost"* && "$endpoint" != *"127.0.0.1"* ]]; then
                        NETWORK_EXFILTRATION_WARNINGS+=("$file:WebSocket connection to external endpoint: $endpoint")
                    fi
                done <<< "$ws_endpoints"
            fi

            # Check for suspicious HTTP headers
            if grep -q "X-Exfiltrate\|X-Data-Export\|X-Credential" "$file" 2>/dev/null; then
                NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious HTTP headers detected")
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
                            line_num=$(grep -n "btoa(" "$file" 2>/dev/null | head -1 2>/dev/null | cut -d: -f1 2>/dev/null) || true
                            local snippet
                            if [[ -n "$line_num" ]]; then
                                snippet=$(sed -n "${line_num}p" "$file" 2>/dev/null | cut -c1-80 2>/dev/null) || true
                                NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious base64 encoding near network operation at line $line_num: ${snippet}...")
                            else
                                NETWORK_EXFILTRATION_WARNINGS+=("$file:Suspicious base64 encoding near network operation")
                            fi
                        fi
                    fi
                fi
            fi

        fi
    done < <(find "$scan_dir" \( -name "*.js" -o -name "*.ts" -o -name "*.json" -o -name "*.mjs" \) -print0 2>/dev/null)
}

# Generate final report
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

    local high_risk=0
    local medium_risk=0
    local total_issues=0

    # Report malicious workflow files
    if [[ ${#WORKFLOW_FILES[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Malicious workflow files detected:"
        for file in "${WORKFLOW_FILES[@]}"; do
            echo "   - $file"
            show_file_preview "$file" "HIGH RISK: Known malicious workflow filename"
            high_risk=$((high_risk+1))
        done
    fi

    # Report malicious file hashes
    if [[ ${#MALICIOUS_HASHES[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Files with known malicious hashes:"
        for entry in "${MALICIOUS_HASHES[@]}"; do
            local file_path="${entry%:*}"
            local hash="${entry#*:}"
            echo "   - $file_path"
            echo "     Hash: $hash"
            show_file_preview "$file_path" "HIGH RISK: File matches known malicious SHA-256 hash"
            high_risk=$((high_risk+1))
        done
    fi

    # Report compromised packages
    if [[ ${#COMPROMISED_FOUND[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Compromised package versions detected:"
        for entry in "${COMPROMISED_FOUND[@]}"; do
            local file_path="${entry%:*}"
            local package_info="${entry#*:}"
            echo "   - Package: $package_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "HIGH RISK: Contains compromised package version: $package_info"
            high_risk=$((high_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: These specific package versions are known to be compromised.${NC}"
        echo -e "   ${YELLOW}You should immediately update or remove these packages.${NC}"
        echo
    fi

    # Report suspicious content
    if [[ ${#SUSPICIOUS_CONTENT[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious content patterns:"
        for entry in "${SUSPICIOUS_CONTENT[@]}"; do
            local file_path="${entry%:*}"
            local pattern="${entry#*:}"
            echo "   - Pattern: $pattern"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Contains suspicious pattern: $pattern"
            medium_risk=$((medium_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: Manual review required to determine if these are malicious.${NC}"
        echo
    fi

    # Report cryptocurrency theft patterns
    if [[ ${#CRYPTO_PATTERNS[@]} -gt 0 ]]; then
        # Separate HIGH RISK and MEDIUM RISK crypto patterns
        local crypto_high=()
        local crypto_medium=()

        for entry in "${CRYPTO_PATTERNS[@]}"; do
            if [[ "$entry" == *"HIGH RISK"* ]] || [[ "$entry" == *"Known attacker wallet"* ]] || [[ "$entry" == *"XMLHttpRequest prototype"* ]]; then
                crypto_high+=("$entry")
            else
                crypto_medium+=("$entry")
            fi
        done

        # Report HIGH RISK crypto patterns
        if [[ ${#crypto_high[@]} -gt 0 ]]; then
            print_status "$RED" "🚨 HIGH RISK: Cryptocurrency theft patterns detected:"
            for entry in "${crypto_high[@]}"; do
                echo "   - ${entry}"
                high_risk=$((high_risk+1))
            done
            echo -e "   ${RED}NOTE: These patterns strongly indicate crypto theft malware from the September 8 attack.${NC}"
            echo -e "   ${RED}Immediate investigation and remediation required.${NC}"
            echo
        fi

        # Report MEDIUM RISK crypto patterns
        if [[ ${#crypto_medium[@]} -gt 0 ]]; then
            print_status "$YELLOW" "⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:"
            for entry in "${crypto_medium[@]}"; do
                echo "   - ${entry}"
                medium_risk=$((medium_risk+1))
            done
            echo -e "   ${YELLOW}NOTE: These may be legitimate crypto tools or framework code.${NC}"
            echo -e "   ${YELLOW}Manual review recommended to determine if they are malicious.${NC}"
            echo
        fi
    fi

    # Report git branches
    if [[ ${#GIT_BRANCHES[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Suspicious git branches:"
        for entry in "${GIT_BRANCHES[@]}"; do
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
        done
        echo -e "   ${YELLOW}NOTE: 'shai-hulud' branches may indicate compromise.${NC}"
        echo -e "   ${YELLOW}Use the commands above to investigate each branch.${NC}"
        echo
    fi

    # Report suspicious postinstall hooks
    if [[ ${#POSTINSTALL_HOOKS[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Suspicious postinstall hooks detected:"
        for entry in "${POSTINSTALL_HOOKS[@]}"; do
            local file_path="${entry%:*}"
            local hook_info="${entry#*:}"
            echo "   - Hook: $hook_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "HIGH RISK: Contains suspicious postinstall hook: $hook_info"
            high_risk=$((high_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: Postinstall hooks can execute arbitrary code during package installation.${NC}"
        echo -e "   ${YELLOW}Review these hooks carefully for malicious behavior.${NC}"
        echo
    fi

    # Report Trufflehog activity by risk level
    local trufflehog_high=()
    local trufflehog_medium=()
    local trufflehog_low=()

    # Categorize Trufflehog findings by risk level
    for entry in "${TRUFFLEHOG_ACTIVITY[@]}"; do
        local file_path="${entry%%:*}"
        local risk_level="${entry#*:}"
        risk_level="${risk_level%%:*}"
        local activity_info="${entry#*:*:}"

        case "$risk_level" in
            "HIGH")
                trufflehog_high+=("$file_path:$activity_info")
                ;;
            "MEDIUM")
                trufflehog_medium+=("$file_path:$activity_info")
                ;;
            "LOW")
                trufflehog_low+=("$file_path:$activity_info")
                ;;
        esac
    done

    # Report HIGH RISK Trufflehog activity
    if [[ ${#trufflehog_high[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Trufflehog/secret scanning activity detected:"
        for entry in "${trufflehog_high[@]}"; do
            local file_path="${entry%:*}"
            local activity_info="${entry#*:}"
            echo "   - Activity: $activity_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "HIGH RISK: $activity_info"
            high_risk=$((high_risk+1))
        done
        echo -e "   ${RED}NOTE: These patterns indicate likely malicious credential harvesting.${NC}"
        echo -e "   ${RED}Immediate investigation and remediation required.${NC}"
        echo
    fi

    # Report MEDIUM RISK Trufflehog activity
    if [[ ${#trufflehog_medium[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:"
        for entry in "${trufflehog_medium[@]}"; do
            local file_path="${entry%:*}"
            local activity_info="${entry#*:}"
            echo "   - Pattern: $activity_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "MEDIUM RISK: $activity_info"
            medium_risk=$((medium_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: These may be legitimate security tools or framework code.${NC}"
        echo -e "   ${YELLOW}Manual review recommended to determine if they are malicious.${NC}"
        echo
    fi

    # Store LOW RISK findings for optional reporting
    for entry in "${trufflehog_low[@]}"; do
        LOW_RISK_FINDINGS+=("Trufflehog pattern: $entry")
    done

    # Report Shai-Hulud repositories
    if [[ ${#SHAI_HULUD_REPOS[@]} -gt 0 ]]; then
        print_status "$RED" "🚨 HIGH RISK: Shai-Hulud repositories detected:"
        for entry in "${SHAI_HULUD_REPOS[@]}"; do
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
        done
        echo -e "   ${YELLOW}NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration.${NC}"
        echo -e "   ${YELLOW}These should be deleted immediately after investigation.${NC}"
        echo
    fi

    # Report namespace warnings
    if [[ ${#NAMESPACE_WARNINGS[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Packages from compromised namespaces:"
        for entry in "${NAMESPACE_WARNINGS[@]}"; do
            local file_path="${entry%%:*}"
            local namespace_info="${entry#*:}"
            echo "   - Warning: $namespace_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Contains packages from compromised namespace"
            medium_risk=$((medium_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: These namespaces have been compromised but specific versions may vary.${NC}"
        echo -e "   ${YELLOW}Check package versions against known compromise lists.${NC}"
        echo
    fi

    # Report package integrity issues
    if [[ ${#INTEGRITY_ISSUES[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK: Package integrity issues detected:"
        for entry in "${INTEGRITY_ISSUES[@]}"; do
            local file_path="${entry%%:*}"
            local issue_info="${entry#*:}"
            echo "   - Issue: $issue_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Package integrity issue: $issue_info"
            medium_risk=$((medium_risk+1))
        done
        echo -e "   ${YELLOW}NOTE: These issues may indicate tampering with package dependencies.${NC}"
        echo -e "   ${YELLOW}Verify package versions and regenerate lockfiles if necessary.${NC}"
        echo
    fi

    # Report typosquatting warnings (only in paranoid mode)
    if [[ "$paranoid_mode" == "true" && ${#TYPOSQUATTING_WARNINGS[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK (PARANOID): Potential typosquatting/homoglyph attacks detected:"
        local typo_count=0
        for entry in "${TYPOSQUATTING_WARNINGS[@]}"; do
            [[ $typo_count -ge 5 ]] && break
            local file_path="${entry%%:*}"
            local warning_info="${entry#*:}"
            echo "   - Warning: $warning_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Potential typosquatting: $warning_info"
            medium_risk=$((medium_risk+1))
            typo_count=$((typo_count+1))
        done
        if [[ ${#TYPOSQUATTING_WARNINGS[@]} -gt 5 ]]; then
            echo "   - ... and $((${#TYPOSQUATTING_WARNINGS[@]} - 5)) more typosquatting warnings (truncated for brevity)"
        fi
        echo -e "   ${YELLOW}NOTE: These packages may be impersonating legitimate packages.${NC}"
        echo -e "   ${YELLOW}Verify package names carefully and check if they should be legitimate packages.${NC}"
        echo
    fi

    # Report network exfiltration warnings (only in paranoid mode)
    if [[ "$paranoid_mode" == "true" && ${#NETWORK_EXFILTRATION_WARNINGS[@]} -gt 0 ]]; then
        print_status "$YELLOW" "⚠️  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:"
        local net_count=0
        for entry in "${NETWORK_EXFILTRATION_WARNINGS[@]}"; do
            [[ $net_count -ge 5 ]] && break
            local file_path="${entry%%:*}"
            local warning_info="${entry#*:}"
            echo "   - Warning: $warning_info"
            echo "     Found in: $file_path"
            show_file_preview "$file_path" "Network exfiltration pattern: $warning_info"
            medium_risk=$((medium_risk+1))
            net_count=$((net_count+1))
        done
        if [[ ${#NETWORK_EXFILTRATION_WARNINGS[@]} -gt 5 ]]; then
            echo "   - ... and $((${#NETWORK_EXFILTRATION_WARNINGS[@]} - 5)) more network warnings (truncated for brevity)"
        fi
        echo -e "   ${YELLOW}NOTE: These patterns may indicate data exfiltration or communication with C2 servers.${NC}"
        echo -e "   ${YELLOW}Review network connections and data flows carefully.${NC}"
        echo
    fi

    total_issues=$((high_risk + medium_risk))
    local low_risk_count=${#LOW_RISK_FINDINGS[@]}

    # Summary
    print_status "$BLUE" "=============================================="
    if [[ $total_issues -eq 0 ]]; then
        print_status "$GREEN" "✅ No indicators of Shai-Hulud compromise detected."
        print_status "$GREEN" "Your system appears clean from this specific attack."

        # Show low risk findings if any (informational only)
        if [[ $low_risk_count -gt 0 ]]; then
            echo
            print_status "$BLUE" "ℹ️  LOW RISK FINDINGS (informational only):"
            for finding in "${LOW_RISK_FINDINGS[@]}"; do
                echo "   - $finding"
            done
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
            for finding in "${LOW_RISK_FINDINGS[@]}"; do
                echo "   - $finding"
            done
            echo -e "   ${BLUE}NOTE: These are typically legitimate framework patterns.${NC}"
        fi
    fi
    print_status "$BLUE" "=============================================="
}

# Main execution
main() {
    local paranoid_mode=false
    local scan_dir=""

    # Load compromised packages from external file
    load_compromised_packages

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --paranoid)
                paranoid_mode=true
                shift
                ;;
            --help|-h)
                usage
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
                shift
                ;;
        esac
    done

    if [[ -z "$scan_dir" ]]; then
        usage
    fi

    if [[ ! -d "$scan_dir" ]]; then
        print_status "$RED" "Error: Directory '$scan_dir' does not exist."
        exit 1
    fi

    # Convert to absolute path
    scan_dir=$(cd "$scan_dir" && pwd)

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

    # Run additional security checks only in paranoid mode
    if [[ "$paranoid_mode" == "true" ]]; then
        print_status "$BLUE" "🔍+ Checking for typosquatting and homoglyph attacks..."
        check_typosquatting "$scan_dir"
        print_status "$BLUE" "🔍+ Checking for network exfiltration patterns..."
        check_network_exfiltration "$scan_dir"
    fi

    # Generate report
    generate_report "$paranoid_mode"
}

# Run main function with all arguments
main "$@"

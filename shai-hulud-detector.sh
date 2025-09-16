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

# Known malicious file hash
MALICIOUS_HASH="46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"

# Compromised packages and their malicious versions (based on updated threat intelligence)
# Over 187+ packages compromised in the Shai-Hulud worm attack
# Using array format compatible with older bash versions on macOS
COMPROMISED_PACKAGES=(
    # @ctrl namespace
    "@ctrl/tinycolor:4.1.0"
    "@ctrl/deluge:1.2.0"

    # @nativescript-community namespace
    "@nativescript-community/push:1.0.0"
    "@nativescript-community/ui-material-activityindicator:7.2.49"
    "@nativescript-community/ui-material-bottomnavigationbar:7.2.49"
    "@nativescript-community/ui-material-bottomsheet:7.2.49"
    "@nativescript-community/ui-material-button:7.2.49"
    "@nativescript-community/ui-material-cardview:7.2.49"
    "@nativescript-community/ui-material-core:7.2.49"
    "@nativescript-community/ui-material-dialogs:7.2.49"
    "@nativescript-community/ui-material-floatingactionbutton:7.2.49"
    "@nativescript-community/ui-material-progress:7.2.49"
    "@nativescript-community/ui-material-ripple:7.2.49"
    "@nativescript-community/ui-material-slider:7.2.49"
    "@nativescript-community/ui-material-snackbar:7.2.49"
    "@nativescript-community/ui-material-tabs:7.2.49"
    "@nativescript-community/ui-material-textfield:7.2.49"
    "@nativescript-community/ui-material-textview:7.2.49"
)

# Known compromised namespaces - packages in these namespaces may be compromised
COMPROMISED_NAMESPACES=(
    "@crowdstrike"
    "@art-ws"
    "@ngx"
    "@ctrl"
    "@nativescript-community"
)

# Global arrays to store findings with risk levels
WORKFLOW_FILES=()
MALICIOUS_HASHES=()
COMPROMISED_FOUND=()
SUSPICIOUS_CONTENT=()
GIT_BRANCHES=()
POSTINSTALL_HOOKS=()
TRUFFLEHOG_ACTIVITY=()
SHAI_HULUD_REPOS=()
NAMESPACE_WARNINGS=()
LOW_RISK_FINDINGS=()

# Usage function
usage() {
    echo "Usage: $0 <directory_to_scan>"
    echo "Example: $0 /path/to/your/project"
    exit 1
}

# Print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Show file content preview
show_file_preview() {
    local file_path=$1
    local context="$2"
    echo -e "   ${BLUE}┌─ File: $file_path${NC}"
    echo -e "   ${BLUE}│  Context: $context${NC}"
    echo -e "   ${BLUE}│${NC}"

    if [[ -f "$file_path" && -r "$file_path" ]]; then
        # Show first 10 lines with line numbers
        head -10 "$file_path" | while IFS= read -r line; do
            echo -e "   ${BLUE}│${NC}  $line"
        done

        # If file is longer than 10 lines, show indicator
        if [[ $(wc -l < "$file_path" 2>/dev/null) -gt 10 ]]; then
            echo -e "   ${BLUE}│${NC}  ${YELLOW}... (file continues)${NC}"
        fi
    else
        echo -e "   ${BLUE}│${NC}  ${RED}[Unable to read file]${NC}"
    fi
    echo -e "   ${BLUE}└─${NC}"
    echo
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
            if [[ "$file_hash" == "$MALICIOUS_HASH" ]]; then
                MALICIOUS_HASHES+=("$file:$file_hash")
            fi
        fi
    done < <(find "$scan_dir" -type f \( -name "*.js" -o -name "*.ts" -o -name "*.json" \) -print0 2>/dev/null)
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
                if grep -q "\"$package_name\"" "$package_file" 2>/dev/null; then
                    local found_version
                    found_version=$(grep -A1 "\"$package_name\"" "$package_file" | grep -o '"[0-9]\+\.[0-9]\+\.[0-9]\+"' | tr -d '"' | head -1)
                    if [[ "$found_version" == "$malicious_version" ]]; then
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
                postinstall_cmd=$(grep -A1 "\"postinstall\"" "$package_file" | grep -o '"[^"]*"' | tail -1 | tr -d '"')

                # Check for suspicious patterns in postinstall commands
                if [[ "$postinstall_cmd" == *"curl"* ]] || [[ "$postinstall_cmd" == *"wget"* ]] || [[ "$postinstall_cmd" == *"node -e"* ]] || [[ "$postinstall_cmd" == *"eval"* ]]; then
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

# Check for Shai-Hulud repositories
check_shai_hulud_repos() {
    local scan_dir=$1
    print_status "$BLUE" "🔍 Checking for Shai-Hulud repositories..."

    while IFS= read -r -d '' git_dir; do
        local repo_dir
        repo_dir=$(dirname "$git_dir")

        # Check if this is a repository named shai-hulud
        local repo_name
        repo_name=$(basename "$repo_dir")
        if [[ "$repo_name" == *"shai-hulud"* ]] || [[ "$repo_name" == *"Shai-Hulud"* ]]; then
            SHAI_HULUD_REPOS+=("$repo_dir:Repository name contains 'Shai-Hulud'")
        fi

        # Check for GitHub remote URLs containing shai-hulud
        if [[ -f "$git_dir/config" ]]; then
            if grep -q "shai-hulud\|Shai-Hulud" "$git_dir/config" 2>/dev/null; then
                SHAI_HULUD_REPOS+=("$repo_dir:Git remote contains 'Shai-Hulud'")
            fi
        fi
    done < <(find "$scan_dir" -name ".git" -type d -print0 2>/dev/null)
}

# Generate final report
generate_report() {
    echo
    print_status "$BLUE" "=============================================="
    print_status "$BLUE" "      SHAI-HULUD DETECTION REPORT"
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
            show_file_preview "$file" "Known malicious workflow filename"
            ((high_risk++))
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
            show_file_preview "$file_path" "File matches known malicious SHA-256 hash"
            ((high_risk++))
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
            show_file_preview "$file_path" "Contains compromised package version: $package_info"
            ((high_risk++))
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
            ((medium_risk++))
        done
        echo -e "   ${YELLOW}NOTE: Manual review required to determine if these are malicious.${NC}"
        echo
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
            ((medium_risk++))
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
            show_file_preview "$file_path" "Contains suspicious postinstall hook: $hook_info"
            ((high_risk++))
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
            ((high_risk++))
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
            ((medium_risk++))
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
            ((high_risk++))
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
            ((medium_risk++))
        done
        echo -e "   ${YELLOW}NOTE: These namespaces have been compromised but specific versions may vary.${NC}"
        echo -e "   ${YELLOW}Check package versions against known compromise lists.${NC}"
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
    if [[ $# -ne 1 ]]; then
        usage
    fi

    local scan_dir="$1"

    if [[ ! -d "$scan_dir" ]]; then
        print_status "$RED" "Error: Directory '$scan_dir' does not exist."
        exit 1
    fi

    # Convert to absolute path
    scan_dir=$(cd "$scan_dir" && pwd)

    print_status "$GREEN" "Starting Shai-Hulud detection scan..."
    print_status "$BLUE" "Scanning directory: $scan_dir"
    echo

    # Run all checks
    check_workflow_files "$scan_dir"
    check_file_hashes "$scan_dir"
    check_packages "$scan_dir"
    check_postinstall_hooks "$scan_dir"
    check_content "$scan_dir"
    check_trufflehog_activity "$scan_dir"
    check_git_branches "$scan_dir"
    check_shai_hulud_repos "$scan_dir"

    # Generate report
    generate_report
}

# Run main function with all arguments
main "$@"
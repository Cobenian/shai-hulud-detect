#!/usr/bin/env bash
# Shai-Hulud Detector Test Suite
# Validates expected exit codes and risk levels for each test case

set -o pipefail

# Use Bash 5 if available
if command -v /opt/homebrew/bin/bash >/dev/null 2>&1; then
    BASH_CMD="/opt/homebrew/bin/bash"
else
    BASH_CMD="bash"
fi

# `timeout` is GNU coreutils; on macOS it may be `gtimeout` or absent. Degrade gracefully
# so the suite still runs (just without a per-test time limit) where it isn't installed.
if command -v timeout >/dev/null 2>&1; then
    TIMEOUT="timeout 120"
elif command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT="gtimeout 120"
else
    TIMEOUT=""
    echo "Note: 'timeout' not found; running test cases without a per-test time limit." >&2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DETECTOR="$SCRIPT_DIR/shai-hulud-detector.sh"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Expected results: test_name|exit_code|has_high|has_medium|has_low
# Exit codes: 0=clean, 1=high risk, 2=medium only
# These are the CORRECT expected values (matching original behavior where it works,
# or improved behavior where original had bugs like timeouts)
declare -A EXPECTED=(
    ["axios-attack"]="1|yes|no|no"              # HIGH: March 2026 axios supply chain attack IoCs
    ["chalk-debug-attack"]="1|yes|yes|no"      # HIGH: compromised packages + MEDIUM lockfile
    ["clean-project"]="0|no|no|no"             # Clean
    ["common-crypto-libs"]="2|no|yes|no"       # MEDIUM: crypto patterns
    ["comprehensive-test"]="0|no|no|no"        # Clean
    ["debug-js"]="0|no|no|no"                  # Clean
    ["destructive-patterns"]="1|no|yes|no"     # MEDIUM: secret scanning (not HIGH)
    ["discussion-workflows"]="1|yes|no|no"     # HIGH: malicious workflows
    ["edge-case-project"]="0|no|no|no"         # Clean (no detections)
    ["false-positive-project"]="2|no|yes|no"   # MEDIUM: potential false positives
    ["github-actions-runners"]="1|yes|no|no"   # HIGH: malicious runners
    ["gitlab-false-positive"]="0|no|no|no"    # Clean: non-.github YAML files (issue #83)
    ["hash-verification"]="1|yes|no|no"        # HIGH: known malicious hashes (was timeout in orig)
    ["infected-lockfile"]="2|no|yes|no"        # MEDIUM: lockfile issues
    ["infected-lockfile-pnpm"]="2|no|yes|no"   # MEDIUM: pnpm lockfile issues
    ["infected-project"]="1|yes|yes|no"        # HIGH: multiple indicators
    ["legitimate-crypto"]="2|no|yes|no"        # MEDIUM: legitimate crypto patterns
    ["legitimate-security-project"]="2|no|yes|no" # MEDIUM: security tool patterns
    ["lockfile-comprehensive-test"]="2|no|yes|no" # MEDIUM: lockfile compromise detected
    ["lockfile-compromised"]="1|yes|yes|no"    # HIGH: compromised packages
    ["lockfile-false-positive"]="0|no|no|no"   # Clean: false positive handling
    ["lockfile-safe-versions"]="0|no|no|no"    # Clean: safe versions
    ["minified-false-positives"]="1|no|yes|no" # MEDIUM: secret scanning
    ["mixed-project"]="2|no|yes|yes"           # MEDIUM + LOW
    ["multi-hash-detection"]="1|yes|no|no"     # HIGH: malicious hashes
    ["namespace-warning"]="0|no|no|yes"        # LOW: namespace warning
    ["network-exfiltration-project"]="2|no|yes|no" # TODO: Fix trufflehog HIGH detection
    ["no-lockfile-test"]="0|no|no|no"          # Clean
    ["november-2025-attack"]="1|yes|yes|no"    # HIGH: November 2025 attack (was timeout in orig)
    ["sandworm-mode-workflow"]="1|yes|no|no"   # HIGH: February 2026 SANDWORM_MODE workflow IOC
    ["tanstack-attack"]="1|yes|no|no"          # HIGH: May 2026 Mini Shai-Hulud TanStack IOCs (router_init.js, wipe-threat, malicious optionalDependencies, compromised package versions)
    ["tanstack-clean"]="0|no|no|no"            # Clean: last-known-good @tanstack versions (1.169.4)
    ["mini-shai-hulud-dead-mans-switch"]="1|yes|no|no"  # HIGH: in-tree dead-man's-switch artifacts (gh-token-monitor.sh, plist)
    ["pypi-attack-requirements"]="1|yes|no|no" # HIGH: PyPI mistralai==2.4.6 (Mini Shai-Hulud cross-ecosystem spread)
    ["pypi-attack-poetry"]="1|yes|no|no"       # HIGH: PyPI guardrails-ai==0.10.1 in pyproject.toml + poetry.lock
    ["polyglot-attack"]="1|yes|no|no"          # HIGH: both npm (@tanstack/react-router) AND PyPI (mistralai) compromises in one repo
    ["pypi-clean"]="0|no|no|no"                # Clean: safe versions of campaign-targeted PyPI packages
    ["semver-matching"]="0|no|no|yes"          # LOW: semver edge cases
    ["semver-wildcards"]="0|no|no|no"          # Clean
    ["spaces-in-filenames"]="0|no|no|no"       # Clean: handles spaces in filenames (issue #92)
    ["typosquatting-project"]="0|no|no|no"     # Clean
    ["xmlhttp-legitimate"]="0|no|no|yes"       # LOW: framework XMLHttpRequest
    ["xmlhttp-malicious"]="1|yes|yes|no"       # HIGH: malicious XMLHttpRequest + MEDIUM patterns
)

passed=0
failed=0
total=0

echo "========================================"
echo "  Shai-Hulud Detector Test Suite"
echo "========================================"
echo ""

for test_dir in "$SCRIPT_DIR"/test-cases/*/; do
    test_name=$(basename "$test_dir")

    # Skip if not in expected list
    if [[ -z "${EXPECTED[$test_name]}" ]]; then
        echo -e "${YELLOW}SKIP${NC}: $test_name (no expected result defined)"
        continue
    fi

    ((total++))

    # Run detector
    result=$($TIMEOUT "$BASH_CMD" "$DETECTOR" "$test_dir" 2>&1)
    actual_exit=$?

    # Handle timeout
    if [[ $actual_exit -eq 124 ]]; then
        echo -e "${RED}FAIL${NC}: $test_name - TIMEOUT"
        ((failed++))
        continue
    fi

    # Parse expected
    IFS='|' read -r exp_exit exp_high exp_med exp_low <<< "${EXPECTED[$test_name]}"

    # Check actual results
    has_high="no"
    has_med="no"
    has_low="no"

    if echo "$result" | grep -q "HIGH RISK"; then
        has_high="yes"
    fi
    if echo "$result" | grep -q "MEDIUM RISK"; then
        has_med="yes"
    fi
    if echo "$result" | grep -q "LOW RISK"; then
        has_low="yes"
    fi

    # Compare
    errors=""

    if [[ "$actual_exit" != "$exp_exit" ]]; then
        errors+=" exit($actual_exit!=$exp_exit)"
    fi
    if [[ "$has_high" != "$exp_high" ]]; then
        errors+=" high($has_high!=$exp_high)"
    fi
    if [[ "$has_med" != "$exp_med" ]]; then
        errors+=" med($has_med!=$exp_med)"
    fi
    if [[ "$has_low" != "$exp_low" ]]; then
        errors+=" low($has_low!=$exp_low)"
    fi

    if [[ -z "$errors" ]]; then
        echo -e "${GREEN}PASS${NC}: $test_name"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: $test_name -$errors"
        ((failed++))
    fi
done

echo ""
echo "========================================"
echo "  Results: $passed/$total passed, $failed failed"
echo "========================================"

# Test --save-log feature
echo ""
echo "========================================"
echo "  Testing --save-log feature"
echo "========================================"

LOG_FILE="/tmp/shai-hulud-test-log-$$.txt"

# Test 1: --save-log creates file with correct structure
"$BASH_CMD" "$DETECTOR" --save-log "$LOG_FILE" "$SCRIPT_DIR/test-cases/infected-project" >/dev/null 2>&1
if [[ -f "$LOG_FILE" ]]; then
    # Check for all three section headers
    if grep -q "^# HIGH" "$LOG_FILE" && grep -q "^# MEDIUM" "$LOG_FILE" && grep -q "^# LOW" "$LOG_FILE"; then
        echo -e "${GREEN}PASS${NC}: --save-log creates file with correct section headers"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --save-log missing section headers"
        ((failed++))
    fi
    ((total++))

    # Check that HIGH section has entries (infected-project should have high risk findings)
    high_count=$(sed -n '/^# HIGH/,/^# MEDIUM/p' "$LOG_FILE" | grep -c "^/" || echo "0")
    if [[ $high_count -gt 0 ]]; then
        echo -e "${GREEN}PASS${NC}: --save-log HIGH section has $high_count entries"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --save-log HIGH section is empty for infected-project"
        ((failed++))
    fi
    ((total++))
else
    echo -e "${RED}FAIL${NC}: --save-log did not create output file"
    ((failed++))
    ((total++))
fi

# Test 2: Clean project produces empty sections (just headers)
"$BASH_CMD" "$DETECTOR" --save-log "$LOG_FILE" "$SCRIPT_DIR/test-cases/clean-project" >/dev/null 2>&1
if [[ -f "$LOG_FILE" ]]; then
    # Count lines that are file paths (start with /)
    path_count=$(grep -c "^/" "$LOG_FILE" 2>/dev/null || true)
    path_count=${path_count:-0}
    if [[ "$path_count" -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}: --save-log clean project has no file entries"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --save-log clean project has unexpected entries ($path_count)"
        ((failed++))
    fi
    ((total++))
fi

# Cleanup
rm -f "$LOG_FILE"

# ============================================================
#  Testing --bulk mode (project discovery + aggregate report)
# ============================================================
echo ""
echo "========================================"
echo "  Testing --bulk mode"
echo "========================================"

BULK_TMP="$(mktemp -d 2>/dev/null || echo "/tmp/shai-hulud-bulk-test-$$")"
mkdir -p "$BULK_TMP"

# Build a small synthetic tree of "projects" inside bucket folders:
#   <tmp>/dev/apps/{proj-a,proj-b}      -> a sub-bucket: two separate projects
#   <tmp>/dev/monorepo/...              -> has a root package.json -> scanned whole, not split
#   <tmp>/dev/notes/{2024,2025}         -> plain content folder -> scanned whole, not split
#   <tmp>/dev/node_modules/leftpad/...  -> a noise dir -> never descended into
#   <tmp>/work/loud-project/...         -> a project carrying a HIGH-risk indicator
#   <tmp>/work/quiet-project/...        -> a clean project
TREE="$BULK_TMP/roots"
mkdir -p \
    "$TREE/dev/apps/proj-a/src" "$TREE/dev/apps/proj-b" \
    "$TREE/dev/monorepo/packages/sub" \
    "$TREE/dev/notes/2024" "$TREE/dev/notes/2025" \
    "$TREE/dev/node_modules/leftpad" \
    "$TREE/work/loud-project/.github/workflows" \
    "$TREE/work/quiet-project"
echo '{"name":"proj-a"}'                                > "$TREE/dev/apps/proj-a/package.json"
echo 'export const x = 1;'                              > "$TREE/dev/apps/proj-a/src/index.js"
echo '{"name":"proj-b"}'                                > "$TREE/dev/apps/proj-b/package.json"
echo '{"name":"monorepo","workspaces":["packages/*"]}' > "$TREE/dev/monorepo/package.json"
echo '{"name":"sub"}'                                   > "$TREE/dev/monorepo/packages/sub/package.json"
echo '# notes 2024'                                     > "$TREE/dev/notes/2024/jan.md"
echo '# notes 2025'                                     > "$TREE/dev/notes/2025/feb.md"
echo '{"name":"leftpad"}'                               > "$TREE/dev/node_modules/leftpad/package.json"
echo '{"name":"loud-project"}'                          > "$TREE/work/loud-project/package.json"
printf 'name: shai-hulud\non: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n' \
                                                        > "$TREE/work/loud-project/.github/workflows/shai-hulud-workflow.yml"
echo '{"name":"quiet-project"}'                         > "$TREE/work/quiet-project/package.json"

# Test: --bulk --bulk-list discovers projects through bucket folders (default depth)
discovered="$("$BASH_CMD" "$DETECTOR" --bulk --bulk-list "$TREE/dev" "$TREE/work" 2>/dev/null | grep '^/' || true)"
disc_count="$(printf '%s\n' "$discovered" | grep -c '^/' || true)"; disc_count="${disc_count:-0}"
((total++))
if [[ "$disc_count" -eq 6 ]] \
   && grep -q "/dev/apps/proj-a$"     <<<"$discovered" \
   && grep -q "/dev/apps/proj-b$"     <<<"$discovered" \
   && grep -q "/dev/monorepo$"        <<<"$discovered" \
   && grep -q "/dev/notes$"           <<<"$discovered" \
   && grep -q "/work/loud-project$"   <<<"$discovered" \
   && grep -q "/work/quiet-project$"  <<<"$discovered"; then
    echo -e "${GREEN}PASS${NC}: --bulk-list discovers projects through bucket folders ($disc_count found)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk-list discovery wrong (count=$disc_count):"
    echo "$discovered" | sed 's/^/         /'
    ((failed++))
fi

# Test: --bulk-list keeps monorepos whole and never descends into node_modules / nested non-projects
((total++))
if ! grep -q "/monorepo/packages/sub" <<<"$discovered" \
   && ! grep -q "/node_modules/"       <<<"$discovered" \
   && ! grep -q "/notes/2024"          <<<"$discovered" \
   && ! grep -q "/notes/2025"          <<<"$discovered"; then
    echo -e "${GREEN}PASS${NC}: --bulk-list keeps monorepos whole; skips node_modules and nested non-projects"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk-list split a monorepo or descended into node_modules:"
    echo "$discovered" | sed 's/^/         /'
    ((failed++))
fi

# Test: --bulk-depth 1 = flat (one entry per immediate, non-noise subdirectory)
flat="$("$BASH_CMD" "$DETECTOR" --bulk --bulk-list --bulk-depth 1 "$TREE/dev" "$TREE/work" 2>/dev/null | grep '^/' || true)"
flat_count="$(printf '%s\n' "$flat" | grep -c '^/' || true)"; flat_count="${flat_count:-0}"
((total++))
if [[ "$flat_count" -eq 5 ]] \
   && grep -q "/dev/apps$"            <<<"$flat" \
   && grep -q "/dev/monorepo$"        <<<"$flat" \
   && grep -q "/dev/notes$"           <<<"$flat" \
   && grep -q "/work/loud-project$"   <<<"$flat" \
   && grep -q "/work/quiet-project$"  <<<"$flat" \
   && ! grep -q "/dev/apps/proj-a"    <<<"$flat"; then
    echo -e "${GREEN}PASS${NC}: --bulk-depth 1 is flat (one entry per immediate subdirectory, $flat_count found)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk-depth 1 not flat (count=$flat_count):"
    echo "$flat" | sed 's/^/         /'
    ((failed++))
fi

# Test: --bulk runs each discovered project, writes an aggregate report, aggregates exit codes
BULK_OUT="$BULK_TMP/report"
"$BASH_CMD" "$DETECTOR" --bulk --bulk-output "$BULK_OUT" "$TREE/dev" "$TREE/work" >/dev/null 2>&1
bulk_rc=$?
((total++))
if [[ "$bulk_rc" -eq 1 ]]; then
    echo -e "${GREEN}PASS${NC}: --bulk exit code is 1 (a project flagged HIGH RISK)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk exit code is $bulk_rc, expected 1"
    ((failed++))
fi

((total++))
if [[ -f "$BULK_OUT/aggregate-report.md" ]] \
   && grep -q "Shai-Hulud Bulk Scan"   "$BULK_OUT/aggregate-report.md" \
   && grep -q "## Per-project results" "$BULK_OUT/aggregate-report.md" \
   && grep -q "quiet-project"          "$BULK_OUT/aggregate-report.md"; then
    echo -e "${GREEN}PASS${NC}: --bulk writes a structured aggregate-report.md covering all projects"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk aggregate report missing, malformed, or incomplete"
    ((failed++))
fi

((total++))
if [[ -f "$BULK_OUT/per-repo/loud-project.findings.log" ]] \
   && [[ -f "$BULK_OUT/per-repo/loud-project.console.txt" ]] \
   && grep -q "loud-project" "$BULK_OUT/aggregate-report.md" \
   && grep -q "shai-hulud-workflow.yml" "$BULK_OUT/per-repo/loud-project.findings.log"; then
    echo -e "${GREEN}PASS${NC}: --bulk writes per-project logs and records the HIGH finding"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk per-project logs missing or HIGH finding not recorded"
    ((failed++))
fi

# Test: --bulk on a nonexistent root exits 0 and leaves no stray output directory in CWD
NOSTRAY="$BULK_TMP/nostray"
mkdir -p "$NOSTRAY"
( cd "$NOSTRAY" && "$BASH_CMD" "$DETECTOR" --bulk "/no-such-dir-$$-$RANDOM" >/dev/null 2>&1 )
nostray_rc=$?
((total++))
if [[ "$nostray_rc" -eq 0 ]] && [[ -z "$(ls -A "$NOSTRAY" 2>/dev/null)" ]]; then
    echo -e "${GREEN}PASS${NC}: --bulk on a missing root exits 0 and creates no stray output directory"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk on a missing root: rc=$nostray_rc, CWD contents: '$(ls -A "$NOSTRAY" 2>/dev/null)'"
    ((failed++))
fi

# Test: hardening (a) — chmod-000 subdir during discovery is reported as unreadable,
# not silently dropped. We build a tree with one readable and one unreadable project,
# and verify (i) --bulk-list still surfaces the readable one, (ii) the unreadable
# project's path appears in --bulk-list's permission-denied warning on stderr, AND
# (iii) the aggregate report's "Unreadable directories" section lists it.
HARDA_TMP="$BULK_TMP/hardening-a"
mkdir -p "$HARDA_TMP/visible-proj" "$HARDA_TMP/locked-proj"
echo '{"name":"visible"}' > "$HARDA_TMP/visible-proj/package.json"
echo '{"name":"locked"}'  > "$HARDA_TMP/locked-proj/package.json"
chmod 000 "$HARDA_TMP/locked-proj"

# (i) and (ii) via --bulk-list. Output mixes stdout (project list) and stderr
# (permission-denied warning); we want both to appear.
harda_list_out="$("$BASH_CMD" "$DETECTOR" --bulk --bulk-list "$HARDA_TMP" 2>&1 || true)"
((total++))
if grep -q "/visible-proj" <<< "$harda_list_out" \
   && grep -qi "permission denied" <<< "$harda_list_out" \
   && grep -q "/locked-proj" <<< "$harda_list_out"; then
    echo -e "${GREEN}PASS${NC}: --bulk-list lists readable projects and warns about unreadable ones"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk-list failed to surface readable+unreadable correctly"
    echo "  output was:"
    echo "$harda_list_out" | sed 's/^/    /' | head -20
    ((failed++))
fi

# (iii) via full --bulk run
HARDA_OUT="$BULK_TMP/hardening-a-report"
harda_run_out="$("$BASH_CMD" "$DETECTOR" --bulk --bulk-output "$HARDA_OUT" "$HARDA_TMP" 2>&1 || true)"
((total++))
if grep -q "Unreadable (permission denied): 1" <<< "$harda_run_out" \
   && [[ -f "$HARDA_OUT/aggregate-report.md" ]] \
   && grep -q "Unreadable directories" "$HARDA_OUT/aggregate-report.md" \
   && grep -q "locked-proj" "$HARDA_OUT/aggregate-report.md"; then
    echo -e "${GREEN}PASS${NC}: --bulk surfaces unreadable dirs in summary + aggregate report"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk did not surface unreadable directory"
    echo "  summary tail:"
    echo "$harda_run_out" | tail -15 | sed 's/^/    /'
    echo "  report 'Unreadable' section:"
    grep -A2 "Unreadable" "$HARDA_OUT/aggregate-report.md" 2>/dev/null | sed 's/^/    /'
    ((failed++))
fi

# Restore perms so the cleanup at end of script can remove the tree.
chmod -R 755 "$HARDA_TMP" 2>/dev/null

# Test: hardening (b) — when --bulk-output points at a directory INSIDE the scan
# root, the output dir itself must NOT be treated as a scan target. Otherwise a
# repeat run would scan the previous run's report files.
HARDB_TMP="$BULK_TMP/hardening-b"
mkdir -p "$HARDB_TMP/projects/proj-a" "$HARDB_TMP/projects/proj-b" "$HARDB_TMP/report/per-repo"
echo '{"name":"a"}' > "$HARDB_TMP/projects/proj-a/package.json"
echo '{"name":"b"}' > "$HARDB_TMP/projects/proj-b/package.json"
# Simulate a leftover prior report so the output dir LOOKS like a scan candidate.
echo "leftover" > "$HARDB_TMP/report/aggregate-report.md"
echo "leftover" > "$HARDB_TMP/report/per-repo/old-project.console.txt"

hardb_run_out="$("$BASH_CMD" "$DETECTOR" --bulk --bulk-output "$HARDB_TMP/report" "$HARDB_TMP" 2>&1 || true)"
((total++))
# Expect: Scanned: 2 (proj-a + proj-b only) and NO per-repo log named "report.*"
hardb_scan_count=$(grep -oE "Scanned: [0-9]+" <<< "$hardb_run_out" | head -1 | grep -oE "[0-9]+")
hardb_has_report_log=0
ls "$HARDB_TMP/report/per-repo/" 2>/dev/null | grep -qE "^report\." && hardb_has_report_log=1
if [[ "$hardb_scan_count" == "2" ]] && [[ "$hardb_has_report_log" -eq 0 ]]; then
    echo -e "${GREEN}PASS${NC}: --bulk-output inside scan root is excluded from discovery"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk scanned the output dir (count=$hardb_scan_count, self-log=$hardb_has_report_log)"
    echo "  per-repo dir contents:"
    ls -la "$HARDB_TMP/report/per-repo/" 2>/dev/null | sed 's/^/    /'
    ((failed++))
fi

# Cleanup
rm -rf "$BULK_TMP"

echo ""
echo "========================================"
echo "  Final Results: $passed/$total passed, $failed failed"
echo "========================================"

if [[ $failed -gt 0 ]]; then
    exit 1
else
    exit 0
fi

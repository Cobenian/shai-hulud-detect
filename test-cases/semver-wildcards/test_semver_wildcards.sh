#!/bin/bash
# Test script for semver wildcard pattern matching
# Tests the fix for GitHub issue #56

# Extract only the semver functions we need from the main script
semverParseInto() {
  local RE='[^0-9]*\([0-9]*\)[.]\([0-9]*\)[.]\([0-9]*\)\([0-9A-Za-z-]*\)'
  #MAJOR
  eval $2=$(echo $1 | sed -e "s/$RE/\1/")
  #MINOR
  eval $3=$(echo $1 | sed -e "s/$RE/\2/")
  #MINOR
  eval $4=$(echo $1 | sed -e "s/$RE/\3/")
  #SPECIAL
  eval $5=$(echo $1 | sed -e "s/$RE/\4/")
}

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
            *x*) # Wildcard pattern (4.x, 1.2.x, etc.)
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

                        # Skip wildcard components
                        if [[ "${pattern_part}" == "x" ]]; then
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

# Test function
test_semver_match() {
    local subject="$1"
    local pattern="$2"
    local expected="$3"
    local description="$4"

    if semver_match "$subject" "$pattern"; then
        local result="MATCH"
    else
        local result="NO MATCH"
    fi

    if [[ "$result" == "$expected" ]]; then
        echo "✅ PASS: $description"
        echo "   $subject vs $pattern -> $result"
    else
        echo "❌ FAIL: $description"
        echo "   $subject vs $pattern -> $result (expected: $expected)"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo
}

echo "Testing semver wildcard pattern matching..."
echo "=========================================="
echo

TOTAL_TESTS=0
FAILED_TESTS=0

# Test the original problem case from issue #56
echo "Original issue #56 test cases:"
echo "------------------------------"
test_semver_match "4.0.0" "4.x" "MATCH" "4.x pattern should match 4.0.0"
test_semver_match "4.5.2" "4.x" "MATCH" "4.x pattern should match 4.5.2"
test_semver_match "4.999.999" "4.x" "MATCH" "4.x pattern should match 4.999.999"
test_semver_match "3.9.9" "4.x" "NO MATCH" "4.x pattern should NOT match 3.9.9"
test_semver_match "5.0.0" "4.x" "NO MATCH" "4.x pattern should NOT match 5.0.0"

echo "Additional wildcard test cases:"
echo "------------------------------"
test_semver_match "1.2.0" "1.2.x" "MATCH" "1.2.x pattern should match 1.2.0"
test_semver_match "1.2.999" "1.2.x" "MATCH" "1.2.x pattern should match 1.2.999"
test_semver_match "1.3.0" "1.2.x" "NO MATCH" "1.2.x pattern should NOT match 1.3.0"
test_semver_match "2.2.0" "1.2.x" "NO MATCH" "1.2.x pattern should NOT match 2.2.0"

echo "Edge case tests:"
echo "---------------"
test_semver_match "1.0.0" "x.x.x" "MATCH" "x.x.x pattern should match any version"
test_semver_match "999.999.999" "x.x.x" "MATCH" "x.x.x pattern should match any version"
test_semver_match "1.0.0" "1.x.x" "MATCH" "1.x.x pattern should match 1.0.0"
test_semver_match "1.999.999" "1.x.x" "MATCH" "1.x.x pattern should match 1.999.999"
test_semver_match "2.0.0" "1.x.x" "NO MATCH" "1.x.x pattern should NOT match 2.0.0"

echo "Ensure existing semver patterns still work:"
echo "-------------------------------------------"
test_semver_match "1.2.3" "1.2.3" "MATCH" "Exact match should still work"
test_semver_match "1.2.4" "1.2.3" "NO MATCH" "Exact non-match should still work"
test_semver_match "1.5.0" "^1.0.0" "MATCH" "Caret range should still work"
test_semver_match "2.0.0" "^1.0.0" "NO MATCH" "Caret range exclusion should still work"
test_semver_match "1.0.5" "~1.0.0" "MATCH" "Tilde range should still work"
test_semver_match "1.1.0" "~1.0.0" "NO MATCH" "Tilde range exclusion should still work"

echo "=========================================="
echo "Test Results:"
echo "Total tests: $TOTAL_TESTS"
echo "Passed: $((TOTAL_TESTS - FAILED_TESTS))"
echo "Failed: $FAILED_TESTS"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo "🎉 All tests passed!"
    exit 0
else
    echo "❌ Some tests failed!"
    exit 1
fi
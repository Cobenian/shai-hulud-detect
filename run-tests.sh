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
    ["destructive-home-subdir-fp"]="0|no|no|no" # Clean: scoped removals BELOW a home dir (rm -rf /home/myapp/.deployer, $HOME/.cache/foo, ~/tmp/build) must not fire the destructive-payload check
    ["destructive-home-wipe"]="1|no|no|no"     # CRITICAL: whole-home wipes the old regex missed (rm -rf "$HOME", rm -rf ${HOME}, rm -rf ~, ~/, ~bob, "/home/bob")
    ["discussion-workflows"]="1|yes|no|no"     # HIGH: malicious workflows
    ["edge-case-project"]="0|no|no|no"         # Clean (no detections)
    ["false-positive-project"]="2|no|yes|no"   # MEDIUM: potential false positives
    ["github-actions-runners"]="1|yes|no|no"   # HIGH: malicious runners
    ["gitlab-false-positive"]="0|no|no|no"    # Clean: non-.github YAML files (issue #83)
    ["secret-scanner-mention"]="2|no|yes|no"  # MEDIUM: bare trufflehog reference - pins severity attribution in --save-log/--json
    ["hash-verification"]="1|yes|no|no"        # HIGH: known malicious hashes (was timeout in orig)
    ["hash-in-node-modules"]="0|no|no|no"      # Clean: inert files under node_modules/ — asserts the hash sweep covers them (see the coverage assertion below)
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
    ["atool-attack"]="1|yes|no|no"             # HIGH: May 2026 Mini Shai-Hulud AntV/atool wave (size-sensor@1.0.4, echarts-for-react@3.0.7, @antv/scale@0.6.2, timeago.js@4.1.2, @antv/g2@5.5.8)
    ["atool-clean"]="0|no|no|no"               # Clean: last-known-good versions of atool-wave-targeted packages
    ["megalodon-attack"]="1|yes|no|no"         # HIGH: May 18, 2026 Megalodon GitHub-repo backdooring (SysDiag workflow + Tiledesk npm fallout + C2 IP + commit SHA)
    ["web3-mcp-attack"]="1|yes|yes|no"         # HIGH: May 20, 2026 Web3/DeFi MCP-server typosquat (chain-key-validator + C2 ddjidd564.github.io + webhook.site fallback); MEDIUM piggybacks because the generic webhook.site content-pattern check fires on the same fallback URL
    ["polymarket-attack"]="1|yes|no|no"        # HIGH: May 21, 2026 Polymarket wallet-drainer typosquat (polymarket-bot@0.1.0 + C2 polymarketbot.polymarketdev.workers.dev + payload SHA + .polybot/wallets.json staging artifact)
    ["sl4x0-attack"]="1|yes|no|no"             # HIGH: sl4x0 dependency-confusion campaign (oc-aa-module-client@9.9.10 + C2 oob.sl4x0.xyz + @sl4x0.xyz publisher fingerprint + slaxorg fab org + hex-named helpers b02e30.js / 6ad264.js)
    ["art-template-attack"]="1|yes|no|no"      # HIGH: 2025-2026 art-template npm hijack (art-template@4.13.5 + iOS exploit-kit C2 v3.jiathis.com / utaq.cfww.shop / l1ewsu3yjkqeroy.xyz + threat-actor goofychris/daughtrymom)
    ["durabletask-attack"]="1|yes|no|no"       # HIGH: May 19, 2026 durabletask PyPI compromise (pypi:durabletask@1.4.1 + C2 check.git-service.com + secondary t.m-kosche.com + FIRESCALE/BABA-YAGA-KOSCHEI beacons + pgsql-monitor persistence)
    ["durabletask-endpoint-fp"]="0|no|no|no"   # Clean: benign AI SDK code using /v1/models etc. — the durabletask C2 endpoints must not fire without corroboration
    ["durabletask-endpoint-corroborated"]="1|yes|no|no" # HIGH: rotated C2 domain + campaign endpoint + campaign marker in one file — the case corroboration exists to keep
    ["trapdoor-attack"]="1|yes|no|no"          # HIGH: May 22-25, 2026 TrapDoor (TeamPCP) multi-ecosystem crypto-stealer — npm (eth-wallet-sentinel) + PyPI (pypi:eth-security-auditor@0.1.0) + Crates (sui-move-build-helper) name matches, P-2024-001 marker, cargo-build-helper-2026 XOR key, trap-core.js payload, and the .cursorrules AI-assistant dropper
    ["laravel-lang-attack"]="1|yes|no|no"      # HIGH: May 22, 2026 Laravel-Lang Composer tag-rewrite — name match on laravel-lang/lang + /http-statuses (all tags backdoored), composer exact-version (composer:laravel-lang/lang@15.29.5), flipboxstudio.info C2 + DebugElevator/DebugChromium payload + malicious commit SHAs
    ["node-ipc-attack"]="1|yes|no|no"          # HIGH: May 14, 2026 node-ipc backdoor (node-ipc@9.1.6 + sh.azurestaticprovider.net C2 + __ntRun/key markers; node-ipc.cjs hash in MALICIOUS_HASHLIST)
    ["bitwarden-attack"]="1|yes|no|no"         # HIGH: April 22, 2026 @bitwarden/cli@2026.4.0 "Shai-Hulud: The Third Coming" (audit.checkmarx.cx C2 + butlerian-jihad/resistance beacon strings + bw1.js payload)
    ["nx-console-attack"]="1|yes|no|no"        # HIGH: May 18, 2026 Nx Console 18.95.0 (TeamPCP) — orphan commit 558b09d7 in nrwl/nx + github:nrwl/nx#558b09d7 npx ref + firedalazer/install-mcp-extension/__DAEMONIZED markers (payload hashes in MALICIOUS_HASHLIST)
    ["malware-slop-attack"]="1|yes|yes|no"     # HIGH: May 26, 2026 mouse5212-super-formatter "Malware-Slop" (unplowed3584 + embedded github_pat + /mnt/user-data Claude-dir abuse); MEDIUM piggybacks because the embedded PAT trips the generic secret-scanning pattern
    ["redhat-miasma-attack"]="1|yes|no|no"     # HIGH: June 2026 Miasma @redhat-cloud-services scope compromise (rbac-client@9.0.3, frontend-components@7.7.2, chrome@2.3.1, types@3.6.1, notifications-client@6.1.4)
    ["redhat-miasma-clean"]="0|no|no|no"       # Clean: last-known-good versions of @redhat-cloud-services packages
    ["miasma-binding-gyp-attack"]="1|yes|no|no" # HIGH: June 3, 2026 Miasma Phantom Gyp worm wave (@vapi-ai/server-sdk@1.2.2, ai-sdk-ollama@3.8.5, autotel-mcp@28.0.3, awaitly-postgres@23.0.1, wrangler-deploy@1.5.5) — 57 packages / 286 versions, binding.gyp command-substitution trigger bypasses preinstall hook monitors
    ["miasma-binding-gyp-clean"]="0|no|no|no"  # Clean: last-known-good versions of Phantom-Gyp-wave-targeted packages
    ["hades-miasma-pypi-attack"]="1|yes|no|no" # HIGH: June 7, 2026 Miasma "Hades" PyPI wave (pypi:bramin@0.0.2, magique-ai@0.4.5, pantheon-agents@0.6.2, ufish@0.1.3, uprobe@0.1.4) — 19 packages / 37 versions; inert markers exercise token-nuke + Hades beacon + api.anthropic.com/v1/api C2 content checks
    ["hades-miasma-pypi-clean"]="0|no|no|no"   # Clean: last-known-good (one release below compromised) versions of Hades-wave PyPI packages
    ["digit-name-package-attack"]="1|yes|no|no" # HIGH: regression — npm names may start with a digit (02-echo@0.0.7). Loader regex + package.json lookup table must not silently drop digit-leading names
    ["ironworm-attack"]="1|yes|no|no"          # HIGH: June 3, 2026 IronWorm (JFrog) — Rust infostealer via 37 asteroiddao npm packages (weavedb-sdk@0.45.3, arnext@0.1.5, zkjson@0.8.5, wao@0.41.2, cwao@0.5.6) + leaked operator wallet 0x7e28...a4d6
    ["ironworm-clean"]="0|no|no|no"            # Clean: non-compromised versions of IronWorm-targeted package names
    ["easy-day-js-attack"]="1|yes|no|no"       # HIGH: June 17, 2026 easy-day-js / Mastra AI wave (BlueNoroff) — @mastra/core@1.42.1, @mastra/memory@1.20.4, easy-day-js@1.11.22; inert markers exercise C2 IP + payload-path + postinstall-hook content checks
    ["easy-day-js-clean"]="0|no|no|no"         # Clean: non-compromised @mastra versions + the legitimate dayjs (not the easy-day-js typosquat)
    ["leoplatform-miasma-attack"]="1|yes|no|no" # HIGH: June 25, 2026 Miasma LeoPlatform/RStreams wave (Socket) — leo-sdk@6.0.19, leo-auth@4.0.6, leo-aws@2.0.4, rstreams-metrics@2.0.2; inert markers exercise the new RevokeAndItGoesKaboom / "Alright Lets See If This Works" / thebeautifulmarchoftime content checks
    ["leoplatform-miasma-clean"]="0|no|no|no"  # Clean: non-compromised (one release below) versions of LeoPlatform/RStreams package names
    ["keyv-shai-hulud-attack"]="1|yes|no|no"   # HIGH: August 4, 2026 Shai-Hulud "Here We Go Again" keyv/cacheable wave (Wiz/Socket) — keyv@6.0.0, flat-cache@6.1.24, file-entry-cache@11.1.6, cacheable-request@13.0.20, @or-sdk/auth@0.38.2; also exercises the extended "node setup.mjs" preinstall pattern
    ["keyv-shai-hulud-clean"]="0|no|no|no"     # Clean: last-known-good versions of keyv/cacheable-wave-targeted package names
    ["go-attack"]="1|yes|no|no"                # HIGH: Go ecosystem support — go.mod + go.sum pin the compromised Verana module (go:github.com/verana-labs/verana-blockchain:v0.10.1-dev.20) from the June 25 Miasma wave
    ["go-clean"]="0|no|no|no"                  # Clean: go.mod requires a non-compromised Verana version (v0.10.0) — exercises the go.mod parser without firing
    ["hex-clean"]="0|no|no|no"                 # Clean: Elixir mix.exs + mix.lock with safe deps — exercises the Hex parsers without firing (no hex: entries in the real list yet). Match path is asserted via the SHAI_HULUD_PACKAGES_FILE override block below.
    ["gem-clean"]="0|no|no|no"                 # Clean: Ruby Gemfile + Gemfile.lock with safe deps — exercises the RubyGems parsers without firing. Match path asserted via the override block below.
    ["polyglot-go-infected-js"]="1|yes|no|yes"  # HIGH: a Go project (clean go.mod) that ALSO ships an infected JS frontend — INLINE package.json (@ctrl/tinycolor@4.1.1) in a subdir. Guards both polyglot detection and the inline-JSON parser fix.
    ["polyglot-ruby-infected-js"]="1|yes|no|yes" # HIGH: a Ruby project (clean Gemfile) with an infected inline JS package.json under app/javascript.
    ["polyglot-elixir-infected-js"]="1|yes|no|yes" # HIGH: an Elixir project (clean mix.exs) with an infected inline JS package.json under assets.
    ["composer-crates-clean"]="0|no|no|no"     # Clean: exercises the new Composer + Crates ecosystem detection/parsers with safe versions (symfony/console, monolog, serde, tokio) — must produce NO findings
    ["paranoid-confusable-fp"]="0|no|no|no"    # Clean: without --paranoid the typosquatting check is disabled. The paranoid-mode behavior (cornrnander flagged, yarn/intern/return/modern skipped) is asserted in the dedicated assertion block further down.
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

# ============================================================
#  May 19 atool/AntV wave content-IoC assertions
# ============================================================
# Lock in that every new content-pattern IoC added for the May 19 Mini Shai-Hulud
# atool/AntV wave actually fires on its fixture, not just that the fixture exits HIGH.
# Each entry below pairs a human-readable label with a fixed-string fragment from
# the detector's output line; if any expected IoC stops firing, this section fails.
echo ""
echo "========================================"
echo "  Testing May 19 atool/AntV IoC coverage"
echo "========================================"

ATOOL_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/atool-attack" 2>&1)
for atool_check in \
    "C2 domain t.m-kosche.com|Mini Shai-Hulud C2 domain (t.m-kosche.com)" \
    "exfil-repo beacon string|beacon string from exfil repos (May 19 wave)" \
    "forged-author email|huiyu.zjt@ant.com, May 19 wave" \
    "firedalazer dead-drop keyword|firedalazer, May 19 wave" \
    "orphan commit 1916faa365|1916faa365f2788b6e193514872d51a242876569" \
    "orphan commit 7cb42f5756|7cb42f57561c321ecb09b4552802ae0ac55b3a7a" \
    "orphan commit dc3d62a218|dc3d62a2181beb9f326952a2d212900c94f2e13d" \
    "atool publisher metadata|atool, May 19 wave" \
    "malicious antvis/G2 optionalDependencies|antvis/G2 orphan commit 1916faa365" \
    "preinstall bun run index.js|preinstall script invokes bun run index.js"
do
    label="${atool_check%|*}"
    pattern="${atool_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$ATOOL_OUT"; then
        echo -e "${GREEN}PASS${NC}: atool-attack fires May 19 IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: atool-attack did NOT fire IoC: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# kitty-monitor variant of the dead-man's-switch (the May 19 wave's renamed daemon).
KITTY_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/mini-shai-hulud-dead-mans-switch" 2>&1)
for kitty_check in \
    "kitty-monitor.sh script|/kitty-monitor.sh" \
    "kitty-monitor LaunchAgent plist|com.user.kitty-monitor.plist" \
    "kitty/cat.py dead-drop fetcher|kitty/cat.py"
do
    label="${kitty_check%|*}"
    pattern="${kitty_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$KITTY_OUT"; then
        echo -e "${GREEN}PASS${NC}: dead-mans-switch fixture surfaces May 19 artifact: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: dead-mans-switch did NOT surface: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 18+20 Megalodon + Web3-MCP IoC assertions
# ============================================================
# Verify content-pattern IoCs for the May 18 Megalodon GitHub-repo backdooring
# campaign and the May 20 Web3/DeFi MCP-server typosquat campaign actually fire
# on their fixtures (in addition to the package-version exit-code expectations
# already covered by the EXPECTED table at the top of this file).
echo ""
echo "========================================"
echo "  Testing Megalodon + Web3-MCP IoC coverage"
echo "========================================"

MEGALODON_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/megalodon-attack" 2>&1)
for megalodon_check in \
    "Tiledesk compromised version|@tiledesk/tiledesk-server@2.18.6" \
    "SysDiag workflow name|SysDiag — mass-variant injection" \
    "C2 IP 216.126.225.129|216.126.225.129" \
    "Tiledesk malicious commit SHA|Tiledesk variant"
do
    label="${megalodon_check%|*}"
    pattern="${megalodon_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$MEGALODON_OUT"; then
        echo -e "${GREEN}PASS${NC}: megalodon-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: megalodon-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

WEB3_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/web3-mcp-attack" 2>&1)
for web3_check in \
    "MCP typosquat compromised version|chain-key-validator@0.2.3" \
    "GitHub-Pages C2 reference|ddjidd564.github.io/defi-security-best-practices/config.json" \
    "webhook.site fallback UUID|webhook.site/8d334534-1c63-4f4f-a0d7-95c446c8b233"
do
    label="${web3_check%|*}"
    pattern="${web3_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$WEB3_OUT"; then
        echo -e "${GREEN}PASS${NC}: web3-mcp-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: web3-mcp-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

ART_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/art-template-attack" 2>&1)
for art_check in \
    "art-template compromised version|art-template@4.13.5" \
    "art-template C2 v3.jiathis.com|art-template hijack C2 reference (v3.jiathis.com)" \
    "art-template C2 git.youzzjizz.com|art-template hijack C2 reference (git.youzzjizz.com)" \
    "art-template C2 utaq.cfww.shop|art-template hijack C2 reference (utaq.cfww.shop)" \
    "art-template C2 l1ewsu3yjkqeroy.xyz|art-template hijack C2 reference (l1ewsu3yjkqeroy.xyz)" \
    "art-template API endpoint|art-template hijack C2 reference (/api/ip-sync/sync)" \
    "art-template obfuscation seed|cecd08aa6ff548c2" \
    "art-template publisher daughtrymom|art-template hijack threat-actor fingerprint" \
    "art-template GitHub goofychris|github.com/goofychris/"
do
    label="${art_check%|*}"
    pattern="${art_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$ART_OUT"; then
        echo -e "${GREEN}PASS${NC}: art-template-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: art-template-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

DT_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/durabletask-attack" 2>&1)
for dt_check in \
    "durabletask compromised PyPI version|durabletask@1.4.1" \
    "durabletask primary C2|durabletask C2 reference (check.git-service.com)" \
    "durabletask C2 /rope.pyz|durabletask C2 reference (/rope.pyz)" \
    "durabletask C2 /v1/models|durabletask C2 endpoint (/v1/models) alongside another campaign marker" \
    "durabletask C2 /api/public/version|durabletask C2 endpoint (/api/public/version) alongside another campaign marker" \
    "durabletask beacon FIRESCALE|durabletask beacon string (FIRESCALE)" \
    "durabletask beacon BABA-YAGA-KOSCHEI|durabletask beacon string (BABA-YAGA-KOSCHEI)" \
    "durabletask beacon PUSH UR T3MPRR|durabletask beacon string (PUSH UR T3MPRR)" \
    "durabletask pgsql-monitor persistence|pgsql-monitor.service" \
    "durabletask shared C2 with Mini Shai-Hulud|t.m-kosche.com"
do
    label="${dt_check%|*}"
    pattern="${dt_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$DT_OUT"; then
        echo -e "${GREEN}PASS${NC}: durabletask-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: durabletask-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  June 7 Hades/Miasma PyPI wave content-IoC assertions
# ============================================================
# Lock in the near-zero-FP string markers added for the June 7 Hades PyPI
# wave (and the backfilled June 1/3 Miasma token-nuke marker). The fixture's
# inert .py file carries ONLY these strings as comments — no payload.
HADES_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/hades-miasma-pypi-attack" 2>&1)
for hades_check in \
    "Hades compromised PyPI version|bramin@0.0.2" \
    "Hades token-nuke marker|IfYouYankThisTokenItWillNukeTheComputerOfTheOwnerFully" \
    "Hades exfil-repo beacon|Hades - The End for the Damned" \
    "Hades C2 camouflage path|api.anthropic.com/v1/api"
do
    label="${hades_check%|*}"
    pattern="${hades_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$HADES_OUT"; then
        echo -e "${GREEN}PASS${NC}: hades-miasma-pypi-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: hades-miasma-pypi-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  June 3 IronWorm content-IoC assertions
# ============================================================
# Lock in the IronWorm package-version detection and the leaked operator
# wallet address (high-confidence known-attacker-wallet IoC).
IRONWORM_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/ironworm-attack" 2>&1)
for iw_check in \
    "IronWorm compromised npm version|weavedb-sdk@0.45.3" \
    "IronWorm leaked operator wallet|ioc_inert.js:Known attacker wallet address detected"
do
    label="${iw_check%|*}"
    pattern="${iw_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$IRONWORM_OUT"; then
        echo -e "${GREEN}PASS${NC}: ironworm-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: ironworm-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  June 17, 2026 easy-day-js / Mastra AI content-IoC assertions
# ------------------------------------------------------------
EASYDAYJS_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/easy-day-js-attack" 2>&1)
for edj_check in \
    "easy-day-js compromised npm version|@mastra/core@1.42.1" \
    "easy-day-js malicious dependency reference|Reason: easy-day-js malicious dependency reference" \
    "easy-day-js C2 IP address|Reason: easy-day-js C2 IP address" \
    "easy-day-js C2 payload path|Reason: easy-day-js C2 payload path (/update/49890878)" \
    "easy-day-js postinstall dropper hook|Reason: easy-day-js postinstall dropper hook"
do
    label="${edj_check%|*}"
    pattern="${edj_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$EASYDAYJS_OUT"; then
        echo -e "${GREEN}PASS${NC}: easy-day-js-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: easy-day-js-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  June 25, 2026 Miasma LeoPlatform/RStreams content-IoC assertions
# ------------------------------------------------------------
LEOPLATFORM_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/leoplatform-miasma-attack" 2>&1)
for lp_check in \
    "LeoPlatform compromised npm version|leo-sdk@6.0.19" \
    "LeoPlatform marker RevokeAndItGoesKaboom|Reason: Miasma LeoPlatform/RStreams wave marker (RevokeAndItGoesKaboom)" \
    "LeoPlatform marker 'Alright Lets See If This Works'|Reason: Miasma LeoPlatform/RStreams wave marker (Alright Lets See If This Works)" \
    "LeoPlatform marker thebeautifulmarchoftime|Reason: Miasma LeoPlatform/RStreams wave marker (thebeautifulmarchoftime)"
do
    label="${lp_check%|*}"
    pattern="${lp_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$LEOPLATFORM_OUT"; then
        echo -e "${GREEN}PASS${NC}: leoplatform-miasma-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: leoplatform-miasma-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  August 4, 2026 Shai-Hulud "Here We Go Again" keyv/cacheable assertions
# ------------------------------------------------------------
KEYV_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/keyv-shai-hulud-attack" 2>&1)
for keyv_check in \
    "keyv index-case version flagged|keyv@6.0.0" \
    "flat-cache compromised version flagged|flat-cache@6.1.24" \
    "file-entry-cache compromised version flagged|file-entry-cache@11.1.6" \
    "scoped @or-sdk/auth compromised version flagged|@or-sdk/auth@0.38.2" \
    "scoped @nebula.js/cli-serve compromised version flagged|@nebula.js/cli-serve@7.1.2" \
    "node setup.mjs preinstall hook flagged|Fake Bun preinstall patterns detected" \
    "npm-cache.com C2 fallback domain flagged|keyv/cacheable wave C2 fallback domain"
do
    label="${keyv_check%|*}"
    pattern="${keyv_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$KEYV_OUT"; then
        echo -e "${GREEN}PASS${NC}: keyv-shai-hulud-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: keyv-shai-hulud-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  Go ecosystem support — go.mod / go.sum parsing + matching
# ------------------------------------------------------------
GO_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/go-attack" 2>&1)
for go_check in \
    "Go ecosystem auto-detected|Detected ecosystems: go" \
    "Go compromised module flagged|[Go] github.com/verana-labs/verana-blockchain@v0.10.1-dev.20" \
    "Go module matched from go.mod|go-attack/go.mod" \
    "Go module matched from go.sum|go-attack/go.sum"
do
    label="${go_check%|*}"
    pattern="${go_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$GO_OUT"; then
        echo -e "${GREEN}PASS${NC}: go-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: go-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  Hex (Elixir) + Gem (RubyGems) ecosystem support
# ------------------------------------------------------------
# There are no real hex:/gem: entries in the shipped list yet, so the match path
# is proven by pointing SHAI_HULUD_PACKAGES_FILE at a temporary list with one
# synthetic entry that matches a real dependency in the clean fixture. This
# exercises auto-detection + the parsers + the comm-based match end-to-end
# without inventing data in the committed compromised-packages.txt.
HEX_PKGS=$(mktemp); printf 'hex:phoenix:1.7.10\n' > "$HEX_PKGS"
HEX_OUT=$(SHAI_HULUD_PACKAGES_FILE="$HEX_PKGS" "$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/hex-clean" 2>&1)
rm -f "$HEX_PKGS"
for hex_check in \
    "Hex ecosystem auto-detected|Detected ecosystems: hex" \
    "Hex compromised package flagged (via override)|[Hex] phoenix@1.7.10"
do
    label="${hex_check%|*}"
    pattern="${hex_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$HEX_OUT"; then
        echo -e "${GREEN}PASS${NC}: hex support fires: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: hex support did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

GEM_PKGS=$(mktemp); printf 'gem:rails:7.1.3\n' > "$GEM_PKGS"
GEM_OUT=$(SHAI_HULUD_PACKAGES_FILE="$GEM_PKGS" "$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/gem-clean" 2>&1)
rm -f "$GEM_PKGS"
for gem_check in \
    "Gem ecosystem auto-detected|Detected ecosystems: gem" \
    "Gem compromised package flagged (via override)|[Gem] rails@7.1.3"
do
    label="${gem_check%|*}"
    pattern="${gem_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$GEM_OUT"; then
        echo -e "${GREEN}PASS${NC}: gem support fires: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: gem support did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# The clean fixtures must stay clean against the REAL shipped list (no override).
for clean_eco in hex-clean gem-clean; do
    ((total++))
    CLEAN_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/$clean_eco" 2>&1)
    if grep -qF "No indicators of Shai-Hulud compromise detected" <<< "$CLEAN_OUT"; then
        echo -e "${GREEN}PASS${NC}: $clean_eco is clean against the shipped list"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: $clean_eco unexpectedly flagged against the shipped list"
        ((failed++))
    fi
done

# ------------------------------------------------------------
#  Polyglot: a non-JS project that ALSO ships infected JS must be caught.
#  Each fixture's package.json uses an INLINE (single-line) dependency object,
#  which the old line-oriented parser silently dropped — so these also guard the
#  inline/minified-JSON parser fix. We assert BOTH that the non-JS ecosystem is
#  detected AND that the compromised npm dep is flagged (i.e. JS was not skipped).
# ------------------------------------------------------------
for poly in "polyglot-go-infected-js|go" "polyglot-ruby-infected-js|gem" "polyglot-elixir-infected-js|hex"; do
    fixture="${poly%|*}"
    other_eco="${poly#*|}"
    POLY_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/$fixture" 2>&1)
    ((total++))
    if grep -qF "@ctrl/tinycolor@4.1.1" <<< "$POLY_OUT"; then
        echo -e "${GREEN}PASS${NC}: $fixture flags the infected inline JS dependency (@ctrl/tinycolor@4.1.1)"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: $fixture did NOT flag the infected inline JS dependency"
        ((failed++))
    fi
    ((total++))
    if grep -qE "Detected ecosystems:.*npm" <<< "$POLY_OUT" && grep -qE "Detected ecosystems:.*\\b$other_eco\\b" <<< "$POLY_OUT"; then
        echo -e "${GREEN}PASS${NC}: $fixture activates both npm and $other_eco ecosystems"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: $fixture did NOT activate both npm and $other_eco ecosystems"
        ((failed++))
    fi
done

# ============================================================
#  Issue #146: detector must not flag its OWN installation dir
# ============================================================
# When the detector is vendored/cloned inside the tree being scanned, its
# test-cases/ fixtures (real attacker wallet addresses, fake Bun installers,
# malicious workflows) and its source/CHANGELOG used to self-trigger a flood
# of false positives. Build a project that contains a working copy of the
# detector, point that in-tree copy at the project, and assert it stays clean.
SELF_FP_TMP=$(mktemp -d)
mkdir -p "$SELF_FP_TMP/project/vendored/test-cases/x"
echo '<?php echo "ok";' > "$SELF_FP_TMP/project/app.php"
cp "$DETECTOR" "$SELF_FP_TMP/project/vendored/shai-hulud-detector.sh"
cp "$SCRIPT_DIR/compromised-packages.txt" "$SELF_FP_TMP/project/vendored/compromised-packages.txt"
# A file that WOULD trip crypto detection if the detector scanned its own tree.
echo 'const w="0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976"; // wallet' > "$SELF_FP_TMP/project/vendored/test-cases/x/bad.js"
SELF_OUT=$("$BASH_CMD" "$SELF_FP_TMP/project/vendored/shai-hulud-detector.sh" "$SELF_FP_TMP/project" 2>&1)
((total++))
if grep -qiE "No indicators of Shai-Hulud compromise detected" <<< "$SELF_OUT" \
   && ! grep -qF "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976" <<< "$SELF_OUT"; then
    echo -e "${GREEN}PASS${NC}: issue #146 - detector excludes its own in-tree directory (no self-detection)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: issue #146 - detector self-flagged its own vendored copy"
    ((failed++))
fi
rm -rf "$SELF_FP_TMP"

# ============================================================
#  Issue #148: empty file list must not fall through to a CWD scan
# ============================================================
# When a scan target has no files of a given category, the three fast_grep_files*
# helpers used to pipe an EMPTY list into `xargs -0 <tool>`. GNU xargs runs the
# command once on empty input (with no path args), so git grep/rg recursively
# scan the current working directory instead of nothing — producing false
# positives whose paths point at the CWD (test-cases/, /tmp junk, bulk reports).
#
# The bug is invisible on macOS (BSD xargs does not run on empty input), so this
# test does not rely on real xargs semantics. Instead it shadows `xargs` with a
# stub that emits a sentinel whenever invoked, sources the real helper functions
# straight out of the detector, and asserts that empty input never reaches xargs
# (i.e. the early-return guard fired). This fails on the unpatched code on every
# platform, macOS included.
XARGS_TMP=$(mktemp -d)
mkdir -p "$XARGS_TMP/bin"
printf '#!/bin/sh\necho STUB_XARGS_CALLED\n' > "$XARGS_TMP/bin/xargs"
chmod +x "$XARGS_TMP/bin/xargs"
# Pull the three contiguous helpers (fast_grep_files .. fast_grep_files_fixed)
# out of the detector so we exercise the real function bodies, not a copy.
HELPERS_SRC="$XARGS_TMP/helpers.sh"
awk '/^fast_grep_files\(\) \{/{f=1} f{print} f&&/^\}/{c++} c==3{exit}' "$DETECTOR" > "$HELPERS_SRC"
for helper in fast_grep_files fast_grep_files_i fast_grep_files_fixed; do
    ((total++))
    # git-grep is the auto-selected tool whose empty-input branch triggers the
    # real-world CWD scan; the guard runs before the tool branch either way.
    XARGS_OUT=$(PATH="$XARGS_TMP/bin:$PATH" GREP_TOOL=git-grep "$BASH_CMD" -c '
        set -eo pipefail
        source "$1"
        printf "" | "$2" "SOME_PATTERN"
    ' _ "$HELPERS_SRC" "$helper" 2>&1)
    if [[ -z "$XARGS_OUT" ]]; then
        echo -e "${GREEN}PASS${NC}: issue #148 - $helper returns early on empty input (no CWD scan)"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: issue #148 - $helper ran the grep tool on empty input (would scan CWD): $XARGS_OUT"
        ((failed++))
    fi
done
rm -rf "$XARGS_TMP"

# ============================================================
#  Backend parity: every grep tool must find the same content IoCs
# ============================================================
# `git grep --no-index` refuses absolute pathspecs, and main() resolves the scan
# directory to an absolute path before collecting files. The fast_grep_* helpers
# discard git's stderr (`2>/dev/null || true`), so on the git-grep backend every
# content-pattern check (~20 functions: C2 domains, network exfiltration, crypto
# theft, trufflehog, destructive payloads, …) silently returned NOTHING and the
# scan reported clean.
#
# The bug is invisible to the rest of this suite because the fixtures live under
# $SCRIPT_DIR, and running from inside the detector's own git repository happens
# to be the one case where git grep accepts the paths. This test therefore uses an
# out-of-tree fixture in $TMPDIR and runs from a neutral working directory — the
# way CI and `cd shai-hulud-detect && ./shai-hulud-detector.sh ~/project` behave.
BACKEND_TMP=$(mktemp -d)
mkdir -p "$BACKEND_TMP/proj/node_modules/keyv"
# npm-cache.com is the Aug 4, 2026 keyv/cacheable C2 fallback (check_keyv_indicators).
# Inert string constants throughout this block — no executable payload, per the
# fixture policy in README's Contributing section.
printf 'const endpoint = "https://npm-cache.com/router";\n' \
    > "$BACKEND_TMP/proj/node_modules/keyv/Math_Symbol.js"
printf '{"name":"app","version":"1.0.0"}\n' > "$BACKEND_TMP/proj/package.json"

# The whole point of this block is that the working directory is NOT inside a git
# repository containing the scan target — that is the one arrangement in which git
# grep accepts the paths, and it would turn every assertion below into a silent
# false negative. $TMPDIR is normally outside any repo, but CI runners that set
# TMPDIR=$GITHUB_WORKSPACE/tmp (or a dotfiles repo at $HOME) break the assumption,
# so assert it rather than trusting it.
if ! command -v git >/dev/null 2>&1; then
    # --use-git-grep exits 1 outright without git, so these would FAIL rather than
    # be skipped. The backend under test is the git one; nothing to assert here.
    echo -e "${YELLOW}SKIP${NC}: grep backend parity - git is not installed"
elif git -C "$BACKEND_TMP" rev-parse --show-toplevel >/dev/null 2>&1; then
    echo -e "${YELLOW}SKIP${NC}: grep backend parity - the temp fixture directory is inside a git repository"
else
    for backend in "" "--use-git-grep" "--use-ripgrep" "--use-grep"; do
        backend_label="${backend:-auto-selected}"
        # ripgrep may not be installed on the runner; skip that backend if so.
        if [[ "$backend" == "--use-ripgrep" ]] && ! command -v rg >/dev/null 2>&1; then
            echo -e "${YELLOW}SKIP${NC}: grep backend parity - ripgrep is not installed"
            continue
        fi
        ((total++))
        # Run from a directory that is neither the scan target nor a git repository
        # containing it, so absolute pathspecs are genuinely out of tree.
        BACKEND_OUT=$(cd "$BACKEND_TMP" && "$BASH_CMD" "$DETECTOR" $backend "$BACKEND_TMP/proj" 2>&1)
        if grep -q "npm-cache.com" <<< "$BACKEND_OUT"; then
            echo -e "${GREEN}PASS${NC}: grep backend parity - $backend_label finds out-of-tree content IoCs"
            ((passed++))
        else
            echo -e "${RED}FAIL${NC}: grep backend parity - $backend_label silently missed the npm-cache.com C2 domain"
            ((failed++))
        fi
    done

    # A path beginning with ":" must not be read as git pathspec magic. ":!x" is
    # git's EXCLUDE syntax, so without the "./" prefix the backend adds, a malicious
    # package could ship one extra path named ":!<target>" to silently drop <target>
    # from every content search — attacker-controlled and completely silent.
    #
    # The decoy must be a DIRECTORY mirroring the real file's path, not a bare file:
    # git's exclude pathspec matches from the start of the path, so a top-level
    # ":!Math_Symbol.js" would not suppress "node_modules/keyv/Math_Symbol.js" and
    # the assertion would pass even without the fix. Contents are inert.
    mkdir -p "$BACKEND_TMP/proj/:!node_modules/keyv"
    printf '// inert decoy\n' > "$BACKEND_TMP/proj/:!node_modules/keyv/Math_Symbol.js"
    ((total++))
    PATHSPEC_OUT=$(cd "$BACKEND_TMP" && "$BASH_CMD" "$DETECTOR" --use-git-grep "$BACKEND_TMP/proj" 2>&1)
    if grep -q "npm-cache.com" <<< "$PATHSPEC_OUT"; then
        echo -e "${GREEN}PASS${NC}: grep backend parity - ':!'-prefixed decoy path cannot suppress a finding"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: grep backend parity - ':!'-prefixed decoy path suppressed the npm-cache.com finding"
        ((failed++))
    fi
    rm -rf "$BACKEND_TMP/proj/:!node_modules"

    # A backslash in the scan path must survive the path relativization. `awk -v`
    # applies escape-sequence processing to its assignments, so passing the base
    # that way turns /tmp/we\ird into /tmp/weird, matches nothing, and degrades the
    # backend right back to finding nothing at all.
    mkdir -p "$BACKEND_TMP/we\\ird"
    printf '{"name":"app"}\n' > "$BACKEND_TMP/we\\ird/package.json"
    printf 'const endpoint = "https://npm-cache.com/router";\n' > "$BACKEND_TMP/we\\ird/payload.js"
    ((total++))
    BSLASH_OUT=$(cd "$BACKEND_TMP" && "$BASH_CMD" "$DETECTOR" --use-git-grep "$BACKEND_TMP/we\\ird" 2>&1)
    if grep -q "npm-cache.com" <<< "$BSLASH_OUT"; then
        echo -e "${GREEN}PASS${NC}: grep backend parity - backslash in scan path does not break relativization"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: grep backend parity - backslash in scan path silently disabled content checks"
        ((failed++))
    fi
    rm -rf "$BACKEND_TMP/we\\ird"

    # --check-host probes $HOME/.claude/settings.json, which is OUTSIDE the scan
    # root and therefore not addressable as a git pathspec at all. It must fall
    # back to plain grep rather than silently reporting the host clean.
    mkdir -p "$BACKEND_TMP/fakehome/.claude"
    printf '{"hooks":{"SessionStart":"firedalazer install-mcp-extension"}}\n' \
        > "$BACKEND_TMP/fakehome/.claude/settings.json"
    ((total++))
    HOSTCHK_OUT=$(cd "$BACKEND_TMP" && HOME="$BACKEND_TMP/fakehome" \
        "$BASH_CMD" "$DETECTOR" --use-git-grep --check-host "$BACKEND_TMP/proj" 2>&1)
    # Assert on the finding text itself. "Nx Console" alone is a tautology (the
    # progress banner always prints it) and "settings.json" appears in generic
    # remediation advice for any AI-assistant-dropper finding.
    if grep -qF "Suspicious hook in Claude settings" <<< "$HOSTCHK_OUT"; then
        echo -e "${GREEN}PASS${NC}: grep backend parity - --check-host reads paths outside the scan root"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: grep backend parity - --check-host missed the Nx Console marker in \$HOME"
        ((failed++))
    fi
    rm -rf "$BACKEND_TMP/fakehome"
fi
rm -rf "$BACKEND_TMP"

# ============================================================
#  Destructive-payload home-directory scoping regression
# ============================================================
# Lock in the basic_destructive_regex fix in check_destructive_patterns.
#
# Over-match: the old "/home/" alternative matched ANY path below /home/, so a
# legitimate deployment line "rm -rf /home/myapp/.deployer" was reported as
# "CRITICAL: Destructive payload patterns detected".
#
# Under-match: the old "~[^a-zA-Z0-9_/]" alternative excluded "/", could not
# match at end-of-line and allowed neither a leading quote nor ${HOME}, so the
# real wipes 'rm -rf "$HOME"', "rm -rf ${HOME}", "rm -rf ~", "rm -rf ~/" and
# "rm -rf ~/*" were all MISSED.
#
# The fixtures are in-tree (NOT $TMPDIR) so the assertions also hold on the
# git-grep backend, which can only address paths under the scan root.
DESTR_FP_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/destructive-home-subdir-fp" 2>&1)
((total++))
if grep -qF "Destructive payload patterns detected" <<< "$DESTR_FP_OUT"; then
    echo -e "${RED}FAIL${NC}: destructive-home-subdir-fp wrongly flagged a scoped removal (rm -rf /home/myapp/.deployer) as destructive"
    ((failed++))
else
    echo -e "${GREEN}PASS${NC}: destructive-home-subdir-fp does NOT flag 'rm -rf /home/myapp/.deployer' as destructive"
    ((passed++))
fi

DESTR_WIPE_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/destructive-home-wipe" 2>&1)
((total++))
if grep -qF "Destructive payload patterns detected" <<< "$DESTR_WIPE_OUT"; then
    echo -e "${GREEN}PASS${NC}: destructive-home-wipe flags the quoted home wipe (rm -rf \"\$HOME\") as destructive"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: destructive-home-wipe did NOT flag 'rm -rf \"\$HOME\"' (the home-wipe regex is broken)"
    ((failed++))
fi

# ============================================================
#  Symlinked scan root must be resolved, not scanned as a symlink
# ============================================================
# `find` does not descend a start path that is itself a symlink, and main() used the
# default LOGICAL `pwd`, which preserves the symlink. Scanning /work (a symlink to
# /Volumes/Work) collected zero files and printed "No indicators of Shai-Hulud
# compromise detected" — a clean bill of health for a tree that was never opened.
# --bulk was hit the same way: "No projects found". A trailing slash makes `find`
# resolve the link, but the logical `pwd` strips it, so `/work/` failed identically.
# Symlinked roots are ordinary: /work -> /Volumes/Work, macOS /tmp -> /private/tmp.
SYMROOT_TMP=$(mktemp -d)
mkdir -p "$SYMROOT_TMP/real/proj"
# Inert: a compromised version string in a manifest, nothing executable.
printf '{"name":"p","version":"1.0.0","dependencies":{"keyv":"6.0.0"}}\n' \
    > "$SYMROOT_TMP/real/proj/package.json"
ln -s "$SYMROOT_TMP/real" "$SYMROOT_TMP/link"

((total++))
SYMROOT_OUT=$("$BASH_CMD" "$DETECTOR" "$SYMROOT_TMP/link" 2>&1)
if grep -qF "keyv@6.0.0" <<< "$SYMROOT_OUT"; then
    echo -e "${GREEN}PASS${NC}: symlinked scan root is resolved (plain scan)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: symlinked scan root scanned nothing and reported clean (plain scan)"
    ((failed++))
fi

((total++))
SYMROOT_BULK=$("$BASH_CMD" "$DETECTOR" --bulk --bulk-list "$SYMROOT_TMP/link" 2>&1)
if grep -q "/proj$" <<< "$SYMROOT_BULK"; then
    echo -e "${GREEN}PASS${NC}: symlinked scan root is resolved (--bulk discovery)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --bulk found no projects under a symlinked root"
    ((failed++))
fi
rm -rf "$SYMROOT_TMP"

# ============================================================
#  Hash sweep must cover node_modules
# ============================================================
# npm supply-chain payloads land inside node_modules by definition, but
# check_file_hashes used to hash only files OUTSIDE it plus an allowlist of known
# malicious basenames. Two of the Aug 4, 2026 keyv/cacheable wave's three payload
# hashes were therefore unreachable: the tarball's setup.mjs and the Math_Symbol.js
# it drops both live under node_modules/<pkg>/.
#
# A fixture cannot carry a real malicious hash, so this asserts coverage instead:
# every collected file must reach the hash sweep. The detector prints
# "Checking <n> files for known malicious content (of <m> collected)"; n must
# equal m, and m must exceed the number of files outside node_modules.
((total++))
HASHCOV_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/hash-in-node-modules" 2>&1)
HASHCOV_LINE=$(grep -o 'Checking *[0-9]* files for known malicious content (of *[0-9]* collected)' <<< "$HASHCOV_OUT")
HASHCOV_N=$(sed -E 's/Checking *([0-9]+) .*/\1/' <<< "$HASHCOV_LINE")
HASHCOV_M=$(sed -E 's/.*\(of *([0-9]+) collected\)/\1/' <<< "$HASHCOV_LINE")
# The fixture has 4 collected files, 3 of them under node_modules/.
if [[ -n "$HASHCOV_LINE" && "$HASHCOV_N" == "$HASHCOV_M" && "$HASHCOV_M" -ge 4 ]]; then
    echo -e "${GREEN}PASS${NC}: hash sweep covers node_modules ($HASHCOV_N of $HASHCOV_M files hashed)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: hash sweep skipped files (hashed '$HASHCOV_N' of '$HASHCOV_M' collected)"
    ((failed++))
fi

# ============================================================
#  durabletask C2 endpoints: corroborated match must still fire
# ============================================================
# The endpoint paths are no longer matched bare (see test-cases/durabletask-endpoint-fp),
# but dropping them outright would lose the one case the bare match caught and the C2
# host literal does not: a variant that rotates the C2 domain while keeping the
# endpoints. That case is preserved by requiring another campaign marker in the same
# file. The EXPECTED table already asserts the fixture is HIGH; this pins the reason,
# so the fixture cannot start passing for some unrelated finding.
((total++))
DTCORR_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/durabletask-endpoint-corroborated" 2>&1)
if grep -qF "durabletask C2 endpoint (/v1/models) alongside another campaign marker" <<< "$DTCORR_OUT"; then
    echo -e "${GREEN}PASS${NC}: durabletask C2 endpoint still fires when corroborated (rotated C2 host)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: durabletask C2 endpoint missed a corroborated match (rotated C2 host)"
    ((failed++))
fi

# ============================================================
#  trufflehog findings must keep their own severity in --save-log / --json
# ============================================================
# trufflehog_activity.txt stores "path:SEVERITY:message" and mixes HIGH/MEDIUM/LOW.
# The --save-log and --json writers dumped the WHOLE file as HIGH, so a file that
# merely mentions trufflehog (a MEDIUM finding) was recorded as HIGH. Under --bulk this
# produced self-contradicting rows: "MEDIUM RISK (H:4 M:0 L:0)" - the label comes from
# the child exit code (correctly MEDIUM), the counts from the log (wrongly HIGH).
TH_FIX="$SCRIPT_DIR/test-cases/secret-scanner-mention"
TH_LOG=$(mktemp)

((total++))
"$BASH_CMD" "$DETECTOR" --save-log "$TH_LOG" "$TH_FIX" >/dev/null 2>&1
TH_HIGH=$(awk '$0=="# HIGH"{s=1;next} /^# /{s=0} s&&length($0)>0{c++} END{print c+0}' "$TH_LOG")
TH_MED=$(awk '$0=="# MEDIUM"{s=1;next} /^# /{s=0} s&&length($0)>0{c++} END{print c+0}' "$TH_LOG")
if [[ "$TH_HIGH" -eq 0 && "$TH_MED" -ge 1 ]]; then
    echo -e "${GREEN}PASS${NC}: MEDIUM trufflehog finding is logged as MEDIUM, not HIGH"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: trufflehog severity mis-graded in --save-log (HIGH=$TH_HIGH MEDIUM=$TH_MED)"
    ((failed++))
fi
rm -f "$TH_LOG"

if command -v jq >/dev/null 2>&1; then
    ((total++))
    TH_JSON=$(mktemp)
    "$BASH_CMD" "$DETECTOR" --json "$TH_JSON" "$TH_FIX" >/dev/null 2>&1
    if [[ "$(jq -r '[.findings[]|select(.message|test("trufflehog"))|.severity]|unique|join(",")' "$TH_JSON" 2>/dev/null)" == "MEDIUM" ]]; then
        echo -e "${GREEN}PASS${NC}: MEDIUM trufflehog finding is MEDIUM in --json too"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: trufflehog severity mis-graded in --json"
        ((failed++))
    fi
    rm -f "$TH_JSON"
else
    echo -e "${YELLOW}SKIP${NC}: trufflehog --json severity (jq not installed)"
fi

# ============================================================
#  Paranoid-mode confusable-substring regression
# ============================================================
# Lock in the fix for the bare-substring false positive (yarn/intern/return/modern
# being flagged as typosquats because they contain `rn`). The fixture mixes
# legitimate names that contain confusable bigrams with one synthetic typosquat
# (cornrnander, which substitutes `rn`->`m` to impersonate commander). Under
# --paranoid the detector should flag ONLY cornrnander.
CONF_OUT=$("$BASH_CMD" "$DETECTOR" --paranoid "$SCRIPT_DIR/test-cases/paranoid-confusable-fp" 2>&1)

# Positive case: the synthetic typosquat must be flagged.
((total++))
if grep -qF "'cornrnander' resembles popular package 'commander'" <<< "$CONF_OUT"; then
    echo -e "${GREEN}PASS${NC}: paranoid-confusable-fp flags cornrnander (substituted form matches commander)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: paranoid-confusable-fp did NOT flag cornrnander (the substituted-form check is broken)"
    ((failed++))
fi

# Negative cases: legitimate names containing confusable bigrams must NOT be flagged.
for legit_name in yarn intern return modern; do
    ((total++))
    # Match the specific finding-line shape so we don't accidentally count substring
    # collisions in unrelated output (e.g. the word "return" in a remediation note).
    if grep -E "Potential typosquatting.*'$legit_name'" <<< "$CONF_OUT" >/dev/null 2>&1; then
        echo -e "${RED}FAIL${NC}: paranoid-confusable-fp wrongly flagged legitimate '$legit_name' as a typosquat"
        ((failed++))
    else
        echo -e "${GREEN}PASS${NC}: paranoid-confusable-fp does NOT flag legitimate '$legit_name'"
        ((passed++))
    fi
done

SL4X0_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/sl4x0-attack" 2>&1)
for sl4x0_check in \
    "sl4x0 compromised version|oc-aa-module-client@9.9.10" \
    "sl4x0 C2 domain reference|sl4x0 C2/domain reference (oob.sl4x0.xyz)" \
    "sl4x0 publisher email fingerprint|sl4x0 publisher email-domain fingerprint" \
    "sl4x0 fabricated GitHub org|fabricated GitHub org reference (slaxorg)" \
    "sl4x0 hex helper b02e30.js|sl4x0 hex-named payload helper (b02e30.js)" \
    "sl4x0 hex helper 6ad264.js|sl4x0 hex-named payload helper (6ad264.js)"
do
    label="${sl4x0_check%|*}"
    pattern="${sl4x0_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$SL4X0_OUT"; then
        echo -e "${GREEN}PASS${NC}: sl4x0-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: sl4x0-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

POLY_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/polymarket-attack" 2>&1)
for poly_check in \
    "Polymarket compromised version|polymarket-bot@0.1.0" \
    "Cloudflare Workers C2 host|Polymarket C2 reference (polymarketbot.polymarketdev.workers.dev)" \
    "C2 exfil endpoint path|Polymarket C2 reference (/v1/wallets/keys)" \
    "Polymarket payload SHA-256|Polymarket payload SHA-256 literal reference" \
    "polymarketdev publisher fingerprint|Polymarket threat-actor publisher (polymarketdev)" \
    "attacker source repo reference|texsellix/polymarket-trading-bot" \
    "in-tree .polybot/wallets.json artifact|.polybot/wallets.json"
do
    label="${poly_check%|*}"
    pattern="${poly_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$POLY_OUT"; then
        echo -e "${GREEN}PASS${NC}: polymarket-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: polymarket-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 22-25 TrapDoor (TeamPCP) multi-ecosystem content-IoC assertions
# ============================================================
TRAPDOOR_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/trapdoor-attack" 2>&1)
for trapdoor_check in \
    "TrapDoor npm name match (eth-wallet-sentinel)|TrapDoor compromised package dependency (eth-wallet-sentinel" \
    "TrapDoor npm name match (token-usage-tracker)|TrapDoor compromised package dependency (token-usage-tracker" \
    "TrapDoor PyPI name match (defi-risk-scanner)|TrapDoor compromised package dependency (defi-risk-scanner" \
    "TrapDoor PyPI exact version|eth-security-auditor@0.1.0" \
    "TrapDoor Crates name match (sui-move-build-helper)|TrapDoor compromised package dependency (sui-move-build-helper" \
    "TrapDoor Crates name match (move-compiler-tools)|TrapDoor compromised package dependency (move-compiler-tools" \
    "TrapDoor campaign marker P-2024-001|TrapDoor campaign indicator (P-2024-001)" \
    "TrapDoor crates XOR key|TrapDoor campaign indicator (cargo-build-helper-2026)" \
    "TrapDoor extraction framework|TrapDoor campaign indicator (Universal AI Agent Extraction Framework)" \
    "TrapDoor trap-core.js payload|TrapDoor payload/framework artifact (trap-core.js)" \
    "TrapDoor .cursorrules AI-dropper|Malicious AI-assistant config dropper"
do
    label="${trapdoor_check%|*}"
    pattern="${trapdoor_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$TRAPDOOR_OUT"; then
        echo -e "${GREEN}PASS${NC}: trapdoor-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: trapdoor-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 22 Laravel-Lang Composer tag-rewrite content-IoC assertions
# ============================================================
LARAVEL_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/laravel-lang-attack" 2>&1)
for laravel_check in \
    "Laravel-Lang name match (lang)|Laravel-Lang compromised package dependency (laravel-lang/lang" \
    "Laravel-Lang name match (http-statuses)|Laravel-Lang compromised package dependency (laravel-lang/http-statuses" \
    "Laravel-Lang composer exact version|[Composer] laravel-lang/lang@15.29.5" \
    "Laravel-Lang C2 flipboxstudio.info|Laravel-Lang campaign indicator (flipboxstudio.info)" \
    "Laravel-Lang DebugElevator payload|Laravel-Lang campaign indicator (DebugElevator)" \
    "Laravel-Lang DebugChromium payload|Laravel-Lang campaign indicator (DebugChromium)" \
    "Laravel-Lang malicious commit SHA|Laravel-Lang campaign indicator (a5ea2e8fa92ccf29cdb1d2dadbeb27722b2bff37)"
do
    label="${laravel_check%|*}"
    pattern="${laravel_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$LARAVEL_OUT"; then
        echo -e "${GREEN}PASS${NC}: laravel-lang-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: laravel-lang-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 14 node-ipc backdoor content-IoC assertions
# ============================================================
NODEIPC_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/node-ipc-attack" 2>&1)
for nodeipc_check in \
    "node-ipc compromised version|node-ipc@9.1.6" \
    "node-ipc C2 host|node-ipc backdoor indicator (sh.azurestaticprovider.net)" \
    "node-ipc C2 IP|node-ipc backdoor indicator (37.16.75.69)" \
    "node-ipc export marker|node-ipc backdoor indicator (__ntRun)" \
    "node-ipc embedded key|node-ipc backdoor indicator (qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi)"
do
    label="${nodeipc_check%|*}"
    pattern="${nodeipc_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$NODEIPC_OUT"; then
        echo -e "${GREEN}PASS${NC}: node-ipc-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: node-ipc-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  April 22 Bitwarden CLI ("Third Coming") content-IoC assertions
# ============================================================
BW_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/bitwarden-attack" 2>&1)
for bw_check in \
    "Bitwarden compromised version|@bitwarden/cli@2026.4.0" \
    "Bitwarden C2 host|Bitwarden CLI compromise indicator (audit.checkmarx.cx)" \
    "Bitwarden C2 IP|Bitwarden CLI compromise indicator (94.154.172.43)" \
    "Bitwarden Third Coming beacon|Bitwarden CLI compromise indicator (Shai-Hulud: The Third Coming)" \
    "Bitwarden butlerian-jihad beacon|Bitwarden CLI compromise indicator (Would be executing butlerian jihad!)"
do
    label="${bw_check%|*}"
    pattern="${bw_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$BW_OUT"; then
        echo -e "${GREEN}PASS${NC}: bitwarden-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: bitwarden-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 18 Nx Console 18.95.0 content-IoC assertions
# ============================================================
NX_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/nx-console-attack" 2>&1)
for nx_check in \
    "Nx orphan commit SHA|Nx Console 18.95.0 compromise indicator (558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2)" \
    "Nx npx github ref|Nx Console 18.95.0 compromise indicator (github:nrwl/nx#558b09d7)" \
    "Nx daemon flag|Nx Console 18.95.0 compromise indicator (__DAEMONIZED=1)" \
    "Nx C2 poll firedalazer|Nx Console 18.95.0 compromise indicator (firedalazer)" \
    "Nx task disguise|Nx Console 18.95.0 compromise indicator (install-mcp-extension)"
do
    label="${nx_check%|*}"
    pattern="${nx_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$NX_OUT"; then
        echo -e "${GREEN}PASS${NC}: nx-console-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: nx-console-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  May 26 mouse5212 "Malware-Slop" content-IoC assertions
# ============================================================
SLOP_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/malware-slop-attack" 2>&1)
for slop_check in \
    "Malware-Slop package name|Malware-Slop indicator (mouse5212-super-formatter)" \
    "Malware-Slop attacker username|Malware-Slop indicator (unplowed3584)" \
    "Malware-Slop embedded PAT|Malware-Slop indicator (github_pat_11CEVM5CA0SRA)" \
    "Malware-Slop Claude upload dir|References Claude upload directory /mnt/user-data"
do
    label="${slop_check%|*}"
    pattern="${slop_check#*|}"
    ((total++))
    if grep -qF "$pattern" <<< "$SLOP_OUT"; then
        echo -e "${GREEN}PASS${NC}: malware-slop-attack fires IoC: $label"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: malware-slop-attack did NOT fire: $label (looked for: '$pattern')"
        ((failed++))
    fi
done

# ============================================================
#  Composer + Crates clean-project negative assertions
# ============================================================
# The new ecosystems must be detected AND produce no findings on safe versions.
CC_OUT=$("$BASH_CMD" "$DETECTOR" "$SCRIPT_DIR/test-cases/composer-crates-clean" 2>&1)
((total++))
if grep -qE "Detected ecosystems:.*composer" <<< "$CC_OUT" && grep -qE "Detected ecosystems:.*crates" <<< "$CC_OUT"; then
    echo -e "${GREEN}PASS${NC}: composer-crates-clean detects both composer and crates ecosystems"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: composer-crates-clean did NOT detect both new ecosystems"
    ((failed++))
fi
((total++))
if grep -qE "HIGH RISK|MEDIUM RISK|LOW RISK" <<< "$CC_OUT"; then
    echo -e "${RED}FAIL${NC}: composer-crates-clean produced a finding on safe versions (false positive)"
    ((failed++))
else
    echo -e "${GREEN}PASS${NC}: composer-crates-clean produces no findings (no false positives)"
    ((passed++))
fi

# Regression: --ecosystem=all must run to completion even when some active ecosystems
# have zero marker files in the tree (the ecosystem_banner empty-grep + set -eo pipefail
# abort). On an npm-only project it should finish clean (exit 0) rather than truncating.
ECO_ALL_OUT=$("$BASH_CMD" "$DETECTOR" --ecosystem=all "$SCRIPT_DIR/test-cases/clean-project" 2>&1)
ECO_ALL_EXIT=$?
((total++))
if [[ $ECO_ALL_EXIT -eq 0 ]] && grep -qF "No indicators of Shai-Hulud compromise detected" <<< "$ECO_ALL_OUT"; then
    echo -e "${GREEN}PASS${NC}: --ecosystem=all completes a full scan on a single-ecosystem project (no set -e abort)"
    ((passed++))
else
    echo -e "${RED}FAIL${NC}: --ecosystem=all truncated or errored on clean-project (exit $ECO_ALL_EXIT)"
    ((failed++))
fi

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

# Test --json feature
echo ""
echo "========================================"
echo "  Testing --json feature"
echo "========================================"

if ! command -v jq >/dev/null 2>&1; then
    echo -e "${YELLOW:-}SKIP${NC}: jq not installed; --json tests skipped"
else
    JSON_FILE="/tmp/shai-hulud-test-json-$$.json"

    # Test 1: infected project -> valid JSON, risk_level high, HIGH findings present
    "$BASH_CMD" "$DETECTOR" --json "$JSON_FILE" "$SCRIPT_DIR/test-cases/infected-project" >/dev/null 2>&1
    if [[ -f "$JSON_FILE" ]] && jq -e . "$JSON_FILE" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}: --json produces well-formed JSON"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json did not produce valid JSON"
        ((failed++))
    fi
    ((total++))

    risk=$(jq -r '.risk_level' "$JSON_FILE" 2>/dev/null)
    high_n=$(jq -r '.summary.high' "$JSON_FILE" 2>/dev/null)
    if [[ "$risk" == "high" && "${high_n:-0}" -gt 0 ]]; then
        echo -e "${GREEN}PASS${NC}: --json reports risk_level=high with $high_n HIGH findings"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json risk_level/summary wrong (risk=$risk high=$high_n)"
        ((failed++))
    fi
    ((total++))

    # Test 2: findings preserve the per-finding message (which --save-log discards)
    msg_n=$(jq -r '[.findings[] | select(.message != "")] | length' "$JSON_FILE" 2>/dev/null)
    if [[ "${msg_n:-0}" -gt 0 ]]; then
        echo -e "${GREEN}PASS${NC}: --json preserves finding messages ($msg_n with reasons)"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json findings have no messages"
        ((failed++))
    fi
    ((total++))

    # Test 2b: package findings carry a best-effort line number pointing at the
    # actual dependency line in the manifest (axios-attack: axios on line 6).
    "$BASH_CMD" "$DETECTOR" --json "$JSON_FILE" "$SCRIPT_DIR/test-cases/axios-attack" >/dev/null 2>&1
    axios_line=$(jq -r '.findings[] | select(.message == "axios@1.14.1") | .line' "$JSON_FILE" 2>/dev/null)
    truth_line=$(grep -nF '"axios"' "$SCRIPT_DIR/test-cases/axios-attack/package.json" | head -1 | cut -d: -f1)
    if [[ -n "$axios_line" && "$axios_line" == "$truth_line" ]]; then
        echo -e "${GREEN}PASS${NC}: --json package finding line number is accurate (axios -> line $axios_line)"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json line number wrong (got $axios_line, expected $truth_line)"
        ((failed++))
    fi
    ((total++))

    # Test 3: JSON path set matches the --save-log path set (parity)
    PARITY_LOG="/tmp/shai-hulud-test-parity-$$.log"
    "$BASH_CMD" "$DETECTOR" --save-log "$PARITY_LOG" --json "$JSON_FILE" "$SCRIPT_DIR/test-cases/infected-project" >/dev/null 2>&1
    grep -vE '^#|^$' "$PARITY_LOG" 2>/dev/null | LC_ALL=C sort -u > "/tmp/shai-hulud-parity-log-$$.txt"
    jq -r '.findings[].file' "$JSON_FILE" 2>/dev/null | LC_ALL=C sort -u > "/tmp/shai-hulud-parity-json-$$.txt"
    if diff -q "/tmp/shai-hulud-parity-log-$$.txt" "/tmp/shai-hulud-parity-json-$$.txt" >/dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}: --json path set matches --save-log path set"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json path set differs from --save-log"
        ((failed++))
    fi
    ((total++))

    # Test 4: clean project -> risk_level none, zero findings
    "$BASH_CMD" "$DETECTOR" --json "$JSON_FILE" "$SCRIPT_DIR/test-cases/clean-project" >/dev/null 2>&1
    clean_risk=$(jq -r '.risk_level' "$JSON_FILE" 2>/dev/null)
    clean_n=$(jq -r '.findings | length' "$JSON_FILE" 2>/dev/null)
    if [[ "$clean_risk" == "none" && "${clean_n:-1}" -eq 0 ]]; then
        echo -e "${GREEN}PASS${NC}: --json clean project has risk_level=none, no findings"
        ((passed++))
    else
        echo -e "${RED}FAIL${NC}: --json clean project wrong (risk=$clean_risk n=$clean_n)"
        ((failed++))
    fi
    ((total++))

    rm -f "$JSON_FILE" "$PARITY_LOG" "/tmp/shai-hulud-parity-log-$$.txt" "/tmp/shai-hulud-parity-json-$$.txt"
fi

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

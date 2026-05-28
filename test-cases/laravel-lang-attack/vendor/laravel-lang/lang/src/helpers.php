<?php
// TEST FIXTURE - inert stand-in for the malicious src/helpers.php the attacker added
// to autoload.files so RCE fires on `require vendor/autoload.php`. The real payload
// base64-decodes and runs the DebugElevator / DebugChromium Windows infostealer
// (or an ELF on Linux CI runners) and exfiltrates to flipboxstudio.info. The strings
// below are the inert IoCs the detector matches. Function body is disabled.

// Stage-1 C2 (typosquat of the legit flipboxstudio.com).
$C2 = "https://flipboxstudio.info";        // GET /payload, POST /exfil
$PAYLOAD_NAME = "DebugElevator";            // a.k.a. DebugChromium.exe
$PDB_HINT = "Chromium-DebugElevator";       // from the embedded PDB path

// Disabled in the fixture - never executes.
function laravel_lang_fixture_noop() {
    return false;
}

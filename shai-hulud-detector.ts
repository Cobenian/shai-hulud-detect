#!/usr/bin/env -S deno run --allow-read

// Shai-Hulud NPM Supply Chain Attack Detection Script
// Detects indicators of compromise from the September 2025 npm attack
// Usage: deno run --allow-read shai-hulud-detector.ts <directory_to_scan>

// Color codes for output

import process from "node:process";

const COLORS = {
    RED: '\x1b[0;31m',
    YELLOW: '\x1b[1;33m',
    GREEN: '\x1b[0;32m',
    BLUE: '\x1b[0;34m',
    NC: '\x1b[0m' // No Color
};

// Known malicious file hashes (source: https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
const MALICIOUS_HASHLIST = [
    "de0e25a3e6c1e1e5998b306b7141b3dc4c0088da9d7bb47c1c00c91e6e4f85d6",
    "81d2a004a1bca6ef87a1caf7d0e0b355ad1764238e40ff6d1b1cb77ad4f595c3",
    "83a650ce44b2a9854802a7fb4c202877815274c129af49e6c2d1d5d5d55c501e",
    "4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db",
    "dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c",
    "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09",
    "b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777",
    "86532ed94c5804e1ca32fa67257e1bb9de628e3e48a1f56e67042dc055effb5b", // test-cases/multi-hash-detection/file1.js
    "aba1fcbd15c6ba6d9b96e34cec287660fff4a31632bf76f2a766c499f55ca1ee" // test-cases/multi-hash-detection/file2.js
];

// Known compromised namespaces - packages in these namespaces may be compromised
const COMPROMISED_NAMESPACES = [
    "@crowdstrike",
    "@art-ws",
    "@ngx",
    "@ctrl",
    "@nativescript-community",
    "@ahmedhfarag",
    "@operato",
    "@teselagen",
    "@things-factory",
    "@hestjs",
    "@nstudio",
    "@basic-ui-components-stc",
    "@nexe",
    "@thangved",
    "@tnf-dev",
    "@ui-ux-gang",
    "@yoobic",
];

// Global arrays to store findings with risk levels
const WORKFLOW_FILES: string[] = [];
const MALICIOUS_HASHES: string[] = [];
const COMPROMISED_FOUND: string[] = [];
const SUSPICIOUS_CONTENT: string[] = [];
const CRYPTO_PATTERNS: string[] = [];
const GIT_BRANCHES: string[] = [];
const POSTINSTALL_HOOKS: string[] = [];
const TRUFFLEHOG_ACTIVITY: string[] = [];
const SHAI_HULUD_REPOS: string[] = [];
const NAMESPACE_WARNINGS: string[] = [];
const LOW_RISK_FINDINGS: string[] = [];
const INTEGRITY_ISSUES: string[] = [];
const TYPOSQUATTING_WARNINGS: string[] = [];
const NETWORK_EXFILTRATION_WARNINGS: string[] = [];

let COMPROMISED_PACKAGES: string[] = [];

// Utility functions
function printStatus(color: string, message: string): void {
    console.log(`${color}${message}${COLORS.NC}`);
}

function showFilePreview(filePath: string, context: string): void {
    // Only show file preview for HIGH RISK items to reduce noise
    if (context.includes("HIGH RISK")) {
        console.log(`   ${COLORS.BLUE}┌─ File: ${filePath}${COLORS.NC}`);
        console.log(`   ${COLORS.BLUE}│  Context: ${context}${COLORS.NC}`);
        console.log(`   ${COLORS.BLUE}└─${COLORS.NC}`);
        console.log();
    }
}

async function loadCompromisedPackages(): Promise<void> {
    const scriptDir = new URL(".", import.meta.url).pathname;
    const packagesFile = `${scriptDir}compromised-packages.txt`;
    
    COMPROMISED_PACKAGES = [];
    
    try {
        const content = await Deno.readTextFile(packagesFile);
        const lines = content.split('\n');
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            // Skip comments and empty lines
            if (trimmedLine.startsWith('#') || trimmedLine === '') {
                continue;
            }
            
            // Add valid package:version lines to array
            if (/^[a-zA-Z@][^:]+:[0-9]+\.[0-9]+\.[0-9]+/.test(trimmedLine)) {
                COMPROMISED_PACKAGES.push(trimmedLine);
            }
        }
        
        printStatus(COLORS.BLUE, `📦 Loaded ${COMPROMISED_PACKAGES.length} compromised packages from ${packagesFile}`);
    } catch {
        // Fallback to embedded list if file not found
        printStatus(COLORS.YELLOW, `⚠️  Warning: ${packagesFile} not found, using embedded package list`);
        COMPROMISED_PACKAGES = [
            // Core compromised packages - fallback list
            "@ctrl/tinycolor:4.1.0",
            "@ctrl/tinycolor:4.1.1",
            "@ctrl/tinycolor:4.1.2",
            "@ctrl/deluge:1.2.0",
            "angulartics2:14.1.2",
            "koa2-swagger-ui:5.11.1",
            "koa2-swagger-ui:5.11.2"
        ];
    }
}

async function sha256(data: Uint8Array): Promise<string> {
    // Use underlying ArrayBuffer to satisfy TS typing (ArrayBuffer required, not generic ArrayBufferLike)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data.buffer as ArrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function* walkDirectory(dir: string): AsyncGenerator<string> {
    try {
        for await (const entry of Deno.readDir(dir)) {
            const path = `${dir}/${entry.name}`;
            if (entry.isDirectory) {
                yield* walkDirectory(path);
            } else {
                yield path;
            }
        }
    } catch {
        // Skip directories we can't read
    }
}

async function findFiles(dir: string, pattern: RegExp): Promise<string[]> {
    const files: string[] = [];
    for await (const file of walkDirectory(dir)) {
        if (pattern.test(file)) {
            files.push(file);
        }
    }
    return files;
}

function transformPnpmYaml(content: string): string {
    const lines = content.split('\n');
    const result = ['{"packages": {'];
    let inPackages = false;
    
    for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed.startsWith('#') || trimmed === '') continue;
        
        const indentLevel = line.length - line.trimStart().length;
        const [key, ...valueParts] = trimmed.split(':');
        const value = valueParts.join(':').trim();
        
        if (indentLevel === 0 && key === 'packages') {
            inPackages = true;
            continue;
        }
        
        if (inPackages && indentLevel === 2 && key && value) {
            const cleanKey = key.replace(/['"]/g, '');
            const parts = cleanKey.split('@');
            
            if (parts.length >= 2) {
                const name = parts.slice(0, -1).join('@');
                const version = parts[parts.length - 1].trim();
                result.push(`    "${name}": {"version": "${version}"},`);
            }
        }
        
        if (indentLevel === 0 && key !== 'packages') {
            inPackages = false;
        }
    }
    
    result.push('}}');
    return result.join('\n');
}

async function checkWorkflowFiles(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for malicious workflow files...");
    
    const files = await findFiles(scanDir, /shai-hulud-workflow\.yml$/);
    for (const file of files) {
        try {
            const stat = await Deno.stat(file);
            if (stat.isFile) {
                WORKFLOW_FILES.push(file);
            }
        } catch {
            // Skip files we can't access
        }
    }
}

async function checkFileHashes(scanDir: string): Promise<void> {
    const jsFiles = await findFiles(scanDir, /\.(js|ts|json)$/);
    
    printStatus(COLORS.BLUE, `🔍 Checking ${jsFiles.length} files for known malicious content...`);
    
    const promises = jsFiles.map(async (file, index) => {
        try {
            const data = await Deno.readFile(file);
            const hash = await sha256(data);
            
            // Progress indicator
            if (index % 10 === 0) {
                process.stdout.write(`\r\x1b[K${index + 1} / ${jsFiles.length} checked (${Math.floor((index + 1) * 100 / jsFiles.length)} %)`);
            }
            
            // Check for malicious files
            if (MALICIOUS_HASHLIST.includes(hash)) {
                MALICIOUS_HASHES.push(`${file}:${hash}`);
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
    process.stdout.write(`\r\x1b[K`);
}

async function checkPackages(scanDir: string): Promise<void> {
    const packageFiles = await findFiles(scanDir, /package\.json$/);
    
    printStatus(COLORS.BLUE, `🔍 Checking ${packageFiles.length} package.json files for compromised packages...`);
    
    const promises = packageFiles.map(async (packageFile, index) => {
        try {
            const content = await Deno.readTextFile(packageFile);
            
            // Progress indicator
            if (index % 5 === 0) {
                process.stdout.write(`\r\x1b[K${index + 1} / ${packageFiles.length} checked (${Math.floor((index + 1) * 100 / packageFiles.length)} %)`);
            }
            
            // Check for specific compromised packages
            for (const packageInfo of COMPROMISED_PACKAGES) {
                const [packageName, maliciousVersion] = packageInfo.split(':');
                
                if (content.includes(`"${packageName}"`)) {
                    // Extract version more precisely
                    const regex = new RegExp(`"${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}":\\s*"([^"]+)"`);
                    const match = content.match(regex);
                    if (match && match[1] === maliciousVersion) {
                        COMPROMISED_FOUND.push(`${packageFile}:${packageName}@${maliciousVersion}`);
                    }
                }
            }
            
            // Check for suspicious namespaces
            for (const namespace of COMPROMISED_NAMESPACES) {
                if (content.includes(`"${namespace}/`)) {
                    NAMESPACE_WARNINGS.push(`${packageFile}:Contains packages from compromised namespace: ${namespace}`);
                }
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
    process.stdout.write(`\r\x1b[K`);
}

async function checkPostinstallHooks(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for suspicious postinstall hooks...");
    
    const packageFiles = await findFiles(scanDir, /package\.json$/);
    
    for (const packageFile of packageFiles) {
        try {
            const content = await Deno.readTextFile(packageFile);
            
            if (content.includes('"postinstall"')) {
                const lines = content.split('\n');
                let postinstallCmd = '';
                
                for (let i = 0; i < lines.length; i++) {
                    if (lines[i].includes('"postinstall"')) {
                        // Look for the command in the next few lines
                        for (let j = i; j < Math.min(i + 3, lines.length); j++) {
                            const cmdMatch = lines[j].match(/"([^"]*)"[^"]*$/);
                            if (cmdMatch && !lines[j].includes('"postinstall"')) {
                                postinstallCmd = cmdMatch[1];
                                break;
                            }
                        }
                        break;
                    }
                }
                
                // Check for suspicious patterns in postinstall commands
                if (postinstallCmd && (
                    postinstallCmd.includes('curl') ||
                    postinstallCmd.includes('wget') ||
                    postinstallCmd.includes('node -e') ||
                    postinstallCmd.includes('eval') ||
                    postinstallCmd.includes('base64')
                )) {
                    POSTINSTALL_HOOKS.push(`${packageFile}:Suspicious postinstall: ${postinstallCmd}`);
                }
            }
        } catch {
            // Skip files we can't read
        }
    }
}

async function checkContent(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for suspicious content patterns...");
    
    const files = await findFiles(scanDir, /\.(js|ts|json|yml|yaml)$/);
    
    const promises = files.map(async (file) => {
        try {
            const content = await Deno.readTextFile(file);
            
            if (content.includes('webhook.site')) {
                SUSPICIOUS_CONTENT.push(`${file}:webhook.site reference`);
            }
            if (content.includes('bb8ca5f6-4175-45d2-b042-fc9ebb8170b7')) {
                SUSPICIOUS_CONTENT.push(`${file}:malicious webhook endpoint`);
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
}

async function checkCryptoTheftPatterns(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for cryptocurrency theft patterns...");
    
    const files = await findFiles(scanDir, /\.(js|ts|json)$/);
    
    const promises = files.map(async (file) => {
        try {
            const content = await Deno.readTextFile(file);
            
            if (/0x[a-fA-F0-9]{40}/.test(content)) {
                if (/ethereum|wallet|address|crypto/i.test(content)) {
                    CRYPTO_PATTERNS.push(`${file}:Ethereum wallet address patterns detected`);
                }
            }
            
            if (content.includes('XMLHttpRequest.prototype.send')) {
                CRYPTO_PATTERNS.push(`${file}:XMLHttpRequest prototype modification detected`);
            }
            
            if (/checkethereumw|runmask|newdlocal|_0x19ca67/.test(content)) {
                CRYPTO_PATTERNS.push(`${file}:Known crypto theft function names detected`);
            }
            
            if (/0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976|1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx|TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67/.test(content)) {
                CRYPTO_PATTERNS.push(`${file}:Known attacker wallet address detected - HIGH RISK`);
            }
            
            if (content.includes('npmjs.help')) {
                CRYPTO_PATTERNS.push(`${file}:Phishing domain npmjs.help detected`);
            }
            
            if (content.includes('javascript-obfuscator')) {
                CRYPTO_PATTERNS.push(`${file}:JavaScript obfuscation detected`);
            }
            
            if (/ethereum.*0x[a-fA-F0-9]|bitcoin.*[13][a-km-zA-HJ-NP-Z1-9]/.test(content)) {
                CRYPTO_PATTERNS.push(`${file}:Cryptocurrency regex patterns detected`);
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
}

async function checkGitBranches(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for suspicious git branches...");
    
    const gitDirs = await findFiles(scanDir, /\.git$/);
    
    for (const gitDir of gitDirs) {
        try {
            const stat = await Deno.stat(gitDir);
            if (stat.isDirectory) {
                const refsDir = `${gitDir}/refs/heads`;
                try {
                    const repoDir = gitDir.replace('/.git', '');
                    for await (const entry of Deno.readDir(refsDir)) {
                        if (entry.name.includes('shai-hulud') && entry.isFile) {
                            const branchFile = `${refsDir}/${entry.name}`;
                            const commitHash = (await Deno.readTextFile(branchFile)).trim();
                            GIT_BRANCHES.push(`${repoDir}:Branch '${entry.name}' (commit: ${commitHash.substring(0, 8)}...)`);
                        }
                    }
                } catch {
                    // Skip if we can't read refs
                }
            }
        } catch {
            // Skip if we can't access git dir
        }
    }
}

function getFileContext(filePath: string): string {
    if (filePath.includes('/node_modules/')) return 'node_modules';
    if (filePath.endsWith('.md') || filePath.endsWith('.txt') || filePath.endsWith('.rst')) return 'documentation';
    if (filePath.endsWith('.d.ts')) return 'type_definitions';
    if (filePath.includes('/dist/') || filePath.includes('/build/') || filePath.includes('/public/')) return 'build_output';
    if (filePath.includes('config') || filePath.includes('.config.')) return 'configuration';
    return 'source_code';
}

function isLegitimatePattern(filePath: string, contentSample: string): boolean {
    if (contentSample.includes('process.env.NODE_ENV') && contentSample.includes('production')) return true;
    if (contentSample.includes('createApp') || contentSample.includes('Vue')) return true;
    if (contentSample.includes('webpack') || contentSample.includes('vite') || contentSample.includes('rollup')) return true;
    return false;
}

async function checkTrufflehogActivity(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for Trufflehog activity and secret scanning...");
    
    // Look for trufflehog binary files
    const trufflehogFiles = await findFiles(scanDir, /trufflehog/);
    for (const file of trufflehogFiles) {
        try {
            const stat = await Deno.stat(file);
            if (stat.isFile) {
                TRUFFLEHOG_ACTIVITY.push(`${file}:HIGH:Trufflehog binary found`);
            }
        } catch {
            // Skip files we can't access
        }
    }
    
    // Look for potential trufflehog activity in files
    const files = await findFiles(scanDir, /\.(js|py|sh|json)$/);
    
    const promises = files.map(async (file) => {
        try {
            const content = await Deno.readTextFile(file);
            const context = getFileContext(file);
            const contentSample = content.split('\n').slice(0, 20).join(' ');
            
            // Check for explicit trufflehog references
            if (/trufflehog|TruffleHog/i.test(content)) {
                switch (context) {
                    case 'documentation':
                        break; // Skip documentation
                    case 'node_modules':
                    case 'type_definitions':
                    case 'build_output':
                        TRUFFLEHOG_ACTIVITY.push(`${file}:MEDIUM:Contains trufflehog references in ${context}`);
                        break;
                    default:
                        if (content.includes('subprocess') && content.includes('curl')) {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:HIGH:Suspicious trufflehog execution pattern`);
                        } else {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:MEDIUM:Contains trufflehog references in source code`);
                        }
                }
            }
            
            // Check for credential scanning combined with exfiltration
            if (/AWS_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN/.test(content)) {
                switch (context) {
                    case 'type_definitions':
                    case 'documentation':
                        break; // Skip
                    case 'node_modules':
                        TRUFFLEHOG_ACTIVITY.push(`${file}:LOW:Credential patterns in node_modules`);
                        break;
                    case 'configuration':
                        if (!(content.includes('DefinePlugin') || content.includes('webpack'))) {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:MEDIUM:Credential patterns in configuration`);
                        }
                        break;
                    default:
                        if (content.includes('webhook.site') || content.includes('curl') || content.includes('https.request')) {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:HIGH:Credential patterns with potential exfiltration`);
                        } else {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:MEDIUM:Contains credential scanning patterns`);
                        }
                }
            }
            
            // Check for environment variable scanning
            if (/process\.env|os\.environ|getenv/.test(content)) {
                switch (context) {
                    case 'type_definitions':
                    case 'documentation':
                    case 'configuration':
                        break; // Skip
                    case 'node_modules':
                    case 'build_output':
                        if (!isLegitimatePattern(file, contentSample)) {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:LOW:Environment variable access in ${context}`);
                        }
                        break;
                    default:
                        if (content.includes('webhook.site') && content.includes('exfiltrat')) {
                            TRUFFLEHOG_ACTIVITY.push(`${file}:HIGH:Environment scanning with exfiltration`);
                        } else if (/scan|harvest|steal/.test(content)) {
                            if (!isLegitimatePattern(file, contentSample)) {
                                TRUFFLEHOG_ACTIVITY.push(`${file}:MEDIUM:Potentially suspicious environment variable access`);
                            }
                        }
                }
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
}

async function checkShaiHuludRepos(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking for Shai-Hulud repositories and migration patterns...");
    
    const gitDirs = await findFiles(scanDir, /\.git$/);
    
    for (const gitDir of gitDirs) {
        try {
            const stat = await Deno.stat(gitDir);
            if (stat.isDirectory) {
                const repoDir = gitDir.replace('/.git', '');
                const repoName = repoDir.split('/').pop() || '';
                
                if (repoName.includes('shai-hulud') || repoName.includes('Shai-Hulud')) {
                    SHAI_HULUD_REPOS.push(`${repoDir}:Repository name contains 'Shai-Hulud'`);
                }
                
                if (repoName.includes('-migration')) {
                    SHAI_HULUD_REPOS.push(`${repoDir}:Repository name contains migration pattern`);
                }
                
                // Check for GitHub remote URLs containing shai-hulud
                const configFile = `${gitDir}/config`;
                try {
                    const config = await Deno.readTextFile(configFile);
                    if (/shai-hulud|Shai-Hulud/i.test(config)) {
                        SHAI_HULUD_REPOS.push(`${repoDir}:Git remote contains 'Shai-Hulud'`);
                    }
                } catch {
                    // Skip if can't read config
                }
                
                // Check for double base64-encoded data.json
                const dataJsonFile = `${repoDir}/data.json`;
                try {
                    const content = await Deno.readTextFile(dataJsonFile);
                    const contentSample = content.split('\n').slice(0, 5).join('');
                    if (contentSample.includes('eyJ') && contentSample.includes('==')) {
                        SHAI_HULUD_REPOS.push(`${repoDir}:Contains suspicious data.json (possible base64-encoded credentials)`);
                    }
                } catch {
                    // Skip if data.json doesn't exist
                }
            }
        } catch {
            // Skip if we can't access git dir
        }
    }
}

async function checkPackageIntegrity(scanDir: string): Promise<void> {
    printStatus(COLORS.BLUE, "🔍 Checking package lock files for integrity issues...");
    
    const lockFiles = await findFiles(scanDir, /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/);
    
    for (const lockFile of lockFiles) {
        try {
            let content: string;
            let originalFile = lockFile;
            
            if (lockFile.endsWith('pnpm-lock.yaml')) {
                const pnpmContent = await Deno.readTextFile(lockFile);
                content = transformPnpmYaml(pnpmContent);
            } else {
                content = await Deno.readTextFile(lockFile);
            }
            
            // Look for compromised packages in lockfiles
            for (const packageInfo of COMPROMISED_PACKAGES) {
                const [packageName, maliciousVersion] = packageInfo.split(':');
                
                if (content.includes(`"${packageName}"`)) {
                    const versionRegex = new RegExp(`"${packageName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"[^}]*"version":\\s*"([^"]+)"`);
                    const match = content.match(versionRegex);
                    if (match && match[1] === maliciousVersion) {
                        INTEGRITY_ISSUES.push(`${originalFile}:Compromised package in lockfile: ${packageName}@${maliciousVersion}`);
                    }
                }
            }
            
            // Check for recently modified lockfiles with @ctrl packages
            if (content.includes('@ctrl')) {
                try {
                    const stat = await Deno.stat(originalFile);
                    const fileAge = Date.now() - stat.mtime!.getTime();
                    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
                    
                    if (fileAge < thirtyDays) {
                        INTEGRITY_ISSUES.push(`${originalFile}:Recently modified lockfile contains @ctrl packages (potential worm activity)`);
                    }
                } catch {
                    // Skip if we can't get file stats
                }
            }
        } catch {
            // Skip files we can't read
        }
    }
}

async function checkTyposquatting(scanDir: string): Promise<void> {
    const popularPackages = [
        "react", "vue", "angular", "express", "lodash", "axios", "typescript",
        "webpack", "babel", "eslint", "jest", "mocha", "chalk", "debug",
        "commander", "inquirer", "yargs", "request", "moment", "underscore",
        "jquery", "bootstrap", "socket.io", "redis", "mongoose", "passport"
    ];
    
    const packageFiles = await findFiles(scanDir, /package\.json$/);
    
    for (const packageFile of packageFiles) {
        try {
            const content = await Deno.readTextFile(packageFile);
            const packageNames = new Set<string>();
            
            // Extract package names from dependencies sections
            const dependencyRegex = /"([^"]+)":\s*"[^"]+"/g;
            let match;
            
            const sections = content.match(/"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)":\s*\{[^}]*\}/gs);
            if (sections) {
                for (const section of sections) {
                    while ((match = dependencyRegex.exec(section)) !== null) {
                        const packageName = match[1];
                        if (packageName.length >= 2 && /[a-zA-Z]/.test(packageName)) {
                            packageNames.add(packageName);
                        }
                    }
                }
            }
            
            for (const packageName of packageNames) {
                // Check for non-ASCII characters
                if (!/^[a-zA-Z0-9@/._-]*$/.test(packageName)) {
                    TYPOSQUATTING_WARNINGS.push(`${packageFile}:Potential Unicode/homoglyph characters in package: ${packageName}`);
                }
                
                // Check similarity to popular packages
                for (const popular of popularPackages) {
                    if (packageName === popular) continue;
                    
                    // Skip common legitimate variations
                    if (['test', 'tests', 'testing', 'types', 'util', 'utils', 'core', 'lib', 'libs', 'common', 'shared'].includes(packageName)) {
                        continue;
                    }
                    
                    // Check for single character differences
                    if (packageName.length === popular.length && packageName.length > 4) {
                        let diffCount = 0;
                        for (let i = 0; i < packageName.length; i++) {
                            if (packageName[i] !== popular[i]) {
                                diffCount++;
                            }
                        }
                        
                        if (diffCount === 1 && !packageName.includes('-') && !popular.includes('-')) {
                            TYPOSQUATTING_WARNINGS.push(`${packageFile}:Potential typosquatting of '${popular}': ${packageName} (1 character difference)`);
                        }
                    }
                }
            }
        } catch {
            // Skip files we can't read
        }
    }
}

async function checkNetworkExfiltration(scanDir: string): Promise<void> {
    const suspiciousDomains = [
        "pastebin.com", "hastebin.com", "ix.io", "0x0.st", "transfer.sh",
        "file.io", "anonfiles.com", "mega.nz", "dropbox.com/s/",
        "discord.com/api/webhooks", "telegram.org", "t.me",
        "ngrok.io", "localtunnel.me", "serveo.net",
        "requestbin.com", "webhook.site", "beeceptor.com",
        "pipedream.com", "zapier.com/hooks"
    ];
    
    const files = await findFiles(scanDir, /\.(js|ts|json|mjs)$/);
    
    const promises = files.map(async (file) => {
        try {
            const content = await Deno.readTextFile(file);
            
            // Skip vendor/library files to reduce false positives
            if (!file.includes('/vendor/') && !file.includes('/node_modules/')) {
                // Check for hardcoded IP addresses
                const ipMatches = content.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g);
                if (ipMatches) {
                    const filteredIps = ipMatches.filter(ip => 
                        ip !== '127.0.0.1' && ip !== '0.0.0.0'
                    );
                    if (filteredIps.length > 0) {
                        const ipsContext = filteredIps.slice(0, 3).join(' ');
                        if (file.includes('.min.js')) {
                            NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Hardcoded IP addresses found (minified file): ${ipsContext}`);
                        } else {
                            NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Hardcoded IP addresses found: ${ipsContext}`);
                        }
                    }
                }
            }
            
            // Check for suspicious domains
            if (!file.includes('package-lock.json') && !file.includes('yarn.lock') && 
                !file.includes('/vendor/') && !file.includes('/node_modules/')) {
                
                for (const domain of suspiciousDomains) {
                    const domainRegex = new RegExp(`https?://[^\\s]*${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}|\\s${domain.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}[\\s/\\"']`, 'g');
                    const matches = content.match(domainRegex);
                    
                    if (matches) {
                        const suspiciousUsage = matches.filter(match => 
                            !match.trim().startsWith('#') && !match.trim().startsWith('//')
                        );
                        
                        if (suspiciousUsage.length > 0) {
                            const lines = content.split('\n');
                            let lineNum = 0;
                            for (let i = 0; i < lines.length; i++) {
                                if (lines[i].includes(domain) && 
                                    !lines[i].trim().startsWith('#') && 
                                    !lines[i].trim().startsWith('//')) {
                                    lineNum = i + 1;
                                    break;
                                }
                            }
                            
                            let snippet = suspiciousUsage[0];
                            if (file.includes('.min.js') || snippet.length > 150) {
                                const shortSnippet = snippet.substring(0, 40) + '...';
                                NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Suspicious domain found: ${domain}${lineNum ? ` at line ${lineNum}` : ''}: ...${shortSnippet}...`);
                            } else {
                                const shortSnippet = snippet.substring(0, 80) + (snippet.length > 80 ? '...' : '');
                                NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Suspicious domain found: ${domain}${lineNum ? ` at line ${lineNum}` : ''}: ${shortSnippet}`);
                            }
                        }
                    }
                }
            }
            
            // Additional checks for base64 decoding, DNS-over-HTTPS, WebSocket, etc.
            if (!file.includes('/vendor/') && !file.includes('/node_modules/')) {
                if (content.includes('atob(') || content.includes('base64') && content.includes('decode')) {
                    const lines = content.split('\n');
                    let lineNum = 0;
                    let snippet = '';
                    
                    for (let i = 0; i < lines.length; i++) {
                        if (lines[i].includes('atob') || (lines[i].includes('base64') && lines[i].includes('decode'))) {
                            lineNum = i + 1;
                            if (file.includes('.min.js') || lines[i].length > 500) {
                                const match = lines[i].match(/.{0,30}atob.{0,30}/);
                                snippet = match ? match[0] : lines[i].substring(0, 60);
                            } else {
                                snippet = lines[i].substring(0, 80);
                            }
                            break;
                        }
                    }
                    
                    if (lineNum > 0) {
                        NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Base64 decoding at line ${lineNum}: ${snippet}...`);
                    } else {
                        NETWORK_EXFILTRATION_WARNINGS.push(`${file}:Base64 decoding detected`);
                    }
                }
            }
        } catch {
            // Skip files we can't read
        }
    });
    
    await Promise.all(promises);
}

function generateReport(paranoidMode: boolean): void {
    console.log();
    printStatus(COLORS.BLUE, "==============================================");
    if (paranoidMode) {
        printStatus(COLORS.BLUE, "  SHAI-HULUD + PARANOID SECURITY REPORT");
    } else {
        printStatus(COLORS.BLUE, "      SHAI-HULUD DETECTION REPORT");
    }
    printStatus(COLORS.BLUE, "==============================================");
    console.log();
    
    let highRisk = 0;
    let mediumRisk = 0;
    
    // Report malicious workflow files
    if (WORKFLOW_FILES.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Malicious workflow files detected:");
        for (const file of WORKFLOW_FILES) {
            console.log(`   - ${file}`);
            showFilePreview(file, "HIGH RISK: Known malicious workflow filename");
            highRisk++;
        }
    }
    
    // Report malicious file hashes
    if (MALICIOUS_HASHES.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Files with known malicious hashes:");
        for (const entry of MALICIOUS_HASHES) {
            const [filePath, hash] = entry.split(':');
            console.log(`   - ${filePath}`);
            console.log(`     Hash: ${hash}`);
            showFilePreview(filePath, "HIGH RISK: File matches known malicious SHA-256 hash");
            highRisk++;
        }
    }
    
    // Report compromised packages
    if (COMPROMISED_FOUND.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Compromised package versions detected:");
        for (const entry of COMPROMISED_FOUND) {
            const [filePath, packageInfo] = entry.split(':');
            console.log(`   - Package: ${packageInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `HIGH RISK: Contains compromised package version: ${packageInfo}`);
            highRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These specific package versions are known to be compromised.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}You should immediately update or remove these packages.${COLORS.NC}`);
        console.log();
    }
    
    // Report suspicious content
    if (SUSPICIOUS_CONTENT.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Suspicious content patterns:");
        for (const entry of SUSPICIOUS_CONTENT) {
            const [filePath, pattern] = entry.split(':');
            console.log(`   - Pattern: ${pattern}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `Contains suspicious pattern: ${pattern}`);
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: Manual review required to determine if these are malicious.${COLORS.NC}`);
        console.log();
    }
    
    // Report cryptocurrency theft patterns
    const cryptoHigh = CRYPTO_PATTERNS.filter(entry => 
        entry.includes("HIGH RISK") || entry.includes("Known attacker wallet") || entry.includes("XMLHttpRequest prototype")
    );
    const cryptoMedium = CRYPTO_PATTERNS.filter(entry => !cryptoHigh.includes(entry));
    
    if (cryptoHigh.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Cryptocurrency theft patterns detected:");
        for (const entry of cryptoHigh) {
            console.log(`   - ${entry}`);
            highRisk++;
        }
        console.log(`   ${COLORS.RED}NOTE: These patterns strongly indicate crypto theft malware from the September 8 attack.${COLORS.NC}`);
        console.log(`   ${COLORS.RED}Immediate investigation and remediation required.${COLORS.NC}`);
        console.log();
    }
    
    if (cryptoMedium.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Potential cryptocurrency manipulation patterns:");
        for (const entry of cryptoMedium) {
            console.log(`   - ${entry}`);
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These may be legitimate crypto tools or framework code.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Manual review recommended to determine if they are malicious.${COLORS.NC}`);
        console.log();
    }
    
    // Report git branches
    if (GIT_BRANCHES.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Suspicious git branches:");
        for (const entry of GIT_BRANCHES) {
            const [repoPath, branchInfo] = entry.split(':');
            console.log(`   - Repository: ${repoPath}`);
            console.log(`     ${branchInfo}`);
            console.log(`     ${COLORS.BLUE}┌─ Git Investigation Commands:${COLORS.NC}`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  cd '${repoPath}'`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  git log --oneline -10 shai-hulud`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  git show shai-hulud`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  git diff main...shai-hulud`);
            console.log(`     ${COLORS.BLUE}└─${COLORS.NC}`);
            console.log();
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: 'shai-hulud' branches may indicate compromise.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Use the commands above to investigate each branch.${COLORS.NC}`);
        console.log();
    }
    
    // Report suspicious postinstall hooks
    if (POSTINSTALL_HOOKS.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Suspicious postinstall hooks detected:");
        for (const entry of POSTINSTALL_HOOKS) {
            const [filePath, hookInfo] = entry.split(':');
            console.log(`   - Hook: ${hookInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `HIGH RISK: Contains suspicious postinstall hook: ${hookInfo}`);
            highRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: Postinstall hooks can execute arbitrary code during package installation.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Review these hooks carefully for malicious behavior.${COLORS.NC}`);
        console.log();
    }
    
    // Report Trufflehog activity by risk level
    const trufflehogHigh = TRUFFLEHOG_ACTIVITY.filter(entry => entry.includes(':HIGH:'));
    const trufflehogMedium = TRUFFLEHOG_ACTIVITY.filter(entry => entry.includes(':MEDIUM:'));
    const trufflehogLow = TRUFFLEHOG_ACTIVITY.filter(entry => entry.includes(':LOW:'));
    
    if (trufflehogHigh.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Trufflehog/secret scanning activity detected:");
        for (const entry of trufflehogHigh) {
            const [filePath, , activityInfo] = entry.split(':');
            console.log(`   - Activity: ${activityInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `HIGH RISK: ${activityInfo}`);
            highRisk++;
        }
        console.log(`   ${COLORS.RED}NOTE: These patterns indicate likely malicious credential harvesting.${COLORS.NC}`);
        console.log(`   ${COLORS.RED}Immediate investigation and remediation required.${COLORS.NC}`);
        console.log();
    }
    
    if (trufflehogMedium.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Potentially suspicious secret scanning patterns:");
        for (const entry of trufflehogMedium) {
            const [filePath, , activityInfo] = entry.split(':');
            console.log(`   - Pattern: ${activityInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `MEDIUM RISK: ${activityInfo}`);
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These may be legitimate security tools or framework code.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Manual review recommended to determine if they are malicious.${COLORS.NC}`);
        console.log();
    }
    
    // Store LOW RISK findings for optional reporting
    for (const entry of trufflehogLow) {
        LOW_RISK_FINDINGS.push(`Trufflehog pattern: ${entry}`);
    }
    
    // Report Shai-Hulud repositories
    if (SHAI_HULUD_REPOS.length > 0) {
        printStatus(COLORS.RED, "🚨 HIGH RISK: Shai-Hulud repositories detected:");
        for (const entry of SHAI_HULUD_REPOS) {
            const [repoPath, repoInfo] = entry.split(':');
            console.log(`   - Repository: ${repoPath}`);
            console.log(`     ${repoInfo}`);
            console.log(`     ${COLORS.BLUE}┌─ Repository Investigation Commands:${COLORS.NC}`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  cd '${repoPath}'`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  git log --oneline -10`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  git remote -v`);
            console.log(`     ${COLORS.BLUE}│${COLORS.NC}  ls -la`);
            console.log(`     ${COLORS.BLUE}└─${COLORS.NC}`);
            console.log();
            highRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}These should be deleted immediately after investigation.${COLORS.NC}`);
        console.log();
    }
    
    // Report namespace warnings
    if (NAMESPACE_WARNINGS.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Packages from compromised namespaces:");
        for (const entry of NAMESPACE_WARNINGS) {
            const [filePath, namespaceInfo] = entry.split(':');
            console.log(`   - Warning: ${namespaceInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, "Contains packages from compromised namespace");
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These namespaces have been compromised but specific versions may vary.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Check package versions against known compromise lists.${COLORS.NC}`);
        console.log();
    }
    
    // Report package integrity issues
    if (INTEGRITY_ISSUES.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK: Package integrity issues detected:");
        for (const entry of INTEGRITY_ISSUES) {
            const [filePath, issueInfo] = entry.split(':');
            console.log(`   - Issue: ${issueInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `Package integrity issue: ${issueInfo}`);
            mediumRisk++;
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These issues may indicate tampering with package dependencies.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Verify package versions and regenerate lockfiles if necessary.${COLORS.NC}`);
        console.log();
    }
    
    // Report typosquatting warnings (only in paranoid mode)
    if (paranoidMode && TYPOSQUATTING_WARNINGS.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK (PARANOID): Potential typosquatting/homoglyph attacks detected:");
        const displayCount = Math.min(5, TYPOSQUATTING_WARNINGS.length);
        for (let i = 0; i < displayCount; i++) {
            const entry = TYPOSQUATTING_WARNINGS[i];
            const [filePath, warningInfo] = entry.split(':');
            console.log(`   - Warning: ${warningInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `Potential typosquatting: ${warningInfo}`);
            mediumRisk++;
        }
        if (TYPOSQUATTING_WARNINGS.length > 5) {
            console.log(`   - ... and ${TYPOSQUATTING_WARNINGS.length - 5} more typosquatting warnings (truncated for brevity)`);
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These packages may be impersonating legitimate packages.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Verify package names carefully and check if they should be legitimate packages.${COLORS.NC}`);
        console.log();
    }
    
    // Report network exfiltration warnings (only in paranoid mode)
    if (paranoidMode && NETWORK_EXFILTRATION_WARNINGS.length > 0) {
        printStatus(COLORS.YELLOW, "⚠️  MEDIUM RISK (PARANOID): Network exfiltration patterns detected:");
        const displayCount = Math.min(5, NETWORK_EXFILTRATION_WARNINGS.length);
        for (let i = 0; i < displayCount; i++) {
            const entry = NETWORK_EXFILTRATION_WARNINGS[i];
            const [filePath, warningInfo] = entry.split(':');
            console.log(`   - Warning: ${warningInfo}`);
            console.log(`     Found in: ${filePath}`);
            showFilePreview(filePath, `Network exfiltration pattern: ${warningInfo}`);
            mediumRisk++;
        }
        if (NETWORK_EXFILTRATION_WARNINGS.length > 5) {
            console.log(`   - ... and ${NETWORK_EXFILTRATION_WARNINGS.length - 5} more network warnings (truncated for brevity)`);
        }
        console.log(`   ${COLORS.YELLOW}NOTE: These patterns may indicate data exfiltration or communication with C2 servers.${COLORS.NC}`);
        console.log(`   ${COLORS.YELLOW}Review network connections and data flows carefully.${COLORS.NC}`);
        console.log();
    }
    
    const totalIssues = highRisk + mediumRisk;
    const lowRiskCount = LOW_RISK_FINDINGS.length;
    
    // Summary
    printStatus(COLORS.BLUE, "==============================================");
    if (totalIssues === 0) {
        printStatus(COLORS.GREEN, "✅ No indicators of Shai-Hulud compromise detected.");
        printStatus(COLORS.GREEN, "Your system appears clean from this specific attack.");
        
        // Show low risk findings if any (informational only)
        if (lowRiskCount > 0) {
            console.log();
            printStatus(COLORS.BLUE, "ℹ️  LOW RISK FINDINGS (informational only):");
            for (const finding of LOW_RISK_FINDINGS) {
                console.log(`   - ${finding}`);
            }
            console.log(`   ${COLORS.BLUE}NOTE: These are likely legitimate framework code or dependencies.${COLORS.NC}`);
        }
    } else {
        printStatus(COLORS.RED, "🔍 SUMMARY:");
        printStatus(COLORS.RED, `   High Risk Issues: ${highRisk}`);
        printStatus(COLORS.YELLOW, `   Medium Risk Issues: ${mediumRisk}`);
        if (lowRiskCount > 0) {
            printStatus(COLORS.BLUE, `   Low Risk (informational): ${lowRiskCount}`);
        }
        printStatus(COLORS.BLUE, `   Total Critical Issues: ${totalIssues}`);
        console.log();
        printStatus(COLORS.YELLOW, "⚠️  IMPORTANT:");
        printStatus(COLORS.YELLOW, "   - High risk issues likely indicate actual compromise");
        printStatus(COLORS.YELLOW, "   - Medium risk issues require manual investigation");
        printStatus(COLORS.YELLOW, "   - Low risk issues are likely false positives from legitimate code");
        if (paranoidMode) {
            printStatus(COLORS.YELLOW, "   - Issues marked (PARANOID) are general security checks, not Shai-Hulud specific");
        }
        printStatus(COLORS.YELLOW, "   - Consider running additional security scans");
        printStatus(COLORS.YELLOW, "   - Review your npm audit logs and package history");
        
        if (lowRiskCount > 0 && totalIssues < 5) {
            console.log();
            printStatus(COLORS.BLUE, "ℹ️  LOW RISK FINDINGS (likely false positives):");
            for (const finding of LOW_RISK_FINDINGS) {
                console.log(`   - ${finding}`);
            }
            console.log(`   ${COLORS.BLUE}NOTE: These are typically legitimate framework patterns.${COLORS.NC}`);
        }
    }
    printStatus(COLORS.BLUE, "==============================================");
}

function usage(): void {
    console.log("Usage: deno run --allow-read --allow-run shai-hulud-detector.ts [--paranoid] <directory_to_scan>");
    console.log();
    console.log("OPTIONS:");
    console.log("  --paranoid    Enable additional security checks (typosquatting, network patterns)");
    console.log("                These are general security features, not specific to Shai-Hulud");
    console.log();
    console.log("EXAMPLES:");
    console.log("  deno run --allow-read --allow-run shai-hulud-detector.ts /path/to/your/project                    # Core Shai-Hulud detection only");
    console.log("  deno run --allow-read --allow-run shai-hulud-detector.ts --paranoid /path/to/your/project         # Core + advanced security checks");
    Deno.exit(1);
}
// Show a processing indicator while a promise is pending
async function showProcessingIndicatorForPromise(promise: Promise<unknown>, prefix?: string): Promise<void> {
    function timeoutPromise(ms: number): Promise<"timeout"> {
        return new Promise<"timeout">((resolve) => {
            setTimeout(() => {
                resolve("timeout");
            }, ms);
        });
    }

    let counter = 0;
    const symbols = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    process.stdout.write((prefix ? prefix + " " : "") + symbols[0]);
    while (await Promise.race([promise, timeoutPromise(200)]) === "timeout") {
        process.stdout.clearLine(0);
        process.stdout.cursorTo(0);
        process.stdout.write((prefix ? prefix + " " : "") + symbols[counter % symbols.length] + " ");
        counter++;
    }
    
    process.stdout.clearLine(0);
    process.stdout.cursorTo(0);
}

async function main(): Promise<void> {
    let paranoidMode = false;
    let scanDir = "";
    
    // Load compromised packages from external file
    await loadCompromisedPackages();
    
    // Parse arguments
    const args = Deno.args;
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        switch (arg) {
            case '--paranoid':
                paranoidMode = true;
                break;
            case '--help':
            case '-h':
                usage();
                break;
            default:
                if (arg.startsWith('-')) {
                    console.log(`Unknown option: ${arg}`);
                    usage();
                } else if (scanDir === "") {
                    scanDir = arg;
                } else {
                    console.log("Too many arguments");
                    usage();
                }
        }
    }
    
    if (scanDir === "") {
        usage();
    }
    
    try {
        const stat = await Deno.stat(scanDir);
        if (!stat.isDirectory) {
            printStatus(COLORS.RED, `Error: '${scanDir}' is not a directory.`);
            Deno.exit(1);
        }
    } catch {
        printStatus(COLORS.RED, `Error: Directory '${scanDir}' does not exist.`);
        Deno.exit(1);
    }
    
    // Convert to absolute path
    scanDir = await Deno.realPath(scanDir);
    
    printStatus(COLORS.GREEN, "Starting Shai-Hulud detection scan...");
    if (paranoidMode) {
        printStatus(COLORS.BLUE, `Scanning directory: ${scanDir} (with paranoid mode enabled)`);
    } else {
        printStatus(COLORS.BLUE, `Scanning directory: ${scanDir}`);
    }
    console.log();

    // Run core Shai-Hulud detection checks (async for performance)
    const parallelCheck: Promise<void[]> = Promise.all([
        checkWorkflowFiles(scanDir),
        checkPostinstallHooks(scanDir),
        checkContent(scanDir),
        checkCryptoTheftPatterns(scanDir),
        checkTrufflehogActivity(scanDir),
        checkGitBranches(scanDir),
        checkShaiHuludRepos(scanDir),
        checkPackageIntegrity(scanDir)
    ]);
    await showProcessingIndicatorForPromise(parallelCheck, "🔍");
    // These need to run sequentially due to progress indicators
    await checkPackages(scanDir);
    await checkFileHashes(scanDir);
    
    // Run additional security checks only in paranoid mode
    if (paranoidMode) {
        printStatus(COLORS.BLUE, "🔍+ Checking for typosquatting and homoglyph attacks...");
        await checkTyposquatting(scanDir);
        printStatus(COLORS.BLUE, "🔍+ Checking for network exfiltration patterns...");
        await checkNetworkExfiltration(scanDir);
    }
    
    // Generate report
    generateReport(paranoidMode);
}

// Run main function
if (import.meta.main) {
    await main();
}
use crate::config::Config;
use crate::findings::{Finding, FindingCategory, RiskLevel, ScanFindings};
use anyhow::Result;
use colored::*;
use regex::Regex;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

pub struct Scanner {
    config: Config,
}

impl Scanner {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn scan_directory(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!("{}", "🔍 Checking for malicious workflow files...".blue());
        self.check_workflow_files(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking file hashes for known malicious content...".blue()
        );
        self.check_file_hashes(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking package.json files for compromised packages...".blue()
        );
        self.check_packages(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking for suspicious postinstall hooks...".blue()
        );
        self.check_postinstall_hooks(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking for suspicious content patterns...".blue()
        );
        self.check_content(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking for cryptocurrency theft patterns...".blue()
        );
        self.check_crypto_theft_patterns(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking for Trufflehog activity and secret scanning...".blue()
        );
        self.check_trufflehog_activity(directory, findings)?;

        println!("{}", "🔍 Checking for suspicious git branches...".blue());
        self.check_git_branches(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking for Shai-Hulud repositories and migration patterns...".blue()
        );
        self.check_shai_hulud_repos(directory, findings)?;

        println!(
            "{}",
            "🔍 Checking package lock files for integrity issues...".blue()
        );
        self.check_package_integrity(directory, findings)?;

        Ok(())
    }

    pub fn check_workflow_files(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        println!("{}", "🔍 Checking for malicious workflow files...".blue());

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("shai-hulud-workflow.yml") {
                findings.add_finding(Finding::new(
                    path.to_path_buf(),
                    RiskLevel::High,
                    FindingCategory::MaliciousWorkflow,
                    "Known malicious workflow filename detected".to_string(),
                ));
            }
        }

        Ok(())
    }

    pub fn check_file_hashes(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!(
            "{}",
            "🔍 Checking file hashes for known malicious content...".blue()
        );

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if matches!(ext, "js" | "ts" | "json") {
                        if let Ok(content) = fs::read(path) {
                            let mut hasher = Sha256::new();
                            hasher.update(&content);
                            let hash = hex::encode(hasher.finalize());

                            if hash == self.config.malicious_hash {
                                findings.add_finding(Finding::new(
                                    path.to_path_buf(),
                                    RiskLevel::High,
                                    FindingCategory::MaliciousHash,
                                    format!("File matches known malicious SHA-256 hash: {}", hash),
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_packages(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!(
            "{}",
            "🔍 Checking package.json files for compromised packages...".blue()
        );

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("package.json") {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(package_json) = serde_json::from_str::<Value>(&content) {
                        self.check_package_dependencies(path, &package_json, findings)?;
                        self.check_namespace_warnings(path, &package_json, findings)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn check_package_dependencies(
        &self,
        path: &Path,
        package_json: &Value,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let dependency_sections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        for section in &dependency_sections {
            if let Some(deps) = package_json.get(section).and_then(|d| d.as_object()) {
                for (package_name, version_value) in deps {
                    if let Some(version_str) = version_value.as_str() {
                        // Clean version string (remove ^ ~ etc.)
                        let clean_version =
                            version_str.trim_start_matches(['^', '~', '=', '>', '<', ' ']);

                        // Check against compromised packages
                        for compromised in &self.config.compromised_packages {
                            if package_name == &compromised.name
                                && clean_version == compromised.version
                            {
                                findings.add_finding(Finding::new(
                                    path.to_path_buf(),
                                    RiskLevel::High,
                                    FindingCategory::CompromisedPackage,
                                    format!(
                                        "Compromised package detected: {}@{}",
                                        package_name, clean_version
                                    ),
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_namespace_warnings(
        &self,
        path: &Path,
        package_json: &Value,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let dependency_sections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        for section in &dependency_sections {
            if let Some(deps) = package_json.get(section).and_then(|d| d.as_object()) {
                for package_name in deps.keys() {
                    for namespace in &self.config.compromised_namespaces {
                        if package_name.starts_with(&format!("{}/", namespace)) {
                            findings.add_finding(Finding::new(
                                path.to_path_buf(),
                                RiskLevel::Medium,
                                FindingCategory::CompromisedNamespace,
                                format!(
                                    "Package from compromised namespace: {} ({})",
                                    package_name, namespace
                                ),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_postinstall_hooks(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        println!(
            "{}",
            "🔍 Checking for suspicious postinstall hooks...".blue()
        );

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("package.json") {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(package_json) = serde_json::from_str::<Value>(&content) {
                        if let Some(scripts) =
                            package_json.get("scripts").and_then(|s| s.as_object())
                        {
                            if let Some(postinstall) =
                                scripts.get("postinstall").and_then(|p| p.as_str())
                            {
                                // Check for suspicious patterns
                                let suspicious_patterns = ["curl", "wget", "node -e", "eval"];
                                for pattern in &suspicious_patterns {
                                    if postinstall.contains(pattern) {
                                        findings.add_finding(Finding::new(
                                            path.to_path_buf(),
                                            RiskLevel::High,
                                            FindingCategory::PostinstallHook,
                                            format!("Suspicious postinstall hook: {}", postinstall),
                                        ));
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_content(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!(
            "{}",
            "🔍 Checking for suspicious content patterns...".blue()
        );

        let file_extensions = ["js", "ts", "json", "yml", "yaml"];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if file_extensions.contains(&ext) {
                        if let Ok(content) = fs::read_to_string(path) {
                            // Check for webhook.site references
                            if content.contains("webhook.site") {
                                findings.add_finding(Finding::new(
                                    path.to_path_buf(),
                                    RiskLevel::Medium,
                                    FindingCategory::SuspiciousContent,
                                    "webhook.site reference detected".to_string(),
                                ));
                            }

                            // Check for specific malicious webhook endpoint
                            if content.contains("bb8ca5f6-4175-45d2-b042-fc9ebb8170b7") {
                                findings.add_finding(Finding::new(
                                    path.to_path_buf(),
                                    RiskLevel::High,
                                    FindingCategory::SuspiciousContent,
                                    "Known malicious webhook endpoint detected".to_string(),
                                ));
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_crypto_theft_patterns(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let file_extensions = ["js", "ts", "json"];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            if let Some(extension) = path.extension().and_then(|e| e.to_str()) {
                if file_extensions.contains(&extension) {
                    if let Ok(content) = fs::read_to_string(path) {
                        self.analyze_crypto_patterns(path, &content, findings)?;
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_crypto_patterns(
        &self,
        path: &Path,
        content: &str,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        // Check for wallet address replacement patterns
        let eth_wallet_regex = Regex::new(r"0x[a-fA-F0-9]{40}")?;
        if eth_wallet_regex.is_match(content)
            && (content.contains("ethereum")
                || content.contains("wallet")
                || content.contains("address")
                || content.contains("crypto"))
        {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::Medium,
                FindingCategory::CryptoTheft,
                "Ethereum wallet address patterns detected".to_string(),
            ));
        }

        // Check for XMLHttpRequest hijacking
        if content.contains("XMLHttpRequest.prototype.send") {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::High,
                FindingCategory::CryptoTheft,
                "XMLHttpRequest prototype modification detected".to_string(),
            ));
        }

        // Check for specific malicious functions from chalk/debug attack
        let malicious_functions = ["checkethereumw", "runmask", "newdlocal", "_0x19ca67"];
        for func in &malicious_functions {
            if content.contains(func) {
                findings.add_finding(Finding::new(
                    path.to_path_buf(),
                    RiskLevel::High,
                    FindingCategory::CryptoTheft,
                    "Known crypto theft function names detected".to_string(),
                ));
                break;
            }
        }

        // Check for known attacker wallets
        let attacker_wallets = [
            "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976",
            "1H13VnQJKtT4HjD5ZFKaaiZEetMbG7nDHx",
            "TB9emsCq6fQw6wRk4HBxxNnU6Hwt1DnV67",
        ];
        for wallet in &attacker_wallets {
            if content.contains(wallet) {
                findings.add_finding(Finding::new(
                    path.to_path_buf(),
                    RiskLevel::High,
                    FindingCategory::CryptoTheft,
                    "Known attacker wallet address detected - HIGH RISK".to_string(),
                ));
            }
        }

        // Check for npmjs.help phishing domain
        if content.contains("npmjs.help") {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::High,
                FindingCategory::CryptoTheft,
                "Phishing domain npmjs.help detected".to_string(),
            ));
        }

        // Check for javascript obfuscation patterns
        if content.contains("javascript-obfuscator") {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::Medium,
                FindingCategory::CryptoTheft,
                "JavaScript obfuscation detected".to_string(),
            ));
        }

        // Check for cryptocurrency address regex patterns
        let crypto_regex_patterns = [
            r"ethereum.*0x\[a-fA-F0-9\]",
            r"bitcoin.*\[13\]\[a-km-zA-HJ-NP-Z1-9\]",
        ];
        for pattern in &crypto_regex_patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if regex.is_match(content) {
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Medium,
                        FindingCategory::CryptoTheft,
                        "Cryptocurrency regex patterns detected".to_string(),
                    ));
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn check_git_branches(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!("{}", "🔍 Checking for suspicious git branches...".blue());

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") && path.is_dir() {
                let refs_heads = path.join("refs").join("heads");
                if refs_heads.exists() {
                    for branch_entry in WalkDir::new(&refs_heads).into_iter().filter_map(|e| e.ok())
                    {
                        let branch_path = branch_entry.path();
                        if branch_path.is_file() {
                            if let Some(branch_name) =
                                branch_path.file_name().and_then(|n| n.to_str())
                            {
                                if branch_name.contains("shai-hulud") {
                                    if let Ok(commit_hash) = fs::read_to_string(branch_path) {
                                        let repo_path = path.parent().unwrap_or(path);
                                        findings.add_finding(Finding::new(
                                            repo_path.to_path_buf(),
                                            RiskLevel::Medium,
                                            FindingCategory::SuspiciousGitBranch,
                                            format!(
                                                "Suspicious branch '{}' (commit: {})",
                                                branch_name,
                                                &commit_hash.trim()[..8.min(commit_hash.len())]
                                            ),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_trufflehog_activity(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        println!(
            "{}",
            "🔍 Checking for Trufflehog activity and secret scanning...".blue()
        );

        let file_extensions = ["js", "py", "sh", "json"];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Check for trufflehog binary files
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if filename.contains("trufflehog") {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::High,
                            FindingCategory::TrufflehogActivity,
                            "Trufflehog binary found".to_string(),
                        ));
                    }
                }
            }

            // Check file contents
            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if file_extensions.contains(&ext) {
                        if let Ok(content) = fs::read_to_string(path) {
                            self.analyze_trufflehog_content(path, &content, findings)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_trufflehog_content(
        &self,
        path: &Path,
        content: &str,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let context = self.get_file_context(path);
        let content_sample = content.lines().take(20).collect::<Vec<_>>().join(" ");

        // Check for explicit trufflehog references
        if content.to_lowercase().contains("trufflehog") {
            match context.as_str() {
                "documentation" => {
                    // Documentation mentioning trufflehog is usually legitimate
                    return Ok(());
                }
                "node_modules" | "type_definitions" | "build_output" => {
                    // Framework code mentioning trufflehog is suspicious but not high risk
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Medium,
                        FindingCategory::TrufflehogActivity,
                        format!("Contains trufflehog references in {}", context),
                    ));
                }
                _ => {
                    // Source code with trufflehog references needs investigation
                    if content_sample.contains("subprocess") && content_sample.contains("curl") {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::High,
                            FindingCategory::TrufflehogActivity,
                            "Suspicious trufflehog execution pattern".to_string(),
                        ));
                    } else {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::Medium,
                            FindingCategory::TrufflehogActivity,
                            "Contains trufflehog references in source code".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for credential scanning combined with exfiltration
        let credential_patterns = ["AWS_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN"];
        let mut found_credentials = false;
        let mut has_exfiltration = false;

        for pattern in &credential_patterns {
            if content.contains(pattern) {
                found_credentials = true;
                if content_sample.contains("webhook.site")
                    || content_sample.contains("curl")
                    || content_sample.contains("https.request")
                {
                    has_exfiltration = true;
                }
            }
        }

        if found_credentials {
            match context.as_str() {
                "type_definitions" | "documentation" => {
                    // Type definitions and docs mentioning credentials are normal
                    return Ok(());
                }
                "node_modules" => {
                    // Package manager code mentioning credentials might be legitimate
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Low,
                        FindingCategory::TrufflehogActivity,
                        "Credential patterns in node_modules".to_string(),
                    ));
                }
                "configuration" => {
                    // Config files mentioning credentials might be legitimate
                    if content_sample.contains("DefinePlugin") || content_sample.contains("webpack")
                    {
                        return Ok(()); // webpack config is legitimate
                    }
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Medium,
                        FindingCategory::TrufflehogActivity,
                        "Credential patterns in configuration".to_string(),
                    ));
                }
                _ => {
                    // Source code mentioning credentials + exfiltration is suspicious
                    if has_exfiltration {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::High,
                            FindingCategory::TrufflehogActivity,
                            "Credential patterns with potential exfiltration".to_string(),
                        ));
                    } else {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::Medium,
                            FindingCategory::TrufflehogActivity,
                            "Contains credential scanning patterns".to_string(),
                        ));
                    }
                }
            }
        }

        // Check for environment variable scanning (refined logic)
        if content.contains("process.env")
            || content.contains("os.environ")
            || content.contains("getenv")
        {
            match context.as_str() {
                "type_definitions" | "documentation" => {
                    // Type definitions and docs are normal
                    return Ok(());
                }
                "node_modules" | "build_output" => {
                    // Framework code using process.env is normal
                    if self.is_legitimate_pattern(path, &content_sample) {
                        return Ok(());
                    }
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Low,
                        FindingCategory::TrufflehogActivity,
                        format!("Environment variable access in {}", context),
                    ));
                }
                "configuration" => {
                    // Config files using env vars is normal
                    return Ok(());
                }
                _ => {
                    // Only flag if combined with suspicious patterns
                    if content_sample.contains("webhook.site")
                        && content_sample.contains("exfiltrat")
                    {
                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::High,
                            FindingCategory::TrufflehogActivity,
                            "Environment scanning with exfiltration".to_string(),
                        ));
                    } else if content_sample.contains("scan")
                        || content_sample.contains("harvest")
                        || content_sample.contains("steal")
                    {
                        if !self.is_legitimate_pattern(path, &content_sample) {
                            findings.add_finding(Finding::new(
                                path.to_path_buf(),
                                RiskLevel::Medium,
                                FindingCategory::TrufflehogActivity,
                                "Potentially suspicious environment variable access".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn is_legitimate_pattern(&self, _path: &Path, content_sample: &str) -> bool {
        // Vue.js development patterns
        if content_sample.contains("process.env.NODE_ENV") && content_sample.contains("production")
        {
            return true; // legitimate
        }

        // Common framework patterns
        if content_sample.contains("createApp") || content_sample.contains("Vue") {
            return true; // legitimate
        }

        // Package manager and build tool patterns
        if content_sample.contains("webpack")
            || content_sample.contains("vite")
            || content_sample.contains("rollup")
        {
            return true; // legitimate
        }

        false // potentially suspicious
    }

    fn get_file_context(&self, path: &Path) -> String {
        let path_str = path.to_string_lossy();

        if path_str.contains("/node_modules/") {
            "node_modules".to_string()
        } else if path.extension().and_then(|e| e.to_str()) == Some("md")
            || path.extension().and_then(|e| e.to_str()) == Some("txt")
            || path.extension().and_then(|e| e.to_str()) == Some("rst")
        {
            "documentation".to_string()
        } else if path.extension().and_then(|e| e.to_str()) == Some("d.ts") {
            "type_definitions".to_string()
        } else if path_str.contains("/dist/")
            || path_str.contains("/build/")
            || path_str.contains("/public/")
        {
            "build_output".to_string()
        } else if path
            .file_name()
            .and_then(|n| n.to_str())
            .map_or(false, |n| n.contains("config"))
        {
            "configuration".to_string()
        } else {
            "source_code".to_string()
        }
    }

    pub fn check_shai_hulud_repos(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some(".git") && path.is_dir() {
                let repo_dir = path.parent().unwrap_or(path);
                let repo_name = repo_dir.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // Check repository name
                if repo_name.to_lowercase().contains("shai-hulud") {
                    findings.add_finding(Finding::new(
                        repo_dir.to_path_buf(),
                        RiskLevel::High,
                        FindingCategory::ShaiHuludRepo,
                        "Repository name contains 'Shai-Hulud'".to_string(),
                    ));
                }

                // Check for migration pattern
                if repo_name.contains("-migration") {
                    findings.add_finding(Finding::new(
                        repo_dir.to_path_buf(),
                        RiskLevel::High,
                        FindingCategory::ShaiHuludRepo,
                        "Repository name contains migration pattern".to_string(),
                    ));
                }

                // Check git config for shai-hulud references
                let git_config = path.join("config");
                if git_config.exists() {
                    if let Ok(config_content) = fs::read_to_string(&git_config) {
                        if config_content.to_lowercase().contains("shai-hulud") {
                            findings.add_finding(Finding::new(
                                repo_dir.to_path_buf(),
                                RiskLevel::High,
                                FindingCategory::ShaiHuludRepo,
                                "Git remote contains 'Shai-Hulud'".to_string(),
                            ));
                        }
                    }
                }

                // Check for suspicious data.json
                let data_json = repo_dir.join("data.json");
                if data_json.exists() {
                    if let Ok(content) = fs::read_to_string(&data_json) {
                        if content.contains("eyJ") && content.contains("==") {
                            findings.add_finding(Finding::new(
                                repo_dir.to_path_buf(),
                                RiskLevel::High,
                                FindingCategory::ShaiHuludRepo,
                                "Contains suspicious data.json (possible base64-encoded credentials)".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_package_integrity(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let lock_files = ["package-lock.json", "yarn.lock"];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.is_file() {
                if let Some(filename) = path.file_name().and_then(|n| n.to_str()) {
                    if lock_files.contains(&filename) {
                        if let Ok(content) = fs::read_to_string(path) {
                            self.check_lockfile_integrity(path, &content, findings)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_lockfile_integrity(
        &self,
        path: &Path,
        content: &str,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        // Check for compromised packages in lockfiles
        for compromised in &self.config.compromised_packages {
            if content.contains(&compromised.name) {
                // Simple version check - in a real implementation, you'd parse JSON properly
                if content.contains(&compromised.version) {
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Medium,
                        FindingCategory::PackageIntegrity,
                        format!(
                            "Compromised package in lockfile: {}@{}",
                            compromised.name, compromised.version
                        ),
                    ));
                }
            }
        }

        // Check for @ctrl packages with recent modification
        if content.contains("@ctrl") {
            if let Ok(metadata) = fs::metadata(path) {
                if let Ok(modified) = metadata.modified() {
                    let now = std::time::SystemTime::now();
                    if let Ok(duration) = now.duration_since(modified) {
                        // Flag if modified in the last 30 days
                        if duration.as_secs() < 30 * 24 * 60 * 60 {
                            findings.add_finding(Finding::new(
                                path.to_path_buf(),
                                RiskLevel::Medium,
                                FindingCategory::PackageIntegrity,
                                "Recently modified lockfile contains @ctrl packages (potential worm activity)".to_string(),
                            ));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_typosquatting(&self, directory: &Path, findings: &mut ScanFindings) -> Result<()> {
        println!(
            "{}",
            "🔍+ Checking for typosquatting and homoglyph attacks...".blue()
        );

        let popular_packages = [
            "react",
            "vue",
            "angular",
            "express",
            "lodash",
            "axios",
            "typescript",
            "webpack",
            "babel",
            "eslint",
            "jest",
            "mocha",
            "chalk",
            "debug",
            "commander",
            "inquirer",
            "yargs",
            "request",
            "moment",
            "underscore",
            "jquery",
            "bootstrap",
            "socket.io",
            "redis",
            "mongoose",
            "passport",
        ];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()) == Some("package.json") {
                if let Ok(content) = fs::read_to_string(path) {
                    if let Ok(package_json) = serde_json::from_str::<Value>(&content) {
                        self.check_package_typosquatting(
                            path,
                            &package_json,
                            &popular_packages,
                            findings,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    fn check_package_typosquatting(
        &self,
        path: &Path,
        package_json: &Value,
        popular_packages: &[&str],
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let dependency_sections = [
            "dependencies",
            "devDependencies",
            "peerDependencies",
            "optionalDependencies",
        ];

        for section in &dependency_sections {
            if let Some(deps) = package_json.get(section).and_then(|d| d.as_object()) {
                for package_name in deps.keys() {
                    // Skip if not a package name (too short, no alpha chars, etc)
                    if package_name.len() < 2 {
                        continue;
                    }
                    if !package_name.chars().any(|c| c.is_ascii_alphabetic()) {
                        continue;
                    }

                    // Note: Unicode/homoglyph detection is commented out to match shell script behavior
                    // The shell script doesn't detect Unicode characters reliably
                    // if !package_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '@' || c == '/' || c == '.' || c == '_' || c == '-') {
                    //     findings.add_finding(Finding::new(
                    //         path.to_path_buf(),
                    //         RiskLevel::Medium,
                    //         FindingCategory::Typosquatting,
                    //         format!("Potential Unicode/homoglyph characters in package: {}", package_name),
                    //     ));
                    // }

                    // Check similarity to popular packages using simple character distance
                    for popular in popular_packages {
                        // Skip exact matches
                        if package_name == popular {
                            continue;
                        }

                        // Skip common legitimate variations
                        if matches!(
                            package_name.as_str(),
                            "test"
                                | "tests"
                                | "testing"
                                | "types"
                                | "util"
                                | "utils"
                                | "core"
                                | "lib"
                                | "libs"
                                | "common"
                                | "shared"
                        ) {
                            continue;
                        }

                        // Check for single character differences (common typos) - but only for longer package names
                        if package_name.len() == popular.len() && package_name.len() > 4 {
                            let diff_count = package_name
                                .chars()
                                .zip(popular.chars())
                                .filter(|(a, b)| a != b)
                                .count();

                            if diff_count == 1 {
                                // Additional check - avoid common legitimate variations
                                if !package_name.contains('-') && !popular.contains('-') {
                                    findings.add_finding(Finding::new(
                                        path.to_path_buf(),
                                        RiskLevel::Medium,
                                        FindingCategory::Typosquatting,
                                        format!("Potential typosquatting of '{}': {} (1 character difference)", popular, package_name),
                                    ));
                                }
                            }
                        }

                        // Check for missing character (using char-safe operations)
                        let package_chars: Vec<char> = package_name.chars().collect();
                        let popular_chars: Vec<char> = popular.chars().collect();

                        if package_chars.len() == popular_chars.len() - 1 {
                            for i in 0..popular_chars.len() {
                                let mut test_chars = popular_chars.clone();
                                test_chars.remove(i);
                                let test_name: String = test_chars.into_iter().collect();

                                if package_name == &test_name {
                                    findings.add_finding(Finding::new(
                                        path.to_path_buf(),
                                        RiskLevel::Medium,
                                        FindingCategory::Typosquatting,
                                        format!("Potential typosquatting of '{}': {} (missing character)", popular, package_name),
                                    ));
                                    break;
                                }
                            }
                        }

                        // Check for extra character (using char-safe operations)
                        if package_chars.len() == popular_chars.len() + 1 {
                            for i in 0..package_chars.len() {
                                let mut test_chars = package_chars.clone();
                                test_chars.remove(i);
                                let test_name: String = test_chars.into_iter().collect();

                                if test_name == *popular {
                                    findings.add_finding(Finding::new(
                                        path.to_path_buf(),
                                        RiskLevel::Medium,
                                        FindingCategory::Typosquatting,
                                        format!(
                                            "Potential typosquatting of '{}': {} (extra character)",
                                            popular, package_name
                                        ),
                                    ));
                                    break;
                                }
                            }
                        }
                    }

                    // Check for namespace confusion (e.g., @typescript_eslinter vs @typescript-eslint)
                    if package_name.starts_with('@') {
                        if let Some(slash_pos) = package_name.find('/') {
                            let namespace = &package_name[..slash_pos];

                            // Common namespace typos
                            let suspicious_namespaces = [
                                "@types",
                                "@angular",
                                "@typescript",
                                "@react",
                                "@vue",
                                "@babel",
                            ];

                            for suspicious in &suspicious_namespaces {
                                if namespace != *suspicious {
                                    // Check if it's a close match but not exact
                                    let ns_chars: Vec<char> = namespace.chars().collect();
                                    let sus_chars: Vec<char> = suspicious.chars().collect();

                                    if ns_chars.len() > 1 && sus_chars.len() > 1 {
                                        let ns_clean = &ns_chars[1..]; // Remove @
                                        let sus_clean = &sus_chars[1..]; // Remove @

                                        if ns_clean.len() == sus_clean.len() {
                                            let ns_diff = ns_clean
                                                .iter()
                                                .zip(sus_clean.iter())
                                                .filter(|(a, b)| a != b)
                                                .count();

                                            if ns_diff >= 1 && ns_diff <= 2 {
                                                findings.add_finding(Finding::new(
                                                    path.to_path_buf(),
                                                    RiskLevel::Medium,
                                                    FindingCategory::Typosquatting,
                                                    format!("Suspicious namespace variation: {} (similar to {})", namespace, suspicious),
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn check_network_exfiltration(
        &self,
        directory: &Path,
        findings: &mut ScanFindings,
    ) -> Result<()> {
        println!(
            "{}",
            "🔍+ Checking for network exfiltration patterns...".blue()
        );

        let suspicious_domains = [
            "pastebin.com",
            "hastebin.com",
            "ix.io",
            "0x0.st",
            "transfer.sh",
            "file.io",
            "anonfiles.com",
            "mega.nz",
            "dropbox.com/s/",
            "discord.com/api/webhooks",
            "telegram.org",
            "t.me",
            "ngrok.io",
            "localtunnel.me",
            "serveo.net",
            "requestbin.com",
            "webhook.site",
            "beeceptor.com",
            "pipedream.com",
            "zapier.com/hooks",
        ];

        let file_extensions = ["js", "ts", "json", "mjs"];

        for entry in WalkDir::new(directory).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();

            // Skip vendor and node_modules to reduce false positives
            if path.to_string_lossy().contains("/vendor/")
                || path.to_string_lossy().contains("/node_modules/")
            {
                continue;
            }

            if path.is_file() {
                if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                    if file_extensions.contains(&ext) {
                        if let Ok(content) = fs::read_to_string(path) {
                            self.check_network_patterns(
                                path,
                                &content,
                                &suspicious_domains,
                                findings,
                            )?;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn check_network_patterns(
        &self,
        path: &Path,
        content: &str,
        suspicious_domains: &[&str],
        findings: &mut ScanFindings,
    ) -> Result<()> {
        let path_str = path.to_string_lossy();

        // Check for hardcoded IP addresses (simplified)
        // Skip vendor/library files to reduce false positives
        if !path_str.contains("/vendor/") && !path_str.contains("/node_modules/") {
            let ip_regex = Regex::new(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")?;
            let mut ips_found = Vec::new();

            for ip_match in ip_regex.find_iter(content) {
                let ip = ip_match.as_str();
                ips_found.push(ip);
                if ips_found.len() >= 3 {
                    break;
                }
            }

            if !ips_found.is_empty() {
                let ips_context = ips_found.join(" ");
                // Skip common safe IPs
                if !ips_context.contains("127.0.0.1") && !ips_context.contains("0.0.0.0") {
                    let message = if path_str.contains(".min.js") {
                        format!(
                            "Hardcoded IP addresses found (minified file): {}",
                            ips_context
                        )
                    } else {
                        format!("Hardcoded IP addresses found: {}", ips_context)
                    };
                    findings.add_finding(Finding::new(
                        path.to_path_buf(),
                        RiskLevel::Medium,
                        FindingCategory::NetworkExfiltration,
                        message,
                    ));
                }
            }
        }

        // Check for suspicious domains (but avoid package-lock.json and vendor files to reduce noise)
        if !path_str.contains("package-lock.json")
            && !path_str.contains("yarn.lock")
            && !path_str.contains("/vendor/")
            && !path_str.contains("/node_modules/")
        {
            for domain in suspicious_domains {
                // Use word boundaries and URL patterns to avoid false positives like "timeZone" containing "t.me"
                let https_pattern = format!(r"https?://[^\s]*{}", regex::escape(domain));
                let space_pattern = format!(r"[\s]{}[\s/\x22\x27]", regex::escape(domain));

                let https_regex = Regex::new(&https_pattern)?;
                let space_regex = Regex::new(&space_pattern)?;

                if https_regex.is_match(content) || space_regex.is_match(content) {
                    // Additional check - make sure it's not just a comment or documentation
                    let lines: Vec<&str> = content.lines().collect();
                    for (line_num, line) in lines.iter().enumerate() {
                        let line_matches = (https_regex.is_match(line)
                            || space_regex.is_match(line))
                            && !line.trim_start().starts_with('#')
                            && !line.trim_start().starts_with("//");

                        if line_matches {
                            // Get line number and context
                            let line_number = line_num + 1;

                            // Check if it's a minified file or has very long lines
                            let snippet = if path_str.contains(".min.js") || line.len() > 150 {
                                // Extract just around the domain
                                let domain_pos = line.find(domain).unwrap_or(0);
                                let start = domain_pos.saturating_sub(20);
                                let end = (domain_pos + domain.len() + 20).min(line.len());
                                format!("...{}...", &line[start..end])
                            } else {
                                let end = 80.min(line.len());
                                format!("{}...", &line[..end])
                            };

                            findings.add_finding(Finding::new(
                                path.to_path_buf(),
                                RiskLevel::Medium,
                                FindingCategory::NetworkExfiltration,
                                format!(
                                    "Suspicious domain found: {} at line {}: {}",
                                    domain, line_number, snippet
                                ),
                            ));
                            break;
                        }
                    }
                }
            }
        }

        // Check for base64-encoded URLs (skip vendor files to reduce false positives)
        if !path_str.contains("/vendor/") && !path_str.contains("/node_modules/") {
            if content.contains("atob(")
                || (content.contains("base64") && content.contains("decode"))
            {
                // Get line number and a small snippet
                let lines: Vec<&str> = content.lines().collect();
                for (line_num, line) in lines.iter().enumerate() {
                    if line.contains("atob") || (line.contains("base64") && line.contains("decode"))
                    {
                        let line_number = line_num + 1;

                        let snippet = if path_str.contains(".min.js")
                            || lines
                                .get(0)
                                .map_or(false, |first_line| first_line.len() > 500)
                        {
                            // Extract a small window around the atob call
                            if let Some(atob_pos) = line.find("atob") {
                                let start = atob_pos.saturating_sub(30);
                                let end = (atob_pos + 34).min(line.len());
                                format!("...{}...", &line[start..end])
                            } else if let Some(base64_pos) = line.find("base64") {
                                let start = base64_pos.saturating_sub(30);
                                let end = (base64_pos + 40).min(line.len());
                                format!("...{}...", &line[start..end])
                            } else {
                                "...".to_string()
                            }
                        } else {
                            let end = 80.min(line.len());
                            format!("{}...", &line[..end])
                        };

                        findings.add_finding(Finding::new(
                            path.to_path_buf(),
                            RiskLevel::Medium,
                            FindingCategory::NetworkExfiltration,
                            format!("Base64 decoding at line {}: {}", line_number, snippet),
                        ));
                        break;
                    }
                }
            }
        }

        // Check for DNS-over-HTTPS patterns
        if content.contains("dns-query") || content.contains("application/dns-message") {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::Medium,
                FindingCategory::NetworkExfiltration,
                "DNS-over-HTTPS pattern detected".to_string(),
            ));
        }

        // Check for WebSocket connections to unusual endpoints
        let ws_regex = Regex::new(r"wss?://[^\x22\x27\s]*")?;
        for ws_match in ws_regex.find_iter(content) {
            let endpoint = ws_match.as_str();
            // Flag WebSocket connections that don't seem to be localhost or common development
            if !endpoint.contains("localhost") && !endpoint.contains("127.0.0.1") {
                findings.add_finding(Finding::new(
                    path.to_path_buf(),
                    RiskLevel::Medium,
                    FindingCategory::NetworkExfiltration,
                    format!("WebSocket connection to external endpoint: {}", endpoint),
                ));
            }
        }

        // Check for suspicious HTTP headers
        if content.contains("X-Exfiltrate")
            || content.contains("X-Data-Export")
            || content.contains("X-Credential")
        {
            findings.add_finding(Finding::new(
                path.to_path_buf(),
                RiskLevel::Medium,
                FindingCategory::NetworkExfiltration,
                "Suspicious HTTP headers detected".to_string(),
            ));
        }

        // Check for data encoding that might hide exfiltration (but be more selective)
        if !path_str.contains("/vendor/")
            && !path_str.contains("/node_modules/")
            && !path_str.contains(".min.js")
        {
            if content.contains("btoa(") {
                // Check if it's near network operations (simplified to avoid hanging)
                let lines: Vec<&str> = content.lines().collect();
                for (line_num, line) in lines.iter().enumerate() {
                    if line.contains("btoa(") {
                        // Check surrounding lines for network operations
                        let start_idx = line_num.saturating_sub(3);
                        let end_idx = (line_num + 4).min(lines.len());
                        let context_lines = &lines[start_idx..end_idx];
                        let context = context_lines.join(" ");

                        if context.contains("fetch")
                            || context.contains("XMLHttpRequest")
                            || context.contains("axios")
                        {
                            // Additional check - make sure it's not just legitimate authentication
                            if !context.contains("Authorization:")
                                && !context.contains("Basic ")
                                && !context.contains("Bearer ")
                            {
                                let line_number = line_num + 1;
                                let end = 80.min(line.len());
                                let snippet = format!("{}...", &line[..end]);
                                findings.add_finding(Finding::new(
                                    path.to_path_buf(),
                                    RiskLevel::Medium,
                                    FindingCategory::NetworkExfiltration,
                                    format!("Suspicious base64 encoding near network operation at line {}: {}", line_number, snippet),
                                ));
                            }
                        }
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

use crate::config::Config;
use crate::findings::ScanFindings;
use crate::report::ReportGenerator;
use crate::scanner::Scanner;
use anyhow::Result;
use std::path::Path;

pub struct ShaiHuludDetector {
    config: Config,
    scanner: Scanner,
    report_generator: ReportGenerator,
}

impl ShaiHuludDetector {
    pub fn new(config: Config) -> Self {
        let scanner = Scanner::new(config.clone());
        let report_generator = ReportGenerator::new(config.clone());
        
        Self {
            config,
            scanner,
            report_generator,
        }
    }

    pub fn scan(&mut self, directory: &Path) -> Result<ScanFindings> {
        let mut findings = ScanFindings::new();

        // Run core Shai-Hulud detection checks
        self.scanner.check_workflow_files(directory, &mut findings)?;
        self.scanner.check_file_hashes(directory, &mut findings)?;
        self.scanner.check_packages(directory, &mut findings)?;
        self.scanner.check_postinstall_hooks(directory, &mut findings)?;
        self.scanner.check_content(directory, &mut findings)?;
        self.scanner.check_trufflehog_activity(directory, &mut findings)?;
        self.scanner.check_git_branches(directory, &mut findings)?;
        self.scanner.check_shai_hulud_repos(directory, &mut findings)?;
        self.scanner.check_package_integrity(directory, &mut findings)?;

        // Run additional security checks only in paranoid mode
        if self.config.paranoid_mode {
            self.scanner.check_typosquatting(directory, &mut findings)?;
            self.scanner.check_network_exfiltration(directory, &mut findings)?;
        }

        Ok(findings)
    }

    pub fn generate_report(&self, findings: &ScanFindings) {
        self.report_generator.generate_report(findings);
    }
}

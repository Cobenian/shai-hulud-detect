use crate::config::Config;
use crate::findings::{Finding, FindingCategory, RiskLevel, ScanFindings};
use colored::*;

pub struct ReportGenerator {
    config: Config,
}

impl ReportGenerator {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn generate_report(&self, findings: &ScanFindings) {
        println!();
        self.print_header();
        println!();

        let high_risk_findings = findings.findings_by_risk(RiskLevel::High);
        let medium_risk_findings = findings.findings_by_risk(RiskLevel::Medium);
        let low_risk_findings = findings.findings_by_risk(RiskLevel::Low);

        // Report findings by category and risk level
        self.report_high_risk_findings(&high_risk_findings);
        self.report_medium_risk_findings(&medium_risk_findings);

        // Generate summary
        self.generate_summary(findings, &low_risk_findings);
    }

    fn print_header(&self) {
        println!(
            "{}",
            "==============================================".blue()
        );
        if self.config.paranoid_mode {
            println!("{}", "  SHAI-HULUD + PARANOID SECURITY REPORT".blue());
        } else {
            println!("{}", "      SHAI-HULUD DETECTION REPORT".blue());
        }
        println!(
            "{}",
            "==============================================".blue()
        );
    }

    fn report_high_risk_findings(&self, findings: &[&Finding]) {
        if findings.is_empty() {
            return;
        }

        // Group findings by category
        let mut categories = std::collections::HashMap::new();
        for finding in findings {
            categories
                .entry(&finding.category)
                .or_insert_with(Vec::new)
                .push(*finding);
        }

        for (category, category_findings) in categories {
            self.print_category_header(category, RiskLevel::High);

            for finding in category_findings {
                println!("   - {}", finding.description);
                println!("     Found in: {}", finding.file_path.display());

                if let Some(details) = &finding.details {
                    println!("     Details: {}", details);
                }

                self.show_investigation_commands(category, &finding.file_path);
                println!();
            }

            self.print_category_notes(category);
        }
    }

    fn report_medium_risk_findings(&self, findings: &[&Finding]) {
        if findings.is_empty() {
            return;
        }

        // Group findings by category
        let mut categories = std::collections::HashMap::new();
        for finding in findings {
            categories
                .entry(&finding.category)
                .or_insert_with(Vec::new)
                .push(*finding);
        }

        for (category, category_findings) in categories {
            // Limit output for paranoid mode findings to avoid spam
            let display_findings = if self.is_paranoid_category(category) {
                &category_findings[..5.min(category_findings.len())]
            } else {
                &category_findings[..]
            };

            self.print_category_header(category, RiskLevel::Medium);

            for finding in display_findings {
                println!("   - {}", finding.description);
                println!("     Found in: {}", finding.file_path.display());

                if let Some(details) = &finding.details {
                    println!("     Details: {}", details);
                }
                println!();
            }

            if self.is_paranoid_category(category) && category_findings.len() > 5 {
                println!(
                    "   - ... and {} more {} warnings (truncated for brevity)",
                    category_findings.len() - 5,
                    category.display_name().to_lowercase()
                );
                println!();
            }

            self.print_category_notes(category);
        }
    }

    fn print_category_header(&self, category: &FindingCategory, risk_level: RiskLevel) {
        let (emoji, color) = match risk_level {
            RiskLevel::High => ("🚨", "red"),
            RiskLevel::Medium => ("⚠️", "yellow"),
            RiskLevel::Low => ("ℹ️", "blue"),
        };

        let risk_text = format!("{:?}", risk_level).to_uppercase();
        let category_name = category.display_name();

        let paranoid_suffix = if self.is_paranoid_category(category) {
            " (PARANOID)"
        } else {
            ""
        };

        match color {
            "red" => println!(
                "{}",
                format!(
                    "{} {} RISK: {}{}:",
                    emoji, risk_text, category_name, paranoid_suffix
                )
                .red()
            ),
            "yellow" => println!(
                "{}",
                format!(
                    "{} {} RISK{}: {}:",
                    emoji, risk_text, paranoid_suffix, category_name
                )
                .yellow()
            ),
            "blue" => println!(
                "{}",
                format!(
                    "{} {} RISK{}: {}:",
                    emoji, risk_text, paranoid_suffix, category_name
                )
                .blue()
            ),
            _ => println!(
                "{} {} RISK{}: {}:",
                emoji, risk_text, paranoid_suffix, category_name
            ),
        }
    }

    fn show_investigation_commands(&self, category: &FindingCategory, file_path: &std::path::Path) {
        match category {
            FindingCategory::SuspiciousGitBranch | FindingCategory::ShaiHuludRepo => {
                if let Some(parent) = file_path.parent() {
                    println!("     {}", "┌─ Git Investigation Commands:".blue());
                    println!("     {}  cd '{}'", "│".blue(), parent.display());
                    println!("     {}  git log --oneline -10", "│".blue());
                    println!("     {}  git remote -v", "│".blue());
                    println!("     {}  git branch -a", "│".blue());
                    println!("     {}", "└─".blue());
                }
            }
            _ => {}
        }
    }

    fn print_category_notes(&self, category: &FindingCategory) {
        let note = match category {
            FindingCategory::CompromisedPackage => {
                "NOTE: These specific package versions are known to be compromised.\nYou should immediately update or remove these packages."
            }
            FindingCategory::SuspiciousContent => {
                "NOTE: Manual review required to determine if these are malicious."
            }
            FindingCategory::SuspiciousGitBranch => {
                "NOTE: 'shai-hulud' branches may indicate compromise.\nUse the commands above to investigate each branch."
            }
            FindingCategory::PostinstallHook => {
                "NOTE: Postinstall hooks can execute arbitrary code during package installation.\nReview these hooks carefully for malicious behavior."
            }
            FindingCategory::TrufflehogActivity => {
                match category {
                    _ if self.config.paranoid_mode => "NOTE: These patterns may indicate credential harvesting or legitimate security tools.\nManual review recommended to determine if they are malicious.",
                    _ => "NOTE: These patterns indicate likely malicious credential harvesting.\nImmediate investigation and remediation required."
                }
            }
            FindingCategory::ShaiHuludRepo => {
                "NOTE: 'Shai-Hulud' repositories are created by the malware for exfiltration.\nThese should be deleted immediately after investigation."
            }
            FindingCategory::CompromisedNamespace => {
                "NOTE: These namespaces have been compromised but specific versions may vary.\nCheck package versions against known compromise lists."
            }
            FindingCategory::PackageIntegrity => {
                "NOTE: These issues may indicate tampering with package dependencies.\nVerify package versions and regenerate lockfiles if necessary."
            }
            FindingCategory::Typosquatting => {
                "NOTE: These packages may be impersonating legitimate packages.\nVerify package names carefully and check if they should be legitimate packages."
            }
            FindingCategory::NetworkExfiltration => {
                "NOTE: These patterns may indicate data exfiltration or communication with C2 servers.\nReview network connections and data flows carefully."
            }
            FindingCategory::CryptoTheft => {
                "NOTE: These patterns indicate cryptocurrency theft attempts.\nCheck for wallet address replacements and XMLHttpRequest hijacking."
            }
            _ => return,
        };

        println!("   {}", note.yellow());
        println!();
    }

    fn is_paranoid_category(&self, category: &FindingCategory) -> bool {
        matches!(
            category,
            FindingCategory::Typosquatting | FindingCategory::NetworkExfiltration
        )
    }

    fn generate_summary(&self, findings: &ScanFindings, low_risk_findings: &[&Finding]) {
        let high_risk_count = findings.high_risk_count();
        let medium_risk_count = findings.medium_risk_count();
        let low_risk_count = low_risk_findings.len();
        let total_issues = high_risk_count + medium_risk_count;

        println!(
            "{}",
            "==============================================".blue()
        );

        if total_issues == 0 {
            println!(
                "{}",
                "✅ No indicators of Shai-Hulud compromise detected.".green()
            );
            println!(
                "{}",
                "Your system appears clean from this specific attack.".green()
            );

            if low_risk_count > 0 {
                println!();
                println!("{}", "ℹ️  LOW RISK FINDINGS (informational only):".blue());
                for finding in low_risk_findings.iter().take(5) {
                    println!(
                        "   - {}: {}",
                        finding.category.display_name(),
                        finding.description
                    );
                }
                if low_risk_count > 5 {
                    println!("   - ... and {} more low risk findings", low_risk_count - 5);
                }
                println!(
                    "   {}",
                    "NOTE: These are likely legitimate framework code or dependencies.".blue()
                );
            }
        } else {
            println!("{}", "🔍 SUMMARY:".red());
            println!(
                "   {}",
                format!("High Risk Issues: {}", high_risk_count).red()
            );
            println!(
                "   {}",
                format!("Medium Risk Issues: {}", medium_risk_count).yellow()
            );
            if low_risk_count > 0 {
                println!(
                    "   {}",
                    format!("Low Risk (informational): {}", low_risk_count).blue()
                );
            }
            println!(
                "   {}",
                format!("Total Critical Issues: {}", total_issues).blue()
            );
            println!();

            println!("{}", "⚠️  IMPORTANT:".yellow());
            println!(
                "   {}",
                "- High risk issues likely indicate actual compromise".yellow()
            );
            println!(
                "   {}",
                "- Medium risk issues require manual investigation".yellow()
            );
            println!(
                "   {}",
                "- Low risk issues are likely false positives from legitimate code".yellow()
            );

            if self.config.paranoid_mode {
                println!("   {}", "- Issues marked (PARANOID) are general security checks, not Shai-Hulud specific".yellow());
            }

            println!(
                "   {}",
                "- Consider running additional security scans".yellow()
            );
            println!(
                "   {}",
                "- Review your npm audit logs and package history".yellow()
            );

            if low_risk_count > 0 && total_issues < 5 {
                println!();
                println!(
                    "{}",
                    "ℹ️  LOW RISK FINDINGS (likely false positives):".blue()
                );
                for finding in low_risk_findings.iter().take(5) {
                    println!(
                        "   - {}: {}",
                        finding.category.display_name(),
                        finding.description
                    );
                }
                if low_risk_count > 5 {
                    println!("   - ... and {} more low risk findings", low_risk_count - 5);
                }
                println!(
                    "   {}",
                    "NOTE: These are typically legitimate framework patterns.".blue()
                );
            }
        }

        println!(
            "{}",
            "==============================================".blue()
        );
    }
}

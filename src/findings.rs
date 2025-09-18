use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq)]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub file_path: PathBuf,
    pub risk_level: RiskLevel,
    pub category: FindingCategory,
    pub description: String,
    pub details: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    MaliciousWorkflow,
    MaliciousHash,
    CompromisedPackage,
    CompromisedNamespace,
    SuspiciousContent,
    PostinstallHook,
    TrufflehogActivity,
    SuspiciousGitBranch,
    ShaiHuludRepo,
    PackageIntegrity,
    Typosquatting,
    NetworkExfiltration,
    CryptoTheft,
}

impl FindingCategory {
    pub fn display_name(&self) -> &'static str {
        match self {
            FindingCategory::MaliciousWorkflow => "Malicious Workflow",
            FindingCategory::MaliciousHash => "Malicious File Hash",
            FindingCategory::CompromisedPackage => "Compromised Package",
            FindingCategory::SuspiciousContent => "Suspicious Content",
            FindingCategory::SuspiciousGitBranch => "Suspicious Git Branch",
            FindingCategory::PostinstallHook => "Suspicious Postinstall Hook",
            FindingCategory::TrufflehogActivity => "Trufflehog Activity",
            FindingCategory::ShaiHuludRepo => "Shai-Hulud Repository",
            FindingCategory::CompromisedNamespace => "Compromised Namespace",
            FindingCategory::PackageIntegrity => "Package Integrity Issue",
            FindingCategory::Typosquatting => "Typosquatting",
            FindingCategory::NetworkExfiltration => "Network Exfiltration",
            FindingCategory::CryptoTheft => "Cryptocurrency Theft",
        }
    }
}

#[derive(Debug, Default)]
pub struct ScanFindings {
    pub findings: Vec<Finding>,
}

impl ScanFindings {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn has_high_risk_issues(&self) -> bool {
        self.findings.iter().any(|f| f.risk_level == RiskLevel::High)
    }

    pub fn high_risk_count(&self) -> usize {
        self.findings.iter().filter(|f| f.risk_level == RiskLevel::High).count()
    }

    pub fn medium_risk_count(&self) -> usize {
        self.findings.iter().filter(|f| f.risk_level == RiskLevel::Medium).count()
    }

    pub fn low_risk_count(&self) -> usize {
        self.findings.iter().filter(|f| f.risk_level == RiskLevel::Low).count()
    }

    pub fn findings_by_risk(&self, risk_level: RiskLevel) -> Vec<&Finding> {
        self.findings.iter().filter(|f| f.risk_level == risk_level).collect()
    }

    pub fn findings_by_category(&self, category: FindingCategory) -> Vec<&Finding> {
        self.findings.iter().filter(|f| std::mem::discriminant(&f.category) == std::mem::discriminant(&category)).collect()
    }
}

impl Finding {
    pub fn new(
        file_path: PathBuf,
        risk_level: RiskLevel,
        category: FindingCategory,
        description: String,
    ) -> Self {
        Self {
            file_path,
            risk_level,
            category,
            description,
            details: None,
        }
    }

    pub fn with_details(mut self, details: String) -> Self {
        self.details = Some(details);
        self
    }
}

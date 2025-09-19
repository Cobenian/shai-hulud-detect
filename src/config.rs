use anyhow::{Context, Result};
use colored::*;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

// Embed the compromised packages file at compile time
const EMBEDDED_PACKAGES: &str = include_str!("../compromised-packages.txt");

#[derive(Debug, Clone)]
pub struct Config {
    pub paranoid_mode: bool,
    pub malicious_hash: String,
    pub compromised_packages: Vec<CompromisedPackage>,
    pub compromised_namespaces: HashSet<String>,
}

#[derive(Debug, Clone)]
pub struct CompromisedPackage {
    pub name: String,
    pub version: String,
}

impl Config {
    pub fn new(paranoid_mode: bool, packages_source: Option<String>) -> Result<Self> {
        let malicious_hash = "46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09".to_string();
        
        let compromised_namespaces = [
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
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let compromised_packages = Self::load_compromised_packages(packages_source)?;

        Ok(Config {
            paranoid_mode,
            malicious_hash,
            compromised_packages,
            compromised_namespaces,
        })
    }

    fn load_compromised_packages(packages_source: Option<String>) -> Result<Vec<CompromisedPackage>> {
        let content = match packages_source {
            Some(source) => {
                if source.starts_with("http://") || source.starts_with("https://") {
                    // Download from URL
                    println!("{}", format!("📦 Downloading compromised packages from: {}", source).blue());
                    Self::download_packages_from_url(&source)?
                } else {
                    // Read from file path
                    println!("{}", format!("📦 Loading compromised packages from: {}", source).blue());
                    fs::read_to_string(&source)
                        .with_context(|| format!("Failed to read packages file: {}", source))?
                }
            }
            None => {
                // Default behavior - use embedded packages
                println!("{}", "📦 Using embedded compromised packages database".green());
                EMBEDDED_PACKAGES.to_string()
            }
        };
        
        let mut packages = Vec::new();
        let mut count = 0;
        
        for line in content.lines() {
            let line = line.trim();
            
            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            
            // Parse package:version format
            if let Some((name, version)) = line.split_once(':') {
                // Validate format
                if Self::is_valid_package_version(name, version) {
                    packages.push(CompromisedPackage {
                        name: name.to_string(),
                        version: version.to_string(),
                    });
                    count += 1;
                }
            }
        }
        
        println!("{}", format!("📦 Loaded {} compromised packages", count).green());
        Ok(packages)
    }

    fn download_packages_from_url(url: &str) -> Result<String> {
        let response = reqwest::blocking::get(url)
            .with_context(|| format!("Failed to download from URL: {}", url))?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error {}: Failed to download from {}", response.status(), url));
        }
        
        let content = response.text()
            .with_context(|| format!("Failed to read response from URL: {}", url))?;
        
        Ok(content)
    }

    fn is_valid_package_version(name: &str, version: &str) -> bool {
        // Basic validation for package name and version format
        !name.is_empty() && 
        !version.is_empty() &&
        version.chars().any(|c| c.is_ascii_digit()) &&
        version.contains('.')
    }

    fn get_fallback_packages() -> Vec<CompromisedPackage> {
        vec![
            CompromisedPackage {
                name: "@ctrl/tinycolor".to_string(),
                version: "4.1.0".to_string(),
            },
            CompromisedPackage {
                name: "@ctrl/tinycolor".to_string(),
                version: "4.1.1".to_string(),
            },
            CompromisedPackage {
                name: "@ctrl/tinycolor".to_string(),
                version: "4.1.2".to_string(),
            },
            CompromisedPackage {
                name: "@ctrl/deluge".to_string(),
                version: "1.2.0".to_string(),
            },
            CompromisedPackage {
                name: "angulartics2".to_string(),
                version: "14.1.2".to_string(),
            },
            CompromisedPackage {
                name: "koa2-swagger-ui".to_string(),
                version: "5.11.1".to_string(),
            },
            CompromisedPackage {
                name: "koa2-swagger-ui".to_string(),
                version: "5.11.2".to_string(),
            },
        ]
    }
}

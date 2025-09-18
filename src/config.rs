use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

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
    pub fn new(paranoid_mode: bool) -> Result<Self> {
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

        let compromised_packages = Self::load_compromised_packages()?;

        Ok(Config {
            paranoid_mode,
            malicious_hash,
            compromised_packages,
            compromised_namespaces,
        })
    }

    fn load_compromised_packages() -> Result<Vec<CompromisedPackage>> {
        let packages_file = "compromised-packages.txt";
        
        if Path::new(packages_file).exists() {
            let content = fs::read_to_string(packages_file)
                .context("Failed to read compromised-packages.txt")?;
            
            let mut packages = Vec::new();
            
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
                    }
                }
            }
            
            println!("📦 Loaded {} compromised packages from {}", packages.len(), packages_file);
            Ok(packages)
        } else {
            println!("⚠️  Warning: {} not found, using embedded package list", packages_file);
            Ok(Self::get_fallback_packages())
        }
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

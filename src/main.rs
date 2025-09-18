use clap::Parser;
use colored::*;
use std::path::PathBuf;

mod config;
mod detector;
mod findings;
mod report;
mod scanner;

use config::Config;
use detector::ShaiHuludDetector;

#[derive(Parser)]
#[command(name = "shai-hulud-detector")]
#[command(about = "Shai-Hulud NPM Supply Chain Attack Detection Tool")]
#[command(version = "0.1.0")]
struct Cli {
    /// Enable additional security checks (typosquatting, network patterns)
    #[arg(long, help = "Enable paranoid mode with additional security checks")]
    paranoid: bool,

    /// Directory to scan for indicators of compromise
    #[arg(help = "Directory to scan")]
    directory: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Validate directory exists
    if !cli.directory.exists() {
        eprintln!("{}", format!("Error: Directory '{}' does not exist.", cli.directory.display()).red());
        std::process::exit(1);
    }

    if !cli.directory.is_dir() {
        eprintln!("{}", format!("Error: '{}' is not a directory.", cli.directory.display()).red());
        std::process::exit(1);
    }

    // Load configuration
    let config = Config::new(cli.paranoid)?;

    // Create detector instance
    let mut detector = ShaiHuludDetector::new(config);

    // Print startup message
    println!("{}", "Starting Shai-Hulud detection scan...".green());
    if cli.paranoid {
        println!("{}", format!("Scanning directory: {} (with paranoid mode enabled)", cli.directory.display()).blue());
    } else {
        println!("{}", format!("Scanning directory: {}", cli.directory.display()).blue());
    }
    println!();

    // Run the scan
    let findings = detector.scan(&cli.directory)?;

    // Generate and display report
    detector.generate_report(&findings);

    // Exit with appropriate code
    let exit_code = if findings.has_high_risk_issues() { 1 } else { 0 };
    std::process::exit(exit_code);
}

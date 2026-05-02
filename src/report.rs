use anyhow::Result;
use colored::*;

pub fn generate_report(file: &str, format: &str) -> Result<()> {
    let report = crate::metadata::build_metadata_report(file)?;

    match format.to_lowercase().as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&report)?;
            println!("{}", json);
        }
        "text" => {
            println!("{}", "[+] PhantomBit Report".bright_blue().bold());
            println!("File: {}", report.file_path);
            println!("MIME: {}", report.mime_type);
            println!("Risk Score: {}/100", report.risk_score);
            println!("Risk Level: {}", report.risk_level);

            if !report.suspicious_indicators.is_empty() {
                println!("Indicators:");
                for item in report.suspicious_indicators {
                    println!("- {}", item);
                }
            }
        }
        _ => {
            println!("{}", "[!] Unsupported format. Use json or text.".red());
        }
    }

    Ok(())
}

use anyhow::Result;
use colored::*;

pub fn encode(input: &str, output: &str, message: &str, passphrase: &str) -> Result<()> {
    println!("{}", "[+] Hybrid Encode Mode".bright_blue().bold());

    // Step 1: Analyze metadata
    let report = crate::metadata::build_metadata_report(input)?;

    println!("Original Risk Score: {}/100 ({})", report.risk_score, report.risk_level);

    // Step 2: Warn user if already suspicious
    if report.risk_score > 60 {
        println!("{}", "[!] Warning: Input file already has high risk indicators.".yellow());
    }

    // Step 3: Use LSB encode (already encrypted internally)
    crate::stego::lsb::encode(input, output, message, passphrase)?;

    println!("{}", "\n[+] Hybrid Encoding Complete".green().bold());
    println!("Output File: {}", output);

    Ok(())
}

pub fn decode(input: &str, passphrase: &str) -> Result<()> {
    println!("{}", "[+] Hybrid Decode Mode".bright_blue().bold());

    // Step 1: Decode hidden message
    crate::stego::lsb::decode(input, passphrase)?;

    // Step 2: Re-analyze metadata
    println!("{}", "\n[+] Post-Decode Metadata Analysis".bright_blue().bold());
    let report = crate::metadata::analyze_file(input)?;

    println!(
        "Final Risk Score: {}/100 ({})",
        report.risk_score, report.risk_level
    );

    Ok(())
}

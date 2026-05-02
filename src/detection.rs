use anyhow::Result;
use colored::*;

pub fn analyze_stego(file_path: &str) -> Result<()> {
    println!("{}", "[+] Stego Detection Engine".bright_blue().bold());

    let img = image::open(file_path)?.to_rgba8();

    let mut lsb_bits = Vec::new();

    for pixel in img.pixels() {
        let rgba = pixel.0;

        for channel in 0..3 {
            lsb_bits.push(rgba[channel] & 1);
        }
    }

    let ratio = calculate_ratio(&lsb_bits);
    let variance = calculate_variance(&lsb_bits);

    println!("LSB 1s Ratio: {:.4}", ratio);
    println!("LSB Variance: {:.4}", variance);

    let buffer = std::fs::read(file_path)?;
    let entropy = calculate_entropy(&buffer);

    println!("Entropy: {:.4}", entropy);

    // Chi-Square integration part
    let chi_square = chi_square_test(&buffer);
    println!("Chi-Square Value: {:.4}", chi_square);

    let mut indicators = Vec::new();

    // 1. Ratio check
    if ratio < 0.48 || ratio > 0.52 {
        indicators.push("LSB ratio deviates from natural distribution".to_string());
    }

    // 2. Variance check
    if variance < 0.20 {
        indicators.push("Low LSB variance; possible structured embedding".to_string());
    }

    // 3. Entropy check
    if entropy > 7.95 {
        indicators.push("Unusually high entropy".to_string());
    }

    // 4. Chi-square detection 
    if chi_square < 300.0 {
        indicators.push("Chi-square anomaly detected; possible LSB embedding".to_string());
    }

    // 5. Size anomaly
    if buffer.len() > 15_000_000 {
        indicators.push("Large file anomaly".to_string());
    }

    let score = calculate_stego_score(&indicators);

    if indicators.is_empty() {
        println!("{}", "[+] No strong steganographic indicators detected.".green());
    } else {
        println!("{}", "[!] Suspicious Indicators:".yellow().bold());
        for i in &indicators {
            println!("  - {}", i);
        }
    }

    println!(
        "{} {}/100 ({})",
        "[!] Stego Suspicion Score:".bright_red().bold(),
        score,
        risk_level(score)
    );

    Ok(())
}

// Ratio
fn calculate_ratio(bits: &[u8]) -> f64 {
    let ones = bits.iter().filter(|&&b| b == 1).count();
    ones as f64 / bits.len() as f64
}

//  Variance
fn calculate_variance(bits: &[u8]) -> f64 {
    let mean = calculate_ratio(bits);
    let mut variance = 0.0;

    for &b in bits {
        variance += (b as f64 - mean).powi(2);
    }

    variance / bits.len() as f64
}

//Entropy
fn calculate_entropy(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];

    for b in data {
        freq[*b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for count in freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

//  Chi-Square Attack
fn chi_square_test(data: &[u8]) -> f64 {
    let mut freq = [0usize; 256];

    for &byte in data {
        freq[byte as usize] += 1;
    }

    let mut chi_square = 0.0;

    for i in (0..256).step_by(2) {
        let o1 = freq[i] as f64;
        let o2 = freq[i + 1] as f64;

        let expected = (o1 + o2) / 2.0;

        if expected > 0.0 {
            chi_square += (o1 - expected).powi(2) / expected;
            chi_square += (o2 - expected).powi(2) / expected;
        }
    }

    chi_square
}

//  Scoring
fn calculate_stego_score(indicators: &[String]) -> u8 {
    let mut score = 10;

    for ind in indicators {
        if ind.contains("ratio") {
            score += 30;
        } else if ind.contains("variance") {
            score += 40;
        } else if ind.contains("entropy") {
            score += 20;
        } else if ind.contains("Chi-square") {
            score += 50; 
        } else if ind.contains("file") {
            score += 10;
        }
    }

    score.min(100)
}

// Risk Level
fn risk_level(score: u8) -> &'static str {
    match score {
        0..=30 => "Low",
        31..=60 => "Medium",
        61..=80 => "High",
        _ => "Critical",
    }
}

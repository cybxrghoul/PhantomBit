pub fn calculate_metadata_risk(indicators: &[String], file_size: u64) -> u8 {
    let mut score: u16 = 10;

    for indicator in indicators {
        if indicator.contains("Extension mismatch") {
            score += 35;
        } else if indicator.contains("Unknown file signature") {
            score += 25;
        } else if indicator.contains("Large file size") {
            score += 20;
        } else if indicator.contains("Empty file") {
            score += 40;
        } else if indicator.contains("Readonly") {
            score += 10;
        } else if indicator.contains("Suspicious filename") {
            score += 10;
        } else if indicator.contains("GPS metadata") {
            score += 25;
        } else if indicator.contains("Software metadata") {
            score += 10;
        } else if indicator.contains("metadata may have been stripped") {
            score += 15;
        } else if indicator.contains("Unusually high entropy") {
            score += 20;
        } else if indicator.contains("Very high entropy detected in a non-compressed file") {
            score += 35;
        }
    }

    if file_size > 50_000_000 {
        score += 15;
    }

    score.min(100) as u8
}

pub fn risk_level(score: u8) -> &'static str {
    match score {
        0..=30 => "Low",
        31..=60 => "Medium",
        61..=80 => "High",
        _ => "Critical",
    }
}

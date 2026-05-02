use anyhow::{Context, Result};
use chrono::{DateTime, Local};
use colored::*;
use exif::{In, Reader, Tag};
use serde::Serialize;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::time::SystemTime;

#[derive(Debug, Serialize)]
pub struct MetadataReport {
    pub file_path: String,
    pub file_name: String,
    pub extension: String,
    pub detected_extension: String,
    pub mime_type: String,
    pub file_size_bytes: u64,
    pub readonly: bool,
    pub created: String,
    pub modified: String,
    pub accessed: String,

    pub exif_found: bool,
    pub exif_tag_count: usize,
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub software: Option<String>,
    pub datetime_original: Option<String>,
    pub gps_found: bool,

    pub entropy_score: f64,
    pub suspicious_indicators: Vec<String>,
    pub risk_score: u8,
    pub risk_level: String,
}

pub fn analyze_file(file_path: &str) -> Result<MetadataReport> {
    let report = build_metadata_report(file_path)?;

    println!("{}", "[+] Forensic Metadata Engine".bright_blue().bold());
    println!("File: {}", report.file_path);
    println!("Name: {}", report.file_name);
    println!("Extension: {}", report.extension);
    println!(
        "Detected Type: .{} ({})",
        report.detected_extension, report.mime_type
    );
    println!("Size: {} bytes", report.file_size_bytes);
    println!("Readonly: {}", report.readonly);
    println!("Created: {}", report.created);
    println!("Modified: {}", report.modified);
    println!("Accessed: {}", report.accessed);

    println!("{}", "\n[+] EXIF Intelligence".bright_blue().bold());
    println!("EXIF Found: {}", report.exif_found);
    println!("EXIF Tags: {}", report.exif_tag_count);
    println!("Camera Make: {}", option_text(&report.camera_make));
    println!("Camera Model: {}", option_text(&report.camera_model));
    println!("Software: {}", option_text(&report.software));
    println!("Original DateTime: {}", option_text(&report.datetime_original));
    println!("GPS Found: {}", report.gps_found);

    println!("{}", "\n[+] Entropy Analysis".bright_blue().bold());
    println!("Entropy: {:.4}", report.entropy_score);

    if report.suspicious_indicators.is_empty() {
        println!("{}", "\n[+] No major suspicious indicators found.".green());
    } else {
        println!("{}", "\n[!] Suspicious Indicators:".yellow().bold());
        for indicator in &report.suspicious_indicators {
            println!("  - {}", indicator);
        }
    }

    println!(
        "{} {}/100 ({})",
        "\n[!] Risk Score:".bright_red().bold(),
        report.risk_score,
        report.risk_level
    );

    Ok(report)
}

pub fn build_metadata_report(file_path: &str) -> Result<MetadataReport> {
    let path = Path::new(file_path);

    let metadata = fs::metadata(path)
        .with_context(|| format!("Could not read metadata for file: {}", file_path))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string();

    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("none")
        .to_lowercase();

    let buffer = fs::read(path)
        .with_context(|| format!("Could not read file content: {}", file_path))?;

    let detected = infer::get(&buffer);

    let detected_extension = detected
        .map(|kind| kind.extension().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mime_type = detected
        .map(|kind| kind.mime_type().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let created = format_system_time(metadata.created().ok());
    let modified = format_system_time(metadata.modified().ok());
    let accessed = format_system_time(metadata.accessed().ok());

    let exif_info = extract_exif_info(path).unwrap_or_default();
    let entropy_score = calculate_entropy(&buffer);

    let suspicious_indicators = collect_indicators(
        &extension,
        &detected_extension,
        &mime_type,
        metadata.len(),
        metadata.permissions().readonly(),
        &file_name,
        &exif_info,
        entropy_score,
    );

    let risk_score = crate::risk::calculate_metadata_risk(&suspicious_indicators, metadata.len());
    let risk_level = crate::risk::risk_level(risk_score).to_string();

    Ok(MetadataReport {
        file_path: file_path.to_string(),
        file_name,
        extension,
        detected_extension,
        mime_type,
        file_size_bytes: metadata.len(),
        readonly: metadata.permissions().readonly(),
        created,
        modified,
        accessed,
        exif_found: exif_info.exif_found,
        exif_tag_count: exif_info.exif_tag_count,
        camera_make: exif_info.camera_make,
        camera_model: exif_info.camera_model,
        software: exif_info.software,
        datetime_original: exif_info.datetime_original,
        gps_found: exif_info.gps_found,
        entropy_score,
        suspicious_indicators,
        risk_score,
        risk_level,
    })
}

#[derive(Default)]
struct ExifInfo {
    exif_found: bool,
    exif_tag_count: usize,
    camera_make: Option<String>,
    camera_model: Option<String>,
    software: Option<String>,
    datetime_original: Option<String>,
    gps_found: bool,
}

fn extract_exif_info(path: &Path) -> Result<ExifInfo> {
    let file = File::open(path)?;
    let mut bufreader = BufReader::new(file);

    let exif_reader = Reader::new().read_from_container(&mut bufreader)?;

    let mut info = ExifInfo {
        exif_found: true,
        exif_tag_count: exif_reader.fields().count(),
        ..Default::default()
    };

    info.camera_make = get_exif_field(&exif_reader, Tag::Make);
    info.camera_model = get_exif_field(&exif_reader, Tag::Model);
    info.software = get_exif_field(&exif_reader, Tag::Software);
    info.datetime_original = get_exif_field(&exif_reader, Tag::DateTimeOriginal);

    info.gps_found = exif_reader
        .fields()
        .any(|field| format!("{:?}", field.tag).to_lowercase().contains("gps"));

    Ok(info)
}

fn get_exif_field(exif: &exif::Exif, tag: Tag) -> Option<String> {
    exif.get_field(tag, In::PRIMARY)
        .map(|field| field.display_value().with_unit(exif).to_string())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut frequency = [0usize; 256];

    for byte in data {
        frequency[*byte as usize] += 1;
    }

    let data_len = data.len() as f64;
    let mut entropy = 0.0;

    for count in frequency {
        if count > 0 {
            let probability = count as f64 / data_len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

fn format_system_time(time: Option<SystemTime>) -> String {
    match time {
        Some(value) => {
            let datetime: DateTime<Local> = value.into();
            datetime.format("%Y-%m-%d %H:%M:%S").to_string()
        }
        None => "Unavailable".to_string(),
    }
}

fn option_text(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "Not found".to_string())
}

fn collect_indicators(
    extension: &str,
    detected_extension: &str,
    mime_type: &str,
    file_size: u64,
    readonly: bool,
    file_name: &str,
    exif_info: &ExifInfo,
    entropy_score: f64,
) -> Vec<String> {
    let mut indicators = Vec::new();

    if detected_extension == "unknown" || mime_type == "unknown" {
        indicators.push("Unknown file signature or unsupported MIME type".to_string());
    }

    if extension != "none"
        && detected_extension != "unknown"
        && extension != detected_extension
        && !(extension == "jpeg" && detected_extension == "jpg")
    {
        indicators.push(format!(
            "Extension mismatch: file says .{}, signature suggests .{}",
            extension, detected_extension
        ));
    }

    if file_size == 0 {
        indicators.push("Empty file detected".to_string());
    }

    if file_size > 10_000_000 {
        indicators.push("Large file size; possible embedded payload or hidden data".to_string());
    }

    if readonly {
        indicators.push("Readonly file attribute is enabled".to_string());
    }

    let suspicious_name_terms = ["secret", "hidden", "payload", "encoded", "stego", "phantom"];
    let lowercase_name = file_name.to_lowercase();

    for term in suspicious_name_terms {
        if lowercase_name.contains(term) {
            indicators.push(format!("Suspicious filename term detected: '{}'", term));
        }
    }

    if exif_info.gps_found {
        indicators.push("GPS metadata found; possible privacy exposure".to_string());
    }

    if exif_info.exif_found && exif_info.software.is_some() {
        indicators.push("Software metadata found; may reveal editing or processing tool".to_string());
    }

    if !exif_info.exif_found && matches!(extension, "jpg" | "jpeg" | "tiff" | "png" | "webp") {
        indicators.push("No EXIF metadata found in image; metadata may have been stripped".to_string());
    }

    let compressed_media = matches!(
        detected_extension,
        "jpg" | "jpeg" | "png" | "webp" | "zip" | "pdf" | "mp4" | "mp3"
    );

    if entropy_score > 7.90 && !compressed_media {
        indicators.push(
            "Very high entropy detected in a non-compressed file; possible encrypted or packed payload"
                .to_string(),
        );
    } else if entropy_score > 7.97 && compressed_media {
        indicators.push(
            "Unusually high entropy even for a compressed media file; possible embedded payload"
                .to_string(),
        );
    }

    indicators
}

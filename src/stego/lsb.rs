use anyhow::{anyhow, Result};
use colored::*;
use image::{ImageBuffer, RgbaImage};

const END_MARKER: &str = "<<<PHANTOMBIT_END>>>";

pub fn encode(input: &str, output: &str, message: &str, passphrase: &str) -> Result<()> {
    let img = image::open(input)?.to_rgba8();

    let encrypted = crate::crypto::encrypt_message(message, passphrase)?;
    let payload = format!("{}{}", encrypted, END_MARKER);
    let bits = string_to_bits(&payload);

    let capacity = (img.width() * img.height() * 3) as usize;

    if bits.len() > capacity {
        return Err(anyhow!(
            "Message too large. Required {} bits, but image capacity is {} bits.",
            bits.len(),
            capacity
        ));
    }

    let mut encoded_img: RgbaImage = ImageBuffer::new(img.width(), img.height());
    let mut bit_index = 0;

    for (x, y, pixel) in img.enumerate_pixels() {
        let mut rgba = pixel.0;

        for channel in 0..3 {
            if bit_index < bits.len() {
                rgba[channel] = (rgba[channel] & 0xFE) | bits[bit_index];
                bit_index += 1;
            }
        }

        encoded_img.put_pixel(x, y, image::Rgba(rgba));
    }

    encoded_img.save(output)?;

    println!("{}", "[+] Secure LSB Encode Complete".bright_blue().bold());
    println!("Input: {}", input);
    println!("Output: {}", output);
    println!("Original message size: {} bytes", message.len());
    println!("Encrypted payload bits embedded: {}", bits.len());
    println!("{}", "[+] Encrypted hidden message embedded successfully.".green());

    Ok(())
}

pub fn decode(input: &str, passphrase: &str) -> Result<()> {
    let img = image::open(input)?.to_rgba8();

    let mut bits = Vec::new();

    for pixel in img.pixels() {
        let rgba = pixel.0;

        for channel in 0..3 {
            bits.push(rgba[channel] & 1);
        }
    }

    let decoded = bits_to_string(&bits);

    if let Some(position) = decoded.find(END_MARKER) {
        let encrypted_payload = &decoded[..position];

        println!("{}", "[+] LSB Payload Found".bright_blue().bold());

        match crate::crypto::decrypt_message(encrypted_payload, passphrase) {
            Ok(message) => {
                println!("{}", "[+] Decryption successful".green());
                println!("Hidden Message:");
                println!("{}", message.green());
            }
            Err(_) => {
                println!("{}", "[!] Decryption failed. Wrong passphrase or corrupted payload.".red());
            }
        }
    } else {
        println!("{}", "[!] No PhantomBit LSB payload marker found.".yellow());
    }

    Ok(())
}

fn string_to_bits(input: &str) -> Vec<u8> {
    let mut bits = Vec::new();

    for byte in input.bytes() {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1);
        }
    }

    bits
}

fn bits_to_string(bits: &[u8]) -> String {
    let mut bytes = Vec::new();

    for chunk in bits.chunks(8) {
        if chunk.len() < 8 {
            break;
        }

        let mut byte = 0u8;

        for bit in chunk {
            byte = (byte << 1) | bit;
        }

        bytes.push(byte);
    }

    String::from_utf8_lossy(&bytes).to_string()
}

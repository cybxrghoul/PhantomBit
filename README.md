# ⬡ PhantomBit v1.0

**Steganography • Forensic Metadata Analysis • Stego Detection**

PhantomBit is a Rust-based cybersecurity tool designed for **secure data hiding** and **forensic-level steganalysis**. It combines encryption, steganography, metadata intelligence, and statistical detection into a single CLI framework.

---

## Features

### 🔍 Forensic Metadata Engine
- File signature detection (magic bytes)
- MIME type validation
- EXIF extraction (camera, software, timestamps)
- GPS metadata detection
- Entropy analysis
- Metadata anomaly detection
- Risk scoring (Low → Critical)

---

### 🔐 Secure Steganography
- LSB-based image steganography (PNG)
- AES-256-GCM encryption
- Argon2-based key derivation
- Passphrase-protected payloads

---

### 🧠 Hybrid Mode
- Combines metadata analysis + encryption + steganography
- Warns if carrier file is already suspicious
- Produces risk-aware stego output

---

### 🕵️ Stego Detection Engine
- LSB statistical analysis
- Bit distribution & variance checks
- Entropy-based anomaly detection
- Chi-square attack (research-level detection)
- Stego suspicion scoring

---

## Installation

```bash
git clone https://github.com/cybxrghoul/PhantomBit.git
cd PhantomBit
cargo build

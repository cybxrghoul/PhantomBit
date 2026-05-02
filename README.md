# ⬡ PhantomBit v1.0

<p align="center">
  <b>Steganography • Stego Detection • Forensic Metadata Analysis</b><br>
  <sub>A Rust-based cybersecurity toolkit for secure data hiding and statistical steganalysis</sub>
</p>

---

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70+-orange?style=for-the-badge&logo=rust">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge">
</p>

---

## Why PhantomBit?

PhantomBit is not just a steganography tool.

It is a **forensic-aware steganography and stego detection engine** built for:

- Cybersecurity enthusiasts  
- Digital forensics learners  
- Detection engineering projects  
- Research-oriented applications  

---

## Core Features

### 🔐 Secure Steganography
- PNG LSB steganography
- AES-256-GCM encryption
- Argon2 key derivation
- Passphrase-protected payloads

---

### 🔍 Forensic Metadata Engine
- File signature (magic byte) detection  
- MIME type validation  
- EXIF extraction (camera, software, timestamps)  
- GPS metadata detection  
- Entropy analysis  
- Risk scoring (Low → Critical)  

---

### 🧠 Hybrid Mode (🔥 Unique Feature)
- Combines metadata analysis + encryption + steganography  
- Warns if carrier file is already suspicious  
- Produces **risk-aware stego output**  

---

### 🕵️ Stego Detection Engine
- LSB statistical analysis  
- Bit distribution & variance checks  
- Entropy anomaly detection  
- **Chi-square attack (research-level)**  
- Stego suspicion scoring  

---

## ⚙️ Installation

```bash
git clone https://github.com/cybxrghoul/PhantomBit.git
cd PhantomBit
cargo build
```
---

## 🧠 Detection Techniques

PhantomBit uses multiple detection strategies:

- Entropy-based anomaly detection
- LSB bit distribution analysis
- Variance-based statistical modeling
- Chi-square attack for LSB embedding detection

---

## 🛡️ Security Design
- AES-256-GCM (Authenticated Encryption)
- Argon2 password hashing
- Nonce-based encryption
- Payload integrity validation

---

## Project Structure
```
src/
├── cli.rs
├── crypto.rs
├── metadata.rs
├── risk.rs
├── detection.rs
├── stego/
│   ├── lsb.rs
│   └── hybrid.rs
```

---

## ⚠️Limitations
Detection is probabilistic (not guaranteed)
JPEG is not suitable for LSB encoding (use PNG)
Small payloads are harder to detect

---

## 🚀 Future Work
RS analysis (advanced steganalysis)
Machine learning-based detection
Tauri GUI interface
Stego heatmap visualization
Multi-format support (audio/video)

---

## 📜License
MIT License

---

## ⭐ Support

If you found this project useful:

👉 Star ⭐ the repo
👉 Share it with cybersecurity peers
👉 Use it in your projects

---
## 👤Author
**cybxrghoul**
Cybersecurity | Detection Engineering | Steganalysis


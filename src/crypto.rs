use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use base64::{engine::general_purpose, Engine};

pub fn encrypt_message(message: &str, passphrase: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 error: {}", e))?;

    let hash = password_hash
        .hash
        .ok_or_else(|| anyhow!("Key derivation failed"))?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher
        .encrypt(&nonce, message.as_bytes())
        .map_err(|e| anyhow!("Encryption error: {}", e))?;

    let payload = format!(
        "{}:{}:{}",
        salt.as_str(),
        general_purpose::STANDARD.encode(nonce),
        general_purpose::STANDARD.encode(ciphertext)
    );

    Ok(payload)
}

pub fn decrypt_message(payload: &str, passphrase: &str) -> Result<String> {
    let parts: Vec<&str> = payload.split(':').collect();

    if parts.len() != 3 {
        return Err(anyhow!("Invalid encrypted payload format"));
    }

    let salt_str = parts[0];
    let nonce = general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| anyhow!("Nonce decode error: {}", e))?;

    let ciphertext = general_purpose::STANDARD
        .decode(parts[2])
        .map_err(|e| anyhow!("Ciphertext decode error: {}", e))?;

    let salt = SaltString::from_b64(salt_str)
        .map_err(|e| anyhow!("Salt parse error: {}", e))?;

    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(passphrase.as_bytes(), &salt)
        .map_err(|e| anyhow!("Argon2 error: {}", e))?;

    let hash = password_hash
        .hash
        .ok_or_else(|| anyhow!("Key derivation failed"))?;

    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(&hash.as_bytes()[..32]);
    let cipher = Aes256Gcm::new(key);

    let decrypted = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("Decryption failed (wrong passphrase or corrupted data)"))?;

    Ok(String::from_utf8(decrypted)?)
}

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Error};
use rand::{thread_rng, Rng};

/// Nonce: unique per message.
/// 96-bits (12 bytes)
const NONCE_LENGTH: usize = 12;

fn random_bytes() -> [u8; NONCE_LENGTH] {
    thread_rng().gen::<[u8; NONCE_LENGTH]>()
}

pub fn encrypt(key: &[u8], plain_txt: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce_rnd = random_bytes();
    let nonce = Nonce::from_slice(&nonce_rnd);
    let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(Error::msg)?;
    let mut cipher_txt = Vec::new();
    cipher_txt.extend_from_slice(&nonce_rnd);
    cipher_txt.extend(encrypt_msg);
    Ok(cipher_txt)
}

pub fn decrypt(key: &[u8], cipher_txt: &[u8]) -> Result<Vec<u8>, Error> {
    if cipher_txt.len() <= NONCE_LENGTH {
        bail!("cipher text is invalid");
    }
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nonce_rnd);
    let plain_txt = cipher
        .decrypt(nonce, &cipher_txt[NONCE_LENGTH..])
        .map_err(Error::msg)?;
    Ok(plain_txt)
}

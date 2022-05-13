use aes_gcm_example::{decrypt, encrypt};
use anyhow::{bail, Context, Error};

fn main() -> Result<(), Error> {
    // 1. Secret Key
    //  256-bits (32 bytes)
    const KEY: &[u8; 32] = b"a very simple secret key to use!";

    const PLAIN_TEXT: &[u8; 32] = b"a very simple message to encrypt";

    // 2. Encrypt
    let cipher_text = encrypt(KEY, PLAIN_TEXT.as_ref()).with_context(|| "encryption failure!")?;

    // 3. Decrypt
    let plain_text = decrypt(KEY, cipher_text.as_ref()).with_context(|| "decryption failure!")?;

    // 4. Match!
    if plain_text != PLAIN_TEXT {
        bail!("decrypted text doesn't match!")
    }

    Ok(())
}

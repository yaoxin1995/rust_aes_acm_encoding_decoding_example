use std::borrow::BorrowMut;

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Error};
use rand::{thread_rng, Rng};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct IoFrame {
    pub nonce: Vec<u8>,
    // length: usize,
    // encrypted payload structure using aes-gcm
    pub pay_load: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Default,Clone)]
pub struct PayLoad {
    pub counter: u128,
    pub data: Vec<u8>,
}


/// Nonce: unique per message.
/// 96-bits (12 bytes)
pub const NONCE_LENGTH: usize = 12;

fn random_bytes() -> [u8; NONCE_LENGTH] {
    thread_rng().gen::<[u8; NONCE_LENGTH]>()
}



pub fn encrypt(key: &[u8], plain_txt: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    let nonce_rnd = random_bytes();
    let nonce = Nonce::from_slice(&nonce_rnd);
    let encrypt_msg = cipher.encrypt(nonce, plain_txt).map_err(Error::msg)?;
    let mut cipher_txt = Vec::new();
    // cipher_txt.extend_from_slice(&nonce_rnd);
    cipher_txt.extend(encrypt_msg);
    Ok((cipher_txt, nonce_rnd.to_vec()))
}

pub fn decrypt(key: &[u8], cipher_txt: &[u8], nouce: &[u8]) -> Result<Vec<u8>, Error> {
    // if cipher_txt.len() <= NONCE_LENGTH {
    //     bail!("cipher text is invalid");
    // }
    let cipher = Aes256Gcm::new(Key::from_slice(key));
    // let nonce_rnd = &cipher_txt[..NONCE_LENGTH];
    let nonce = Nonce::from_slice(nouce);
    let plain_txt = cipher
        .decrypt(nonce, &cipher_txt[..])
        .map_err(Error::msg)?;
    Ok(plain_txt)
}


pub fn prepareEncodedIoFrame(plainText :&[u8]) -> Result<Vec<u8>, Error> {

    const KEY: &[u8; 32] = b"a very simple secret key to use!";

    let mut payload = PayLoad::default();
    payload.counter = 1;
    payload.data = plainText.to_vec();

    let encoded_payload: Vec<u8> = bincode::serialize(&payload).unwrap();

    let mut io_frame = IoFrame::default();

    (io_frame.pay_load, io_frame.nonce)= encrypt(KEY, encoded_payload.as_ref()).unwrap();

    let encoded_frame = bincode::serialize(&io_frame).unwrap();

    Ok(encoded_frame)
}


pub fn getDecodedPayloads(encoded_payload :&Vec<u8>) -> Result<Vec<PayLoad>, Error> {

    const KEY: &[u8; 32] = b"a very simple secret key to use!";

    let mut payloads = Vec::new();

    let mut start= 0;
    while start < encoded_payload.len() {
        let frame1:IoFrame = bincode::deserialize(encoded_payload[start..].as_ref()).unwrap();
        // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        // print!("frame111111111111 : {:?}\n", frame1);
    
    
        let decrypted = decrypt(KEY, &frame1.pay_load, &frame1.nonce).unwrap();
        let payload:PayLoad = bincode::deserialize(decrypted.as_ref()).unwrap();

        payloads.push(payload);
    
    
        // print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());

        // print!("payload111 :{:?}\n", &payload);
        start = start + bincode::serialized_size(&frame1).unwrap() as usize;

    }
    

    // print!("payloads22222 :{:?}\n", payloads);
    Ok(payloads)

}

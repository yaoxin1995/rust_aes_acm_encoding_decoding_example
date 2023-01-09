use aes_gcm_example::*;
use anyhow::{bail, Context, Error};
use std::io::prelude::*;
use std::process::{Command, Stdio};
use serde::{Serialize, Deserialize};
use bincode::*;

static PANGRAM: &'static str =
"the quick brown fox jumped over the lazy dog\n";

static PANGRAM1: &'static str =
"who are you docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configuration\n";





fn main() -> () {

    const KEY: &[u8; 32] = b"a very simple secret key to use!";

    const PLAIN_TEXT: &[u8] = b"a very simple message to encrypt";


    const PLAIN_TEXT1: &[u8] = b"who are you docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configurationt1111111111111111111111111111111111111111111111\n";

    let mut payload1 = PayLoad::default();
    payload1.counter = 1;
    payload1.data = PLAIN_TEXT.to_vec();

    let mut payload2 = PayLoad::default();
    payload2.counter = 2;
    payload2.data = PLAIN_TEXT1.to_vec();

    let encodedIoFrame1: Vec<u8> = bincode::serialize(&payload1).unwrap();
    let encodedIoFrame2: Vec<u8> = bincode::serialize(&payload2).unwrap();

    let mut ioFrame1 = IoFrame::default();
    let mut  ioFrame2 = IoFrame::default();

    // 2. Encrypt
    (ioFrame1.pay_load, ioFrame1.nonce)= encrypt(KEY, encodedIoFrame1.as_ref()).with_context(|| "encryption failure!").unwrap();

    (ioFrame2.pay_load, ioFrame2.nonce) = encrypt(KEY, encodedIoFrame2.as_ref()).with_context(|| "encryption failure!").unwrap();


    print!("ioFrame1 : {:?}\n", ioFrame1);
    print!("ioFrame2 : {:?}\n", ioFrame2);


    let encodedFrame1 = bincode::serialize(&ioFrame1).unwrap();
    let encodedFrame2 = bincode::serialize(&ioFrame2).unwrap();

    let mut encoded12 =  encodedFrame1.clone();
    encoded12.append(encodedFrame2.clone().as_mut());

    
    let mut start= 0;
    while start < encoded12.len() {
        let frame1:IoFrame = bincode::deserialize(encoded12[start..].as_ref()).unwrap();
        // let frame2:IoFrame = bincode::deserialize(encoded12[]).unwrap();
        print!("frame111111111111 : {:?}\n", frame1);
    
    
        let decrypted = decrypt(KEY, &frame1.pay_load, &frame1.nonce).unwrap();
        let payload:PayLoad = bincode::deserialize(decrypted.as_ref()).unwrap();
    
    
        print!("decrypted22222222222 {:?}, PLAIN_TEXT{:?}\n", payload, PLAIN_TEXT1.as_ref());

        start = start + bincode::serialized_size(&frame1).unwrap() as usize;

    }
    
}

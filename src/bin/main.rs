use aes_gcm_example::*;



fn main() -> () {


    const PLAIN_TEXT: &[u8] = b"a very simple message to encrypt";


    const PLAIN_TEXT1: &[u8] = b"who are you docker-entrypoint.sh: /docker-entrypoint.d/ is not empty, will attempt to perform configurationt1111111111111111111111111111111111111111111111\n";

    let encoded_ioframe1= prepareEncodedIoFrame(PLAIN_TEXT).unwrap();
    let encoded_ioframe2 = prepareEncodedIoFrame(PLAIN_TEXT1).unwrap();


    let payload1= getDecodedPayloads(&encoded_ioframe1).unwrap();
    let payload2= getDecodedPayloads(&encoded_ioframe2).unwrap();

    let mut encoded_12 = encoded_ioframe1.clone();
    encoded_12.append(encoded_ioframe2.clone().as_mut());

    assert_eq!(PLAIN_TEXT, payload1[0].data);
    assert_eq!(PLAIN_TEXT1, payload2[0].data);


    let payload12 = getDecodedPayloads(&encoded_12).unwrap();

    assert_eq!(2, payload12.len());
    assert_eq!(PLAIN_TEXT, payload12[0].data);
    assert_eq!(PLAIN_TEXT1, payload12[1].data);


}

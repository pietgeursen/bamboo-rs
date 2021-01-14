use bamboo_rs_core::entry::publish;
use bamboo_rs_core::Keypair;
use ed25519_dalek::{KEYPAIR_LENGTH, SECRET_KEY_LENGTH};

use core::slice;
pub mod error;
pub use error::PublishError;

#[repr(C)]
pub struct PublishEd25519Blake2bEntryArgs<'a> {
    pub out: &'a mut u8,
    pub out_length: usize,
    pub payload_bytes: &'a u8,
    pub payload_length: usize,
    pub public_key_bytes: &'a u8,
    pub public_key_length: usize,
    pub secret_key_bytes: &'a u8,
    pub secret_key_length: usize,
    pub backlink_bytes: &'a u8,
    pub backlink_length: usize,
    pub lipmaalink_bytes: &'a u8,
    pub lipmaalink_length: usize,
    pub is_end_of_feed: bool,
    pub last_seq_num: u64,
    pub log_id: u64,
}

#[no_mangle]
pub extern "C" fn publish_ed25519_blake2b_entry(
    args: &mut PublishEd25519Blake2bEntryArgs,
) -> PublishError {
    let out: &mut [u8] = unsafe { slice::from_raw_parts_mut(args.out, args.out_length) };
    let payload: &[u8] = unsafe { slice::from_raw_parts(args.payload_bytes, args.payload_length) };
    let public_key: &[u8] =
        unsafe { slice::from_raw_parts(args.public_key_bytes, args.public_key_length) };
    let secret_key: &[u8] =
        unsafe { slice::from_raw_parts(args.secret_key_bytes, args.secret_key_length) };

    let lipmaalink_slice =
        unsafe { slice::from_raw_parts(args.lipmaalink_bytes, args.lipmaalink_length) };
    let lipmaalink = match args.lipmaalink_length {
        0 => None,
        _ => Some(lipmaalink_slice),
    };
    let backlink_slice =
        unsafe { slice::from_raw_parts(args.backlink_bytes, args.backlink_length) };
    let backlink = match args.backlink_length {
        0 => None,
        _ => Some(backlink_slice),
    };

    let mut key_pair_bytes = [0u8; KEYPAIR_LENGTH];
    key_pair_bytes[..SECRET_KEY_LENGTH].copy_from_slice(secret_key);
    key_pair_bytes[SECRET_KEY_LENGTH..].copy_from_slice(public_key);

    //first public and then secret
    let key_pair = Keypair::from_bytes(&key_pair_bytes[..]);

    if let Err(_) = key_pair {
        return PublishError::PublishWithoutKeypair;
    }

    match publish(
        out,
        Some(&key_pair.unwrap()),
        args.log_id,
        payload,
        args.is_end_of_feed,
        Some(args.last_seq_num),
        lipmaalink,
        backlink,
    ) {
        Ok(encoded_size) => {
            args.out_length = encoded_size;
            PublishError::NoError
        }
        Err(err) => err.into(),
    }
}

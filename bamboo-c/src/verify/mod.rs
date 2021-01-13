use bamboo_rs_core::entry::verify;
use core::slice;

mod error;
pub use error::VerifyError;

#[repr(C)]
pub struct VerifyEd25519Blake2bEntryArgs<'a> {
    pub entry_bytes: &'a u8,
    pub entry_length: usize,
    pub payload_bytes: &'a u8,
    pub payload_length: usize,
    pub backlink_bytes: &'a u8,
    pub backlink_length: usize,
    pub lipmaalink_bytes: &'a u8,
    pub lipmaalink_length: usize,
}

#[no_mangle]
pub extern "C" fn verify_ed25519_blake2b_entry(
    args: &mut VerifyEd25519Blake2bEntryArgs,
) -> VerifyError {
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
    let payload_slice: &[u8] =
        unsafe { slice::from_raw_parts(args.payload_bytes, args.payload_length) };
    let payload = match args.payload_length {
        0 => None,
        _ => Some(payload_slice),
    };

    let entry: &[u8] = unsafe { slice::from_raw_parts(args.entry_bytes, args.entry_length) };

    match verify(entry, payload, lipmaalink, backlink) {
        Ok(_) => VerifyError::NoError,
        Err(err) => err.into(),
    }
}

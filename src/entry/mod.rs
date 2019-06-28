use super::yamf_hash::YamfHash;

mod de;
mod ser;

pub use self::de::*;
pub use self::ser::*;

pub struct Entry {
    is_end_of_feed: bool,
    payload_hash: YamfHash,
    payload_size: u64,
    seq_num: u64,
    backlink: YamfHash,
    lipmaa_link: YamfHash,
    sig: Vec<u8>,
}

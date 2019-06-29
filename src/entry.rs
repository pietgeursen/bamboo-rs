use std::io::Write;
use varu64::{decode as varu64_decode, encode as varu64_encode};

use super::yamf_hash::YamfHash;
use super::signature::Signature;

pub struct Entry<'a> {
    pub is_end_of_feed: bool,
    pub payload_hash: YamfHash<'a>,
    pub payload_size: u64,
    pub seq_num: u64,
    pub backlink: Option<YamfHash<'a>>,
    pub lipmaa_link: Option<YamfHash<'a>>,
    pub sig: Signature<'a> ,
}

impl<'a> Entry<'a> {
    pub fn encode(self) -> Vec<u8> {
        unimplemented!()
    }

    pub fn encode_write<W: Write>(self, w: W) -> Vec<u8> {
        unimplemented!()
    }

    pub fn decode(bytes: &'a [u8]) -> Entry<'a> {
        unimplemented!()
    }

    pub fn verify_signature() {
        //how would be verify this type ergonimcally tho?
        //verifying means we have to get the contents of the buffer up to but not including the
        //sig.
        unimplemented!();
    }

}

use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;
use lipmaa_link::lipmaa;

pub mod decode;
pub mod encode;
pub mod publish;
pub mod verify;
#[cfg(feature = "std")]
pub mod verify_batch;

pub use decode::decode;
pub use verify::verify;
#[cfg(feature = "std")]
pub use verify_batch::verify_batch;
pub use publish::publish;

#[cfg(feature = "std")]
use crate::util::hex_serde::*;

#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};

use ed25519_dalek::{
    PublicKey as DalekPublicKey, PUBLIC_KEY_LENGTH,
};

use super::signature::{Signature, MAX_SIGNATURE_SIZE};
use super::yamf_hash::{YamfHash, MAX_YAMF_HASH_SIZE};

pub use crate::error::*;

const TAG_BYTE_LENGTH: usize = 1;
const MAX_VARU64_SIZE: usize = 9;
pub const MAX_ENTRY_SIZE_: usize = TAG_BYTE_LENGTH
    + MAX_SIGNATURE_SIZE
    + PUBLIC_KEY_LENGTH
    + (MAX_YAMF_HASH_SIZE * 3)
    + (MAX_VARU64_SIZE * 3);

/// This is useful if you need to know at compile time how big an entry can get.
pub const MAX_ENTRY_SIZE: usize = 322;

// Yes, this is hacky. It's because cbindgen can't understand how to add consts together. This is a
// way to hard code a value for MAX_ENTRY_SIZE that cbindgen can use, but make sure at compile time
// that the value is actually correct.
const_assert_eq!(max_entry_size; MAX_ENTRY_SIZE_ as isize, MAX_ENTRY_SIZE as isize);

#[cfg_attr(feature = "std", derive(Deserialize, Serialize))]
#[cfg_attr(feature = "std", serde(rename_all = "camelCase"))]
#[derive(Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Entry<H, S>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    pub log_id: u64,
    pub is_end_of_feed: bool,
    #[cfg_attr(feature = "std", serde(bound(deserialize = "H: From<Vec<u8>>")))]
    pub payload_hash: YamfHash<H>,
    pub payload_size: u64,
    #[cfg_attr(
        feature = "std",
        serde(
            serialize_with = "serialize_pub_key",
            deserialize_with = "deserialize_pub_key"
        )
    )]
    pub author: DalekPublicKey,
    pub seq_num: u64,
    pub backlink: Option<YamfHash<H>>,
    pub lipmaa_link: Option<YamfHash<H>>,
    #[cfg_attr(feature = "std", serde(bound(deserialize = "S: From<Vec<u8>>")))]
    pub sig: Option<Signature<S>>,
}

impl<'a> TryFrom<&'a [u8]> for Entry<&'a [u8], &'a [u8]> {
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Entry<&'a [u8], &'a [u8]>, Self::Error> {
        decode(bytes)
    }
}

impl<'a, H, S> TryFrom<Entry<H, S>> for ArrayVec<[u8; 512]>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    type Error = Error;

    fn try_from(entry: Entry<H, S>) -> Result<ArrayVec<[u8; 512]>, Self::Error> {
        let mut buff = [0u8; 512];
        let len = entry.encode(&mut buff)?;
        let mut vec = ArrayVec::<[u8; 512]>::from(buff);
        unsafe {
            vec.set_len(len);
        }
        Ok(vec)
    }
}

pub fn into_owned<H, S>(entry: &Entry<H, S>) -> Entry<ArrayVec<[u8; 64]>, ArrayVec<[u8; 64]>>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    let sig = match entry.sig {
        Some(Signature(ref s)) => {
            let mut vec = ArrayVec::<[u8; 64]>::new();
            vec.try_extend_from_slice(&s.borrow()[..]).unwrap();
            Some(Signature(vec))
        }
        None => None,
    };

    let payload_hash = match entry.payload_hash {
        YamfHash::Blake2b(ref s) => {
            let mut vec = ArrayVec::<[u8; 64]>::new();
            vec.try_extend_from_slice(&s.borrow()[..]).unwrap();
            YamfHash::Blake2b(vec)
        }
    };

    let backlink = match entry.backlink {
        Some(YamfHash::Blake2b(ref s)) => {
            let mut vec = ArrayVec::<[u8; 64]>::new();
            vec.try_extend_from_slice(&s.borrow()[..]).unwrap();
            Some(YamfHash::Blake2b(vec))
        }
        None => None,
    };

    let lipmaa_link = match entry.lipmaa_link {
        Some(YamfHash::Blake2b(ref s)) => {
            let mut vec = ArrayVec::<[u8; 64]>::new();
            vec.try_extend_from_slice(&s.borrow()[..]).unwrap();
            Some(YamfHash::Blake2b(vec))
        }
        None => None,
    };

    Entry {
        is_end_of_feed: entry.is_end_of_feed,
        payload_size: entry.payload_size,
        seq_num: entry.seq_num,
        log_id: entry.log_id,
        payload_hash,
        lipmaa_link,
        backlink,
        author: entry.author,
        sig,
    }
}

pub fn is_lipmaa_required(sequence_num: u64) -> bool {
    lipmaa(sequence_num) != sequence_num - 1
}



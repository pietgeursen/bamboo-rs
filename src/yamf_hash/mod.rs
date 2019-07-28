use blake2b_simd::{blake2b, OUTBYTES};
use core::borrow::Borrow;
use core::ops::Deref;
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::io::{Error as IoError, Write};

use crate::util::hex_serde::{cow_from_hex, hex_from_cow};
use varu64::{decode as varu64_decode, encode as varu64_encode, DecodeError as varu64DecodeError};

pub const BLAKE2B_HASH_SIZE: usize = OUTBYTES;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding var64 for hash. {}", source))]
    DecodeVaru64Error { source: varu64DecodeError },
    #[snafu(display("Error when decoding hash."))]
    DecodeError,
    #[snafu(display("IO Error when encoding hash to writer. {}", source))]
    EncodeWriteError { source: IoError },
}

/// Variants of `YamfHash`
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
pub enum YamfHash<'a> {
    #[serde(deserialize_with = "cow_from_hex", serialize_with = "hex_from_cow")]
    Blake2b(Cow<'a, [u8]>),
}

/// A borrowed YamfHash
#[derive(Deserialize, Serialize, Debug, Eq, PartialEq)]
pub enum YamfHash2<T: Borrow<[u8]>> {
    Blake2b(T),
}

//impl<T:Borrow<[u8]>> YamfHash2<T> {
//    fn new_blake2b(bytes: &[u8])-> YamfHash2<T>{
//        let hash_bytes = blake2b(bytes);
//        YamfHash2::Blake2b(hash_bytes.as_ref())
//    }
//}

//gah fuck ok what's the problem here:
//
//What do I want in a perfect world
//Either, one type that can abstract over whether the data is owned or borrowed like Cow.
//Or: making two types, one for a ref to a slice and the other that owns the bytes
//  - we know that the general form of the pattern is _possible_ because of the str + String types.
//  - one thing to try is to try and get things to compile using str and String
//  - another thing is try again with the unsafe code and pointers.
//  - read more about deref, asref and borrow.
//  - check Sean's convo on signal
//  - want to try that pattern again
//  - what are other crates that solve similar problems?
//      - blake2b
//      - serde
//          - serde seems to do things a little differently where the methods doing the decoding
//          are split by borrow / owned.
//
// - what are the use cases for when I want to use borrowed vs owned?
//  - borrow:
//      - when we decode from bytes borrowed from a log.
//  - owned
//      - when we want to actually hash some bytes and make a new yamfhash or yamfsignature.
//

//
//impl<'a> YamfHash2<'a> {
//    /// Encode a YamfHash into the out buffer.
//    pub fn encode(&self, out: &mut [u8]) {
//        match self.hash_type {
//            YamfHashType::Blake2b => {
//                varu64_encode(1, &mut out[0..1]);
//                varu64_encode(BLAKE2B_HASH_SIZE as u64, &mut out[1..2]);
//                out[2..].copy_from_slice(&self.inner);
//            }
//        }
//    }
//}

impl<'a> YamfHash<'a> {
    /// Encode a YamfHash into the out buffer.
    pub fn encode(&self, out: &mut [u8]) {
        match self {
            YamfHash::Blake2b(vec) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(BLAKE2B_HASH_SIZE as u64, &mut out[1..2]);
                out[2..].copy_from_slice(&vec);
            }
        }
    }

    /// Encode a YamfHash into the writer.
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfHash::Blake2b(vec) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(BLAKE2B_HASH_SIZE as u64, &mut out[1..2]);
                w.write_all(&out).context(EncodeWriteError)?;
                w.write_all(&vec).context(EncodeWriteError)?;
                Ok(())
            }
        }
    }

    /// Decode the `bytes` as a `YamfHash`
    pub fn decode(bytes: &'a [u8]) -> Result<(YamfHash<'a>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((1, remaining_bytes)) if remaining_bytes.len() >= 65 => {
                let hash = &remaining_bytes[1..65];
                Ok((YamfHash::Blake2b(hash.into()), &remaining_bytes[65..]))
            }
            Err((err, _)) => Err(Error::DecodeVaru64Error { source: err }),
            _ => Err(Error::DecodeError {}),
        }
    }

    /// Create a new `YamfHash::Blake2b` by hashing the input `bytes`. The resulting `YamfHash` owns the underlying
    /// hash bytes.
    pub fn new_blake2b<'b>(bytes: &'b [u8]) -> YamfHash<'static> {
        let hash_bytes = blake2b(bytes);
        YamfHash::Blake2b(Cow::Owned(hash_bytes.as_bytes().to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, YamfHash, YamfHash2, BLAKE2B_HASH_SIZE};
    use arrayvec::ArrayVec;
    use blake2b_simd::blake2b;
    use core::convert::TryInto;
    use core::iter::FromIterator;
    use std::io::Write;

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes.into());
        let expected = [1, 64, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = vec![0; 6];
        yamf_hash.encode(&mut encoded);
        assert_eq!(encoded, expected);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes.into());
        let expected = [1, 64, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = Vec::new();
        yamf_hash.encode_write(&mut encoded).unwrap();
        assert_eq!(encoded, expected);
    }
    #[test]
    fn encode_yamf_not_enough_bytes_for_varu() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes.into());

        let mut encoded = [0; 2];
        match yamf_hash.encode_write(&mut encoded[..]) {
            Err(Error::EncodeWriteError { source: _ }) => {}
            _ => panic!("Go ok, expected error"),
        }
    }
    #[test]
    fn encode_yamf_not_enough_bytes_for_hash() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes.into());

        let mut encoded = [0; 4];
        match yamf_hash.encode_write(&mut encoded[..]) {
            Err(Error::EncodeWriteError { source: _ }) => {}
            _ => panic!("Go ok, expected error"),
        }
    }
    #[test]
    fn decode_yamf() {
        let mut hash_bytes = vec![0xFF; 67];
        hash_bytes[0] = 1;
        hash_bytes[1] = 64;
        hash_bytes[66] = 0xAA;
        let result = YamfHash::decode(&hash_bytes);

        match result {
            Ok((YamfHash::Blake2b(vec), remaining_bytes)) => {
                assert_eq!(vec.len(), 64);
                assert_eq!(vec, &hash_bytes[2..66]);
                assert_eq!(remaining_bytes, &[0xAA]);
            }
            _ => panic!(),
        }
    }
    #[test]
    fn decode_yamf_varu_error() {
        let mut hash_bytes = vec![0xFF; 67];
        hash_bytes[0] = 248;
        hash_bytes[1] = 1;
        hash_bytes[2] = 64;
        hash_bytes[66] = 0xAA;
        let result = YamfHash::decode(&hash_bytes);

        match result {
            Err(Error::DecodeVaru64Error { source: _ }) => {}
            _ => panic!(),
        }
    }
    #[test]
    fn decode_yamf_not_enough_bytes_error() {
        let mut hash_bytes = vec![0xFF; 64];
        hash_bytes[0] = 1;
        hash_bytes[1] = 64;
        let result = YamfHash::decode(&hash_bytes);

        match result {
            Err(Error::DecodeError {}) => {}
            _ => panic!(),
        }
    }

    //If this is gonna be no_std what are the use cases:
    // - it has to work with arrays or arrayvec
    // - we can't use Vec<>
    // - it'd be nice if

    #[test]
    fn blake_yamf_hash() {
        let lam = || {
            let hash_bytes = blake2b(&[1, 2]);
            let vec_bytes: ArrayVec<[u8; BLAKE2B_HASH_SIZE]> =
                ArrayVec::from_iter(hash_bytes.as_bytes().iter().map(|b| *b));
            YamfHash2::Blake2b(vec_bytes)
        };
        let result = lam();
    }
    #[test]
    fn blake_yamf_hash_eq() {
        let lam = || {
            let hash_bytes = blake2b(&[1, 2]);
            let vec_bytes: ArrayVec<[u8; BLAKE2B_HASH_SIZE]> =
                ArrayVec::from_iter(hash_bytes.as_bytes().iter().map(|b| *b));
            YamfHash2::Blake2b(vec_bytes)
        };
        let result = lam();

        let hash_bytes = blake2b(&[1, 2]);
        let result2 = YamfHash2::Blake2b(hash_bytes.as_bytes());

        assert_eq!(result2, result);
    }
    #[test]
    fn owned_yamf_hash() {
        let lam = || {
            let mut hash_bytes = ArrayVec::<[u8; BLAKE2B_HASH_SIZE]>::new();
            hash_bytes.push(1);
            hash_bytes.push(64);
            YamfHash2::Blake2b(hash_bytes)
        };
        let result = lam();
    }
    #[test]
    fn ref_yamf_hash() {
        let mut hash_bytes = ArrayVec::<[u8; BLAKE2B_HASH_SIZE * 2]>::new();
        hash_bytes.push(1);
        hash_bytes.push(64);
        YamfHash2::Blake2b(hash_bytes);
    }
    //    #[test]
    //    fn ref_from_slice_yamf_hash() {
    //        let mut hash_bytes = [0xFFu8; BLAKE2B_HASH_SIZE*2];
    //        hash_bytes[0] = 1;
    //        hash_bytes[1] = 64;
    //
    //        let other_bytes: [u8; BLAKE2B_HASH_SIZE] = hash_bytes[..BLAKE2B_HASH_SIZE].try_into().unwrap();
    //
    //        let result = YamfHash2::Blake2b(other_bytes);
    //
    //        match result {
    //            YamfHash2::Blake2b(arr) => {
    //                assert_eq!(arr[0], 1);
    //            }
    //        }
    //    }
}

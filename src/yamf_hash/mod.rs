use blake2b_simd::{blake2b, OUTBYTES};
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::io::{Error as IoError, Write};

use crate::util::hex_serde::{cow_from_hex, hex_from_cow};
use varu64::{decode as varu64_decode, encode as varu64_encode, DecodeError as varu64DecodeError};

const BLAKE2B_HASH_SIZE: usize = OUTBYTES;

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
    use super::{Error, YamfHash};

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
}
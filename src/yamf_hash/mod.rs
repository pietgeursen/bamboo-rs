use arrayvec::ArrayVec;
use blake2b_simd::{blake2b, OUTBYTES};
use core::borrow::Borrow;
use core::iter::FromIterator;
use snafu::{ResultExt, Snafu};

#[cfg(feature = "std")]
use std::io::{Error as IoError, Write};

use varu64::{
    decode as varu64_decode, encode as varu64_encode, encoding_length,
    DecodeError as varu64DecodeError,
};

pub const BLAKE2B_HASH_SIZE: usize = OUTBYTES;
pub const BLAKE2B_NUMERIC_ID: u64 = 0;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding var64 for hash. {}", source))]
    DecodeVaru64Error { source: varu64DecodeError },
    #[snafu(display("Error when decoding hash."))]
    DecodeError,
    #[snafu(display("IO Error when encoding hash to writer. {}", source))]
    EncodeWriteError { source: IoError },
    #[snafu(display("Error when encoding hash."))]
    EncodeError,
}

/// Variants of `YamfHash`
#[derive(Deserialize, Serialize, Debug, Eq)]
pub enum YamfHash<T: Borrow<[u8]> + PartialEq + Eq> {
    Blake2b(T),
}

impl<B1: Borrow<[u8]> + Eq, B2: Borrow<[u8]> + Eq> PartialEq<YamfHash<B1>> for YamfHash<B2> {
    fn eq(&self, other: &YamfHash<B1>) -> bool {
        match (self, other) {
            (YamfHash::Blake2b(vec), YamfHash::Blake2b(vec2)) => vec.borrow() == vec2.borrow(),
        }
    }
}

pub fn new_blake2b(bytes: &[u8]) -> YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>> {
    let hash_bytes = blake2b(bytes);

    let vec_bytes: ArrayVec<[u8; BLAKE2B_HASH_SIZE]> =
        ArrayVec::from_iter(hash_bytes.as_bytes().iter().map(|b| *b));

    YamfHash::Blake2b(vec_bytes)
}

impl<'a> From<&'a YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>> for YamfHash<&'a[u8]>{
    fn from(hash: & YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>) -> YamfHash<&[u8]>{
        match hash {
            YamfHash::Blake2b(bytes) => {
                YamfHash::Blake2b(&bytes[..])
            }
        }
    }
}

impl<T: Borrow<[u8]> + PartialEq + Eq> YamfHash<T> {
    /// Encode a YamfHash into the out buffer.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let encoded_size = self.encoding_length();

        match (self, out.len()) {
            (YamfHash::Blake2b(vec), len) if len >= encoded_size => {
                varu64_encode(BLAKE2B_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(BLAKE2B_HASH_SIZE as u64, &mut out[1..2]);
                out[2..].copy_from_slice(vec.borrow());
                Ok(encoded_size)
            }
            _ => Err(Error::EncodeError),
        }
    }

    pub fn encoding_length(&self) -> usize {
        match self {
            YamfHash::Blake2b(_) => {
                encoding_length(0u64)
                    + encoding_length(BLAKE2B_HASH_SIZE as u64)
                    + BLAKE2B_HASH_SIZE
            }
        }
    }

    /// Decode the `bytes` as a `YamfHash`
    pub fn decode<'a>(bytes: &'a [u8]) -> Result<(YamfHash<&'a [u8]>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((BLAKE2B_NUMERIC_ID, remaining_bytes)) if remaining_bytes.len() >= 65 => {
                let hash = &remaining_bytes[1..65];
                Ok((YamfHash::Blake2b(hash), &remaining_bytes[65..]))
            }
            Err((err, _)) => Err(Error::DecodeVaru64Error { source: err }),
            _ => Err(Error::DecodeError {}),
        }
    }

    /// Encode a YamfHash into the writer.
    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfHash::Blake2b(vec) => {
                varu64_encode(BLAKE2B_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(BLAKE2B_HASH_SIZE as u64, &mut out[1..2]);
                w.write_all(&out).context(EncodeWriteError)?;
                w.write_all(vec.borrow()).context(EncodeWriteError)?;
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, YamfHash, BLAKE2B_HASH_SIZE};
    use arrayvec::ArrayVec;
    use blake2b_simd::blake2b;
    use core::convert::TryInto;
    use core::iter::FromIterator;
    use std::io::Write;

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; 64];
        let yamf_hash = YamfHash::Blake2b(hash_bytes);

        let mut encoded = vec![0; 66];
        let length = yamf_hash.encode(&mut encoded).unwrap();
        assert_eq!(length, 66);
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 64);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; 64];
        let yamf_hash = YamfHash::Blake2b(hash_bytes);

        let mut encoded = Vec::new();
        yamf_hash.encode_write(&mut encoded).unwrap();
        assert_eq!(encoded.len(), 66);
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 64);
    }
    #[test]
    fn encode_yamf_not_enough_bytes_for_varu() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes);

        let mut encoded = [0; 2];
        match yamf_hash.encode_write(&mut encoded[..]) {
            Err(Error::EncodeWriteError { source: _ }) => {}
            _ => panic!("Go ok, expected error"),
        }
    }
    #[test]
    fn encode_yamf_not_enough_bytes_for_hash() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(hash_bytes);

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
        let result = YamfHash::<&[u8]>::decode(&hash_bytes);

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
        let result = YamfHash::<&[u8]>::decode(&hash_bytes);

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
        let result = YamfHash::<&[u8]>::decode(&hash_bytes);

        match result {
            Err(Error::DecodeError {}) => {}
            _ => panic!(),
        }
    }

    #[test]
    fn blake_yamf_hash() {
        let lam = || {
            let hash_bytes = blake2b(&[1, 2]);
            let vec_bytes: ArrayVec<[u8; BLAKE2B_HASH_SIZE]> =
                ArrayVec::from_iter(hash_bytes.as_bytes().iter().map(|b| *b));
            YamfHash::Blake2b(vec_bytes)
        };
        let result = lam();
    }

    #[test]
    fn blake_yamf_hash_eq() {
        let lam = || {
            let hash_bytes = blake2b(&[1, 2]);
            let vec_bytes: ArrayVec<[u8; BLAKE2B_HASH_SIZE]> =
                ArrayVec::from_iter(hash_bytes.as_bytes().iter().map(|b| *b));
            YamfHash::Blake2b(vec_bytes)
        };
        let result = lam();

        let hash_bytes = blake2b(&[1, 2]);
        let result2 = YamfHash::Blake2b(hash_bytes.as_bytes());

        assert_eq!(result, result2);
        assert_eq!(result2, result);
    }
    #[test]
    fn owned_yamf_hash() {
        let lam = || {
            let mut hash_bytes = ArrayVec::<[u8; BLAKE2B_HASH_SIZE]>::new();
            hash_bytes.push(1);
            hash_bytes.push(64);
            YamfHash::Blake2b(hash_bytes)
        };
        let result = lam();
    }
    #[test]
    fn ref_yamf_hash() {
        let mut hash_bytes = ArrayVec::<[u8; BLAKE2B_HASH_SIZE * 2]>::new();
        hash_bytes.push(1);
        hash_bytes.push(64);
        YamfHash::Blake2b(hash_bytes);
    }
    #[test]
    fn from_owned_to_ref_yamf_hash() {
        let lam = || {
            let mut hash_bytes = ArrayVec::<[u8; BLAKE2B_HASH_SIZE]>::new();
            hash_bytes.push(1);
            hash_bytes.push(64);
            YamfHash::Blake2b(hash_bytes)
        };
        let result = lam();
        let borrowed: YamfHash<&[u8]> = YamfHash::from(&result);
    }
    //    #[test]
    //    fn ref_from_slice_yamf_hash() {
    //        let mut hash_bytes = [0xFFu8; BLAKE2B_HASH_SIZE*2];
    //        hash_bytes[0] = 1;
    //        hash_bytes[1] = 64;
    //
    //        let other_bytes: [u8; BLAKE2B_HASH_SIZE] = hash_bytes[..BLAKE2B_HASH_SIZE].try_into().unwrap();
    //
    //        let result = YamfHash::Blake2b(other_bytes);
    //
    //        match result {
    //            YamfHash::Blake2b(arr) => {
    //                assert_eq!(arr[0], 1);
    //            }
    //        }
    //    }
}

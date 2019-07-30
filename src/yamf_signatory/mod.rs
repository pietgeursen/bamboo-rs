#[cfg(feature = "std")]
use std::io::{Error as IoError, Write};

use crate::util::hex_serde::{cow_from_hex, hex_from_cow};
use snafu::{ResultExt, Snafu};
use ssb_crypto::PUBLICKEYBYTES;
use std::borrow::Cow;
use varu64::{
    decode as varu64_decode, encode as varu64_encode, encoding_length,
    DecodeError as varu64DecodeError,
};

pub const ED25519_NUMERIC_ID: u64 = 0;
pub const ED25519_SIZE: usize = PUBLICKEYBYTES;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding var64 for signatory. {}", source))]
    DecodeVaru64Error { source: varu64DecodeError },
    #[snafu(display("Error when decoding signatory."))]
    DecodeError,
    #[snafu(display("IO Error when encoding signatory to writer. {}", source))]
    EncodeWriteError { source: IoError },
    #[snafu(display("Error when encoding signatory."))]
    EncodeError,
}

/// A Yamf Signatory holds a public key and a ref to an optional private key.
///
/// The [yamf-signatory](https://github.com/AljoschaMeyer/yamf-signatory) spec only supports
/// Ed25519 keys at the moment but more will be added in time.
///
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum YamfSignatory<'a> {
    /// Tuple of public and optional secret key
    Ed25519(
        #[serde(deserialize_with = "cow_from_hex", serialize_with = "hex_from_cow")] Cow<'a, [u8]>,
        #[serde(skip)] Option<&'a [u8]>,
    ),
}

impl<'a> YamfSignatory<'a> {
    /// Encode this signatory into the `out` byte slice.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let encoded_size = self.encoding_length();

        match (self, out.len()) {
            (YamfSignatory::Ed25519(vec, _), buffer_length) if buffer_length >= encoded_size => {
                varu64_encode(ED25519_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(ED25519_SIZE as u64, &mut out[1..2]);
                out[2..].copy_from_slice(&vec);
                Ok(encoded_size)
            }
            _ => Err(Error::EncodeError),
        }
    }

    /// Encode this signatory into a Write.
    ///
    /// Returns errors if the Writer errors.
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfSignatory::Ed25519(vec, _) => {
                varu64_encode(ED25519_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(ED25519_SIZE as u64, &mut out[1..2]);
                w.write_all(&out).context(EncodeWriteError)?;
                w.write_all(&vec).context(EncodeWriteError)?;
                Ok(())
            }
        }
    }

    pub fn encoding_length(&self) -> usize {
        match self {
            YamfSignatory::Ed25519(_, _) => {
                encoding_length(ED25519_NUMERIC_ID) + encoding_length(ED25519_SIZE as u64) + PUBLICKEYBYTES
            }
        }
    }

    /// Attempt to decode a byte slice as a YamfSignatory.
    ///
    /// Returns errors if the provided byte slice was not long enough or if the incoding was
    /// invalid.
    pub fn decode(bytes: &'a [u8]) -> Result<(YamfSignatory<'a>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((ED25519_NUMERIC_ID, remaining_bytes)) if remaining_bytes.len() >= 33 => {
                let hash = &remaining_bytes[1..33];
                Ok((
                    YamfSignatory::Ed25519(hash.into(), None),
                    &remaining_bytes[33..],
                ))
            }
            Err((err, _)) => Err(Error::DecodeVaru64Error { source: err }),
            _ => Err(Error::DecodeError {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{YamfSignatory, ED25519_SIZE, ED25519_NUMERIC_ID};

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; ED25519_SIZE];
        let yamf_hash = YamfSignatory::Ed25519(hash_bytes.into(), None);
        let expected = [ED25519_NUMERIC_ID as u8, ED25519_SIZE as u8, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = vec![0; ED25519_SIZE + 2];
        yamf_hash.encode(&mut encoded);
        assert_eq!(encoded[0], ED25519_NUMERIC_ID as u8);
        assert_eq!(encoded[1], ED25519_SIZE as u8);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; ED25519_SIZE];
        let yamf_hash = YamfSignatory::Ed25519(hash_bytes.into(), None);
        let expected = [ED25519_NUMERIC_ID as u8, ED25519_SIZE as u8, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = Vec::new();
        yamf_hash.encode_write(&mut encoded).unwrap();
        assert_eq!(encoded[0], ED25519_NUMERIC_ID as u8);
        assert_eq!(encoded[1], ED25519_SIZE as u8);
    }
    #[test]
    fn decode_yamf() {
        let mut hash_bytes = vec![0xFF; 35];
        hash_bytes[0] = ED25519_NUMERIC_ID as u8;
        hash_bytes[1] = ED25519_SIZE as u8;
        hash_bytes[34] = 0xAA;
        let result = YamfSignatory::decode(&hash_bytes);

        match result {
            Ok((YamfSignatory::Ed25519(vec, _), remaining_bytes)) => {
                assert_eq!(vec.len(), ED25519_SIZE);
                assert_eq!(vec, &hash_bytes[2..34]);
                assert_eq!(remaining_bytes, &[0xAA]);
            }
            _ => panic!(),
        }
    }
}

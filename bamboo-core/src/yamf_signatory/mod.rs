use crate::error::*;
use core::borrow::Borrow;
#[cfg(feature = "std")]
use std::io::Write;

#[cfg(feature = "std")]
use crate::util::hex_serde::{hex_from_bytes, vec_from_hex};
use arrayvec::ArrayVec;
use ed25519_dalek::PUBLIC_KEY_LENGTH;
use varu64::{decode as varu64_decode, encode as varu64_encode, encoding_length};

pub const ED25519_NUMERIC_ID: u64 = 0;
pub const ED25519_SIZE: usize = PUBLIC_KEY_LENGTH;

/// The maximum number of bytes this will use for any variant.
///
/// This is a bit yuck because it knows the number of bytes varu64 uses to encode the
/// ED25519_NUMERIC_ID and the ED25519_SIZE (2).
/// This is unlikely to cause a problem until there are hundreds of variants.
pub const MAX_YAMF_SIGNATORY_SIZE: usize = ED25519_SIZE + 2;

/// A Yamf Signatory holds a public key and a ref to an optional private key.
///
/// The [yamf-signatory](https://github.com/AljoschaMeyer/yamf-signatory) spec only supports
/// Ed25519 keys at the moment but more will be added in time.
///
#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum YamfSignatory<'a, T: Borrow<[u8]>> {
    /// Tuple of public and optional secret key
    Ed25519(
        #[cfg_attr(
            feature = "std",
            serde(serialize_with = "hex_from_bytes", deserialize_with = "vec_from_hex")
        )]
        #[cfg_attr(feature = "std", serde(bound(deserialize = "T: From<Vec<u8>>")))]
        T,
        #[serde(skip)] Option<&'a [u8]>,
    ),
}

impl<'a> From<&'a YamfSignatory<'a, ArrayVec<[u8; ED25519_SIZE]>>> for YamfSignatory<'a, &'a [u8]> {
    fn from(hash: &'a YamfSignatory<ArrayVec<[u8; ED25519_SIZE]>>) -> YamfSignatory<'a, &'a [u8]> {
        match hash {
            YamfSignatory::Ed25519(bytes, secret) => YamfSignatory::Ed25519(&bytes[..], *secret),
        }
    }
}

impl<'a, T: Borrow<[u8]>> YamfSignatory<'a, T> {
    /// Encode this signatory into the `out` byte slice.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        let encoded_size = self.encoding_length();

        match (self, out.len()) {
            (YamfSignatory::Ed25519(vec, _), buffer_length) if buffer_length >= encoded_size => {
                varu64_encode(ED25519_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(ED25519_SIZE as u64, &mut out[1..2]);
                out[2..encoded_size].copy_from_slice(vec.borrow());
                Ok(encoded_size)
            }
            _ => Err(Error::EncodeError),
        }
    }

    /// Encode this signatory into a Write.
    ///
    /// Returns errors if the Writer errors.
    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfSignatory::Ed25519(vec, _) => {
                varu64_encode(ED25519_NUMERIC_ID, &mut out[0..1]);
                varu64_encode(ED25519_SIZE as u64, &mut out[1..2]);
                w.write_all(&out).map_err(|_| Error::EncodeWriteError)?;
                w.write_all(vec.borrow())
                    .map_err(|_| Error::EncodeWriteError)?;
                Ok(())
            }
        }
    }

    pub fn encoding_length(&self) -> usize {
        match self {
            YamfSignatory::Ed25519(_, _) => {
                encoding_length(ED25519_NUMERIC_ID)
                    + encoding_length(ED25519_SIZE as u64)
                    + ED25519_SIZE
            }
        }
    }

    /// Attempt to decode a byte slice as a YamfSignatory.
    ///
    /// Returns errors if the provided byte slice was not long enough or if the incoding was
    /// invalid.
    pub fn decode(bytes: &'a [u8]) -> Result<(YamfSignatory<'a, &'a [u8]>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((ED25519_NUMERIC_ID, remaining_bytes)) if remaining_bytes.len() >= 33 => {
                let hash = &remaining_bytes[1..33];
                Ok((
                    YamfSignatory::Ed25519(hash.into(), None),
                    &remaining_bytes[33..],
                ))
            }
            Err((_, _)) => Err(Error::DecodeVaru64Error),
            _ => Err(Error::DecodeError {}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{YamfSignatory, ED25519_NUMERIC_ID, ED25519_SIZE};

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; ED25519_SIZE];
        let yamf_hash = YamfSignatory::Ed25519(&hash_bytes[..], None);
        //TODO: this test is not good, we need equality check between types.
        let _ = [
            ED25519_NUMERIC_ID as u8,
            ED25519_SIZE as u8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];

        let mut encoded = vec![0; ED25519_SIZE + 2];
        yamf_hash.encode(&mut encoded).unwrap();
        assert_eq!(encoded[0], ED25519_NUMERIC_ID as u8);
        assert_eq!(encoded[1], ED25519_SIZE as u8);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; ED25519_SIZE];
        let yamf_hash = YamfSignatory::Ed25519(&hash_bytes[..], None);
        //TODO: this test is not good, we need equality check between types.
        let _ = [
            ED25519_NUMERIC_ID as u8,
            ED25519_SIZE as u8,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
        ];

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
        let result = YamfSignatory::<&[u8]>::decode(&hash_bytes);

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

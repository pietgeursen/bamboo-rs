use crate::error::*;
#[cfg(feature = "std")]
use std::io::Write;

pub const ED25519_SIGNATURE_SIZE: usize = 64;
pub use ed25519_dalek::SIGNATURE_LENGTH;
// This is a way to hard code a value that cbindgen can use, but make sure at compile time
// that the value is actually correct.
const_assert_eq!(ed25519_sig_size; ED25519_SIGNATURE_SIZE, SIGNATURE_LENGTH);


/// The maximum number of bytes this will use.
pub const MAX_SIGNATURE_SIZE: usize = ED25519_SIGNATURE_SIZE;

#[cfg(feature = "std")]
use crate::util::hex_serde::{hex_from_bytes, vec_from_hex};
use core::borrow::Borrow;
#[cfg(feature = "std")]

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Signature<B: Borrow<[u8]>>(
    #[cfg_attr(
        feature = "std",
        serde(serialize_with = "hex_from_bytes", deserialize_with = "vec_from_hex")
    )]
    #[cfg_attr(feature = "std", serde(bound(deserialize = "B: From<Vec<u8>>")))]
    pub B,
);

impl<B: Borrow<[u8]>> Signature<B> {
    /// Little bit of sugar to get the signature length in bytes
    pub fn len(&self) -> usize {
        self.0.borrow().len()
    }

    // This is bit yuck that the out slice needs to be the right length.
    /// Encodes signature into `out`. `out` must be the same length as the inner slice.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {

        if out.len() < ED25519_SIGNATURE_SIZE {
            return Err(Error::EncodeError);
        }

        out[..ED25519_SIGNATURE_SIZE].copy_from_slice(&self.0.borrow());
        Ok(ED25519_SIGNATURE_SIZE)
    }

    pub fn encoding_length(&self) -> usize {
        self.len()
    }

    /// Encodes signature into a writer.
    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        w.write_all(&self.0.borrow()[..])
            .map_err(|_| Error::EncodeWriteError)?;
        Ok(())
    }

    pub fn decode<'a>(bytes: &'a [u8]) -> Result<(Signature<&'a [u8]>, &'a [u8]), Error> {
        match bytes {
            bytes if bytes.len() >= ED25519_SIGNATURE_SIZE as usize => Ok((
                Signature(bytes[..ED25519_SIGNATURE_SIZE].into()),
                &bytes[ED25519_SIGNATURE_SIZE as usize..],
            )),
            _ => Err(Error::DecodeError),
        }
    }
}

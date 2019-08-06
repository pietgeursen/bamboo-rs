use crate::error::*;
use ed25519_dalek::SIGNATURE_LENGTH;
#[cfg(feature = "std")]
use std::io::{Error as IoError, Write};

pub const ED25519_SIGNATURE_SIZE: usize = SIGNATURE_LENGTH;

#[cfg(feature = "std")]
use crate::util::hex_serde::{hex_from_bytes, vec_from_hex};
use core::borrow::Borrow;
use varu64::{
    decode as varu64_decode, encode as varu64_encode,
    encoding_length, DecodeError as varu64DecodeError,
};
#[cfg(feature = "std")]
use varu64::encode_write as varu64_encode_write;

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct Signature<B: Borrow<[u8]>>(
    #[cfg_attr(feature = "std", serde(serialize_with = "hex_from_bytes", deserialize_with = "vec_from_hex"))]
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
        let encoded_size = self.len() + encoding_length(self.len() as u64);

        if out.len() < encoded_size {
            return Err(Error::EncodeError);
        }

        varu64_encode(self.len() as u64, &mut out[0..]);

        out[1..encoded_size].copy_from_slice(&self.0.borrow());
        Ok(encoded_size)
    }

    pub fn encoding_length(&self) -> usize {
        self.len() + encoding_length(self.len() as u64)
    }

    /// Encodes signature into a writer.
    #[cfg(feature = "std")]
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        varu64_encode_write(self.len() as u64, &mut w).map_err(|_|Error::EncodeWriteError)?;
        w.write_all(&self.0.borrow()[..])
            .map_err(|_|Error::EncodeWriteError)?;
        Ok(())
    }

    pub fn decode<'a>(bytes: &'a [u8]) -> Result<(Signature<&'a [u8]>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((size, remaining_bytes)) if remaining_bytes.len() >= size as usize => Ok((
                Signature(remaining_bytes[..size as usize].into()),
                &remaining_bytes[size as usize..],
            )),
            Err((err, _)) => Err(Error::DecodeVaru64Error),
            _ => Err(Error::DecodeError),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Error, Signature};

    //These tests are not great because they know a lot about how the inside of varu64 works.
    //TODO: add tests that exercise the multibyte varu64 encoding, eg signatures > 255 bytes

    #[test]
    fn decode_signature() {
        let bytes = vec![0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA];
        let (sig, remaining) = Signature::<&[u8]>::decode(&bytes).unwrap();

        assert_eq!(sig.0.as_ref(), &[0xFF; 5]);
        assert_eq!(remaining, [0xAA]);
    }

    #[test]
    fn decode_signature_non_canonical() {
        let bytes = vec![248, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA];
        match Signature::<&[u8]>::decode(&bytes) {
            Err(Error::DecodeVaru64Error { source: _ }) => {}
            e => {
                println!("{:?}", e);
                panic!("expected an error")
            }
        }
    }

    #[test]
    fn decode_signature_not_enough_bytes() {
        let bytes = vec![0x05, 0xFF, 0xFF, 0xFF, 0xAA];
        match Signature::<&[u8]>::decode(&bytes) {
            Err(Error::DecodeError) => {}
            _ => panic!("expected an error"),
        }
    }

    #[test]
    fn encode_signature() {
        let bytes = vec![0xFF; 5];
        let sig = Signature::<&[u8]>(bytes[..].into());
        let mut out = vec![0; 6];
        sig.encode(&mut out).unwrap();

        assert_eq!(out, &[0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    #[test]
    fn encode_write_signature() {
        let bytes = vec![0xFF; 5];
        let sig = Signature::<&[u8]>(bytes[..].into());

        let mut out = Vec::new();
        sig.encode_write(&mut out).unwrap();
        assert_eq!(out, &[0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }
}

use snafu::{ResultExt, Snafu};
use std::io::{Error as IoError, Write};
use varu64::{
    decode as varu64_decode, encode as varu64_encode, encode_write as varu64_encode_write,
    DecodeError as varu64DecodeError,
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding var64 for signature. {}", source))]
    DecodeVaru64Error{source: varu64DecodeError} ,
    #[snafu(display("Error when decoding signature."))]
    DecodeError,
    #[snafu(display("IO Error when encoding signature to writer. {}", source))]
    EncodeWriteError{source: IoError} ,
}


#[derive(Debug)]
pub struct Signature<'a>(pub &'a [u8]);

impl<'a> Signature<'a> {
    /// Little bit of sugar to get the signature length in bytes
    pub fn len(&self) -> usize {
        self.0.len()
    }

    // This is bit yuck that the out slice needs to be the right length.
    /// Encodes signature into `out`. `out` must be the same length as the inner slice.
    pub fn encode(&self, out: &mut [u8]) {
        varu64_encode(self.0.len() as u64, &mut out[0..]);

        out[1..].copy_from_slice(&self.0);
    }

    /// Encodes signature into a writer.
    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        varu64_encode_write(self.len() as u64, &mut w).context(EncodeWriteError)?;
        w.write_all(&self.0).context(EncodeWriteError)?;
        Ok(())
    }

    pub fn decode(bytes: &'a [u8]) -> Result<(Signature<'a>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((size, remaining_bytes)) if remaining_bytes.len() >= size as usize => Ok((
                Signature(&remaining_bytes[..size as usize]),
                &remaining_bytes[size as usize..],
            )),
            Err((err, _)) => Err(Error::DecodeVaru64Error{source: err}),
            _ => Err(Error::DecodeError)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Signature;

    //These tests are not great because they know a lot about how the inside of varu64 works.
    //TODO: add tests that exercise the multibyte varu64 encoding, eg signatures > 255 bytes

    #[test]
    fn decode_signature() {
        let bytes = vec![0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA];
        let (sig, remaining) = Signature::decode(&bytes).unwrap();

        assert_eq!(sig.0, &[0xFF; 5]);
        assert_eq!(remaining, [0xAA]);
    }

    #[test]
    fn encode_signature() {
        let bytes = vec![0xFF; 5];
        let sig = Signature(&bytes);
        let mut out = vec![0; 6];
        sig.encode(&mut out);

        assert_eq!(out, &[0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }

    #[test]
    fn encode_write_signature() {
        let bytes = vec![0xFF; 5];
        let sig = Signature(&bytes);

        let mut out = Vec::new();
        sig.encode_write(&mut out).unwrap();
        assert_eq!(out, &[0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
    }
}

use super::hex_serde::{cow_from_hex, hex_from_cow};
use snafu::{ResultExt, Snafu};
use std::borrow::Cow;
use std::io::{Error as IoError, Write};
use varu64::{decode as varu64_decode, encode as varu64_encode, DecodeError as varu64DecodeError};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Error when decoding var64 for signatory. {}", source))]
    DecodeVaru64Error { source: varu64DecodeError },
    #[snafu(display("Error when decoding signatory."))]
    DecodeError,
    #[snafu(display("IO Error when encoding signatory to writer. {}", source))]
    EncodeWriteError { source: IoError },
}

#[derive(Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum YamfSignatory<'a> {
    /// Tuple of public and optional secret key
    Ed25519(
        #[serde(deserialize_with = "cow_from_hex", serialize_with = "hex_from_cow")] Cow<'a, [u8]>,
        #[serde(skip)] Option<&'a [u8]>,
    ),
}

impl<'a> YamfSignatory<'a> {
    pub fn encode(&self, out: &mut [u8]) {
        match self {
            YamfSignatory::Ed25519(vec, _) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(32, &mut out[1..2]);
                out[2..].copy_from_slice(&vec);
            }
        }
    }

    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfSignatory::Ed25519(vec, _) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(32, &mut out[1..2]);
                w.write_all(&out).context(EncodeWriteError)?;
                w.write_all(&vec).context(EncodeWriteError)?;
                Ok(())
            }
        }
    }

    pub fn decode(bytes: &'a [u8]) -> Result<(YamfSignatory<'a>, &'a [u8]), Error> {
        match varu64_decode(&bytes) {
            Ok((1, remaining_bytes)) if remaining_bytes.len() >= 33 => {
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
#[cfg_attr(tarpaulin, skip)]
mod tests {
    use super::YamfSignatory;

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfSignatory::Ed25519(hash_bytes.into(), None);
        let expected = [1, 32, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = vec![0; 6];
        yamf_hash.encode(&mut encoded);
        assert_eq!(encoded, expected);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfSignatory::Ed25519(hash_bytes.into(), None);
        let expected = [1, 32, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = Vec::new();
        yamf_hash.encode_write(&mut encoded).unwrap();
        assert_eq!(encoded, expected);
    }
    #[test]
    fn decode_yamf() {
        let mut hash_bytes = vec![0xFF; 35];
        hash_bytes[0] = 1;
        hash_bytes[1] = 32;
        hash_bytes[34] = 0xAA;
        let result = YamfSignatory::decode(&hash_bytes);

        match result {
            Ok((YamfSignatory::Ed25519(vec, _), remaining_bytes)) => {
                assert_eq!(vec.len(), 32);
                assert_eq!(vec, &hash_bytes[2..34]);
                assert_eq!(remaining_bytes, &[0xAA]);
            }
            _ => panic!(),
        }
    }
}

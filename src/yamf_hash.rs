use std::io::{Error, Write};
use varu64::{decode as varu64_decode, encode as varu64_encode, DecodeError};

pub enum YamfHash<'a> {
    Blake2b(&'a [u8]),
}

impl<'a> YamfHash<'a> {
    pub fn encode(&self, out: &mut [u8]) {
        match self {
            YamfHash::Blake2b(vec) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(64, &mut out[1..2]);
                out[2..].copy_from_slice(&vec);
            }
        }
    }

    pub fn encode_write<W: Write>(&self, mut w: W) -> Result<(), Error> {
        let mut out = [0; 2];
        match self {
            YamfHash::Blake2b(vec) => {
                varu64_encode(1, &mut out[0..1]);
                varu64_encode(64, &mut out[1..2]);
                w.write_all(&out)?;
                w.write_all(&vec)?;
                Ok(())
            }
        }
    }

    pub fn decode(bytes: &'a [u8]) -> Result<(YamfHash<'a>, &'a [u8]), DecodeError> {
        match varu64_decode(&bytes) {
            Ok((1, remaining_bytes)) => {
                let hash = &remaining_bytes[1..65];
                Ok((YamfHash::Blake2b(hash), &remaining_bytes[65..]))
            }
            Err((err, _)) => Err(err),
            _ => Err(DecodeError::NonCanonical(0)), // TODO fix the errors
        }
    }
}

#[cfg(test)]
mod tests {
    use super::YamfHash;

    #[test]
    fn encode_yamf() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(&hash_bytes);
        let expected = [1, 64, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = vec![0; 6];
        yamf_hash.encode(&mut encoded);
        assert_eq!(encoded, expected);
    }
    #[test]
    fn encode_yamf_write() {
        let hash_bytes = vec![0xFF; 4];
        let yamf_hash = YamfHash::Blake2b(&hash_bytes);
        let expected = [1, 64, 0xFF, 0xFF, 0xFF, 0xFF];

        let mut encoded = Vec::new();
        yamf_hash.encode_write(&mut encoded).unwrap();
        assert_eq!(encoded, expected);
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
}

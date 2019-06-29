use std::io::{Error, Write};
use varu64::{decode as varu64_decode, encode as varu64_encode};

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

    pub fn decode(bytes: &'a [u8]) -> YamfHash<'a> {
        match varu64_decode(&bytes).unwrap() {
            (1, _) => {
                let hash = &bytes[2..];
                assert_eq!(hash.len(), 64);
                YamfHash::Blake2b(hash)
            }
            _ => panic!("Unknown YamfHash type"),
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
        let mut hash_bytes = vec![0xFF; 66];
        hash_bytes[0] = 1;
        hash_bytes[1] = 64;
        let result = YamfHash::decode(&hash_bytes);

        match result {
            YamfHash::Blake2b(vec) => {
                assert_eq!(vec.len(), 64);
                assert_eq!(vec, &hash_bytes[2..]);
            }
        }
    }
}

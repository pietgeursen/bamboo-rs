use varu64::{decode as varu64_decode, encode as varu64_encode};

mod de;
mod ser;

pub use self::de::*;
pub use self::ser::*;

pub enum YamfHash {
    Blake2b(Vec<u8>),
}

impl YamfHash {
    /// Encode consumes YamfHash and returns a vec
    pub fn encode(mut self) -> Vec<u8> {
        match self {
            YamfHash::Blake2b(mut vec) => {
                let mut prefix_vec = vec![0u8; 2];

                varu64_encode(1, &mut prefix_vec[0..1]);
                varu64_encode(64, &mut prefix_vec[1..2]);

                prefix_vec.append(&mut vec);

                prefix_vec
            }
        }
    }
    pub fn decode(mut vec: Vec<u8>) -> YamfHash {
        match varu64_decode(&vec).unwrap() {
            (1, _) => {
                vec = vec.split_off(2);
                assert_eq!(vec.len(), 64);
                YamfHash::Blake2b(vec)
            }
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::YamfHash;

    #[test]
    fn encode_yamf() {
        let hashBytes = vec![0xFF; 4];
        let yamfHash = YamfHash::Blake2b(hashBytes);
        let expected = [1, 64, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(yamfHash.encode().as_slice(), expected);
    }
    #[test]
    fn decode_yamf() {
        let mut hashBytes = vec![0xFF; 66];
        hashBytes[0] = 1;
        hashBytes[1] = 64;
        let result = YamfHash::decode(hashBytes);

        match result {
            YamfHash::Blake2b(vec) => {
                assert_eq!(vec.len(), 64);
                assert_eq!(vec, vec![0xFF; 64]);
            }
            _ => panic!(),
        }
    }
}

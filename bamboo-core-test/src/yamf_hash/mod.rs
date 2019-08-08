#[cfg(test)]
mod tests {
    use bamboo_core::{Error, YamfHash, BLAKE2B_HASH_SIZE};
    use arrayvec::ArrayVec;
    use blake2b_simd::blake2b;
    use core::iter::FromIterator;

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
        hash_bytes[0] = 0;
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
        let _ = lam();
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
        let _ = lam();
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
        let _: YamfHash<&[u8]> = YamfHash::from(&result);
    }
}

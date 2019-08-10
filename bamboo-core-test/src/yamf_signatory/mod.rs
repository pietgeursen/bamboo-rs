#[cfg(test)]
mod tests {
    use bamboo_core::yamf_signatory::{YamfSignatory, ED25519_NUMERIC_ID, ED25519_SIZE};

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

#[cfg(test)]
mod tests {
    use bamboo_core::{Error, Signature};
    use bamboo_core::signature::ED25519_SIGNATURE_SIZE;

    #[test]
    fn decode_signature() {
        let bytes = vec![0x01; ED25519_SIGNATURE_SIZE + 1];
        let (sig, remaining) = Signature::<&[u8]>::decode(&bytes).unwrap();

        assert_eq!(sig.0.as_ref(), &bytes[..ED25519_SIGNATURE_SIZE]);
        assert_eq!(remaining, [0x01]);
    }

    #[test]
    fn decode_signature_not_enough_bytes() {
        let bytes = vec![0x00; ED25519_SIGNATURE_SIZE - 1];
        match Signature::<&[u8]>::decode(&bytes) {
            Err(Error::DecodeError) => {}
            _ => panic!("expected an error"),
        }
    }

    #[test]
    fn encode_signature() {
        let bytes = vec![0x00; ED25519_SIGNATURE_SIZE];
        let sig = Signature::<&[u8]>(bytes[..].into());
        let mut out = vec![0x00; ED25519_SIGNATURE_SIZE];
        sig.encode(&mut out).unwrap();

        assert_eq!(out, bytes)
    }

    #[test]
    fn encode_write_signature() {
        let bytes = vec![0x00; ED25519_SIGNATURE_SIZE];
        let sig = Signature::<&[u8]>(bytes[..].into());

        let mut out = Vec::new();
        sig.encode_write(&mut out).unwrap();
        assert_eq!(out, bytes)
    }
}

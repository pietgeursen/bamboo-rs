#[cfg(test)]
mod tests {
    use bamboo_core::{Error, Signature};

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
            Err(Error::DecodeVaru64Error) => {}
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

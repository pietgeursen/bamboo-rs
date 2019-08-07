
#[cfg(test)]
mod tests {

    use bamboo_core::{Entry, Signature, YamfHash, YamfSignatory};
    use bamboo_core::entry::decode;
    use bamboo_core::entry_store::MemoryEntryStore;
    use bamboo_core::yamf_hash::BLAKE2B_HASH_SIZE;
    use bamboo_core::{EntryStore, Log};
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use varu64::encode_write as varu64_encode_write;

    #[test]
    fn encode_decode_entry() {
        let backlink_bytes = [0xAA; BLAKE2B_HASH_SIZE];
        let backlink = YamfHash::<&[u8]>::Blake2b(backlink_bytes[..].into());
        let payload_hash_bytes = [0xAB; BLAKE2B_HASH_SIZE];
        let payload_hash = YamfHash::<&[u8]>::Blake2b(payload_hash_bytes[..].into());
        let lipmaa_link_bytes = [0xAC; BLAKE2B_HASH_SIZE];
        let lipmaa_link = YamfHash::<&[u8]>::Blake2b(lipmaa_link_bytes[..].into());
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes[..]);
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes[..], None);

        let mut entry_vec = Vec::new();

        entry_vec.push(1u8); // end of feed is true

        payload_hash.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(payload_size, &mut entry_vec).unwrap();
        author.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(seq_num, &mut entry_vec).unwrap();
        backlink.encode_write(&mut entry_vec).unwrap();
        lipmaa_link.encode_write(&mut entry_vec).unwrap();
        sig.encode_write(&mut entry_vec).unwrap();

        let entry = decode(&entry_vec).unwrap();

        match entry.payload_hash {
            YamfHash::Blake2b(ref hash) => {
                assert_eq!(hash.as_ref(), &payload_hash_bytes[..]);
            }
        }

        match entry.backlink {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &backlink_bytes[..]);
            }
            _ => panic!(),
        }
        match entry.lipmaa_link {
            Some(YamfHash::Blake2b(ref hash)) => {
                assert_eq!(hash.as_ref(), &lipmaa_link_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.sig {
            Some(Signature(ref sig)) => {
                assert_eq!(sig.as_ref(), &sig_bytes[..]);
            }
            _ => panic!(),
        }

        match entry.author {
            YamfSignatory::Ed25519(ref auth, None) => {
                assert_eq!(auth.as_ref(), &author_bytes[..]);
            }
            _ => panic!(),
        }

        let mut encoded = Vec::new();

        entry.encode_write(&mut encoded).unwrap();

        assert_eq!(encoded, entry_vec);
    }

    #[test]
    fn serde_entry() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );
        let payload = "hello bamboo!";
        log.publish(payload.as_bytes(), false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let entry = decode(entry_bytes).unwrap();

        let string = serde_json::to_string(&entry).unwrap();
        println!("{:?}", string);
        let parsed: Entry<Vec<u8>, Vec<u8>, Vec<u8>> = serde_json::from_str(&string).unwrap();

        assert_eq!(parsed.payload_hash, entry.payload_hash);
    }
}

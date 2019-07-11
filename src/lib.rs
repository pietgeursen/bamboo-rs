use blake2b_simd::blake2b;
use lipmaa_link::lipmaa;
use ssb_crypto::{sign_detached, PublicKey, SecretKey};

pub mod entry;
pub mod entry_store;
pub mod error;
pub mod memory_entry_store;
pub mod signature;
pub mod yamf_hash;
pub mod yamf_signatory;

use entry::Entry;
use entry_store::EntryStore;
pub use error::{Error, Result};
pub use memory_entry_store::MemoryEntryStore;
use signature::Signature;
use yamf_hash::YamfHash;
use yamf_signatory::YamfSignatory;

pub struct Log<Store: EntryStore> {
    pub store: Store,
    pub public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store, public_key: PublicKey, secret_key: Option<SecretKey>) -> Log<Store> {
        Log {
            store,
            public_key,
            secret_key,
        }
    }

    pub fn publish(&mut self, payload: &[u8], is_end_of_feed: bool) -> Result<()> {
        // get the last seq number
        let last_seq_num = self.store.get_last_seq();
        let author: YamfSignatory = YamfSignatory::Ed25519(self.public_key.as_ref(), None);

        // calc the payload hash
        let payload_hash_bytes = blake2b(payload);
        let payload_hash = YamfHash::Blake2b(payload_hash_bytes.as_bytes());
        let payload_size = payload.len() as u64;

        let seq_num = last_seq_num + 1;

        let mut entry = Entry {
            is_end_of_feed,
            payload_hash,
            payload_size,
            author,
            seq_num,
            backlink: None,
            lipmaa_link: None,
            sig: None,
        };

        if seq_num > 1 {
            let lipmaa_link_seq = lipmaa(seq_num as u32) as u64;

            // get the lipmaa entry
            let lipmaa_entry_bytes = self.store.get_entry_ref(lipmaa_link_seq)?.unwrap();
            // Calculate the hash of the lipmaa entry
            let lipmaa_hash_bytes = blake2b(lipmaa_entry_bytes);
            let lipmaa_link = YamfHash::Blake2b(lipmaa_hash_bytes.as_bytes());

            // get the backlink entry
            let backlink_bytes = self.store.get_last_entry_ref()?.unwrap();
            // calc the hash of the backlink entry
            let backlink_hash_bytes = blake2b(backlink_bytes);
            let backlink = YamfHash::Blake2b(backlink_hash_bytes.as_bytes());

            entry.backlink = Some(backlink);
            entry.lipmaa_link = Some(lipmaa_link);

            let mut buff = Vec::new();
            entry.encode_write(&mut buff).unwrap();

            let signature = sign_detached(&buff, self.secret_key.as_ref().unwrap());
            let signature = Signature(signature.as_ref());

            entry.sig = Some(signature);

            let mut vec = Vec::new();
            entry.encode_write(&mut vec).unwrap(); //TODO: error
            self.store.append_entry(&vec)
        } else {
            let mut buff = Vec::new();
            entry.encode_write(&mut buff).unwrap();

            let signature = sign_detached(&buff, self.secret_key.as_ref().unwrap());
            let signature = Signature(signature.as_ref());

            entry.sig = Some(signature);

            let mut vec = Vec::new();
            entry.encode_write(&mut vec).unwrap(); //TODO: error
            self.store.append_entry(&vec)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Entry, EntryStore, Log, MemoryEntryStore};
    use ssb_crypto::{generate_longterm_keypair, init};

    #[test]
    fn publish_and_verify_signature() {
        init();

        let (pub_key, secret_key) = generate_longterm_keypair();
        let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));
        let payload = [1, 2, 3];
        log.publish(&payload, false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let mut entry = Entry::decode(entry_bytes).unwrap();
        assert!(entry.verify_signature());
    }
}

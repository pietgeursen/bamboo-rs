use blake2b_simd::blake2b;
use lipmaa_link::lipmaa;
use snafu::Snafu;
use ssb_crypto::{
    init, sign_detached, verify_detached, PublicKey, SecretKey, Signature as SsbSignature,
};
use std::io::Write;
use std::path::PathBuf;
use varu64::DecodeError as varu64DecodeError;

pub mod entry;
pub mod signature;
pub mod yamf_hash;
pub mod yamf_signatory;

use entry::Entry;
use signature::Signature;
use yamf_hash::YamfHash;
use yamf_signatory::YamfSignatory;

// publish(content, getHashOfEntry) -> entry
// add(content, getHashOfEntry)
// getHashOfEntry(seq) -> hash
// getEntry(seq) -> entry

// verify(entry, getEntry)
// verifies:
// - signature
// - hashes and signatures of lipmaa link dependencies
// -

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid sequence number {}", seq_num))]
    GetEntrySequenceInvalid { seq_num: u64 },
    #[snafu(display("IO error when getting entry. {}: {}", filename.display(), source))]
    GetEntryIoError {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("IO error when appending entry. {}: {}", filename.display(), source))]
    AppendEntryIoError {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error when decoding entry. {}: {}", filename.display(), source))]
    DecodeError {
        filename: PathBuf,
        source: varu64DecodeError,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait EntryStore {
    fn get_last_seq(&self) -> u64;
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>>; // these are inconsistent. Should be an option?
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>>;
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>>;
    fn append_entry(&mut self, entry: &[u8]) -> Result<()>;
    fn get_writer_for_next_entry<'a>(&'a mut self) -> &'a mut dyn Write;
}

pub struct MemoryEntryStore {
    pub store: Vec<Vec<u8>>,
}

impl MemoryEntryStore {
    fn new() -> MemoryEntryStore {
        MemoryEntryStore { store: Vec::new() }
    }
}

impl EntryStore for MemoryEntryStore {
    fn get_last_seq(&self) -> u64 {
        self.store.len() as u64
    }
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>> {
        Ok(self.store[seq_num as usize - 1].clone())
    }
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>> {
        let result = self
            .store
            .get(seq_num as usize - 1)
            .map(|vec| vec.as_slice());
        Ok(result)
    }
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.store.last().map(|item| item.clone()))
    }
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>> {
        Ok(self.store.last().map(|item| &item[..]))
    }
    fn append_entry(&mut self, entry: &[u8]) -> Result<()> {
        let mut vec = Vec::with_capacity(entry.len());
        vec.extend_from_slice(entry);
        self.store.push(vec);
        Ok(())
    }
    fn get_writer_for_next_entry(&mut self) -> &mut dyn Write {
        let vec = Vec::new();
        self.store.push(vec);
        self.store.last_mut().unwrap()
    }
}

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
    use ssb_crypto::{
        generate_longterm_keypair, init, sign_detached, verify_detached, PublicKey, SecretKey,
        Signature as SsbSignature,
    };

    #[test]
    fn publish_and_verify_signature() {
        init();

        let (pub_key, secret_key) = generate_longterm_keypair();
        let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));
        let payload = [1, 2, 3];
        log.publish(&payload, false);

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let mut entry = Entry::decode(entry_bytes).unwrap();
        assert!(entry.verify_signature())
    }
}

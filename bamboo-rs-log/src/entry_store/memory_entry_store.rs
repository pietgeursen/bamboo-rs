use super::*;
use async_trait::async_trait;
use bamboo_rs_core::entry::decode;
pub use bamboo_rs_core::entry::decode::error::*;
use std::collections::HashMap;

use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum Error {}

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub struct MemoryEntryStore {
    pub store: HashMap<Vec<u8>, HashMap<u64, HashMap<u64, Vec<u8>>>>,
}

impl MemoryEntryStore {
    pub fn new() -> MemoryEntryStore {
        MemoryEntryStore {
            store: HashMap::new(),
        }
    }
    pub fn clear(&mut self) {
        self.store.clear()
    }
}

impl EntryStorer for MemoryEntryStore {
    fn get_last_seq(&self, public_key: PublicKey, log_id: u64) -> Option<u64> {
        self.store
            .get(&public_key.as_bytes().to_vec())
            .and_then(|logs| logs.get(&log_id))
            .and_then(|entries| entries.keys().max().map(|max| *max))
    }

    fn get_entries(
        &self,
        public_key: PublicKey,
        log_id: u64,
        seq_nums: &[u64],
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let result = seq_nums
            .iter()
            .map(|seq_num| {
                self.store
                    .get(&public_key.as_bytes().to_vec())
                    .and_then(|logs| logs.get(&log_id))
                    .and_then(|entries| entries.get(&seq_num).map(|bytes| bytes.to_vec()))
            })
            .collect();

        Ok(result)
    }

    fn get_entries_ref<'a>(
        &'a self,
        public_key: PublicKey,
        log_id: u64,
        seq_nums: &[u64],
    ) -> Result<Vec<Option<&'a [u8]>>> {
        let result = seq_nums
            .iter()
            .map(|seq_num| {
                self.store
                    .get(&public_key.as_bytes().to_vec())
                    .and_then(|logs| logs.get(&log_id))
                    .and_then(|entries| entries.get(&seq_num).map(|bytes| bytes.as_slice()))
            })
            .collect();

        Ok(result)
    }
    // TODO: what to do here: should entries be bytes or an Entry? Can we avoid mulitple entry
    // decodes?
    // Also this is just a memory thing so perfomance is not critical
    // But the api is important for actuall callers.. But then nothing will be slower than fileio
    // soooo?
    fn add_entries(
        &mut self,
        public_key: PublicKey,
        log_id: u64,
        entries: &[&[u8]],
    ) -> Result<()> {
        let public_key_bytes = public_key.as_bytes().to_vec();
        let entries_store = self
            .store
            .entry(public_key_bytes)
            .or_insert(HashMap::new())
            .entry(log_id)
            .or_insert(HashMap::new());

        entries
            .iter()
            .map(|entry| {
                let mut vec = Vec::with_capacity(entry.len());
                let decoded_entry = decode(&entry)?;
                vec.extend_from_slice(entry);
                entries_store.insert(decoded_entry.seq_num, vec);
                Ok(())
            })
            .collect::<Result<()>>()
            .ok()
            .ok_or_else(|| Error::AppendFailed)
    }
}

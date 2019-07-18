use std::collections::HashMap;
use super::entry_store::{EntryStore, Error, GetEntrySequenceInvalid, Result};
use snafu::ensure;

pub struct MemoryEntryStore {
    pub store: HashMap<u64, Vec<u8>>,
}

impl MemoryEntryStore {
    pub fn new() -> MemoryEntryStore {
        MemoryEntryStore { store: HashMap::new() }
    }
    pub fn clear(&mut self) {
        self.store.clear()
    }
}

impl EntryStore for MemoryEntryStore {
    fn get_last_seq(&self) -> u64 {
        self.store.len() as u64
    }
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>> {
        ensure!(seq_num > 0, GetEntrySequenceInvalid { seq_num });
        self.store
            .get(&seq_num)
            .map(|vec| vec.to_vec())
            .ok_or(Error::GetEntrySequenceInvalid { seq_num })
    }
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<&'a [u8]> {
        ensure!(seq_num != 0, GetEntrySequenceInvalid { seq_num });
        self.store
            .get(&seq_num)
            .map(|vec| vec.as_slice())
            .ok_or(Error::GetEntrySequenceInvalid { seq_num })
    }
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>> {
        self.store
            .keys()
            .max()
            .map(|max| self.get_entry(*max))
            .transpose()
    }
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>> {
        self.store
            .keys()
            .max()
            .map(|max| self.get_entry_ref(*max))
            .transpose()
    }
    fn add_entry(&mut self, entry: &[u8], seq_num: u64) -> Result<()> {
        let mut vec = Vec::with_capacity(entry.len());
        vec.extend_from_slice(entry);
        self.store.insert(seq_num, vec);
        Ok(())
    }
}

use super::*;
pub use bamboo_rs_core::error::*;
use std::collections::HashMap;

pub struct MemoryEntryStore {
    pub store: HashMap<u64, Vec<u8>>,
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

impl EntryStore for MemoryEntryStore {
    fn get_last_seq(&self) -> Option<u64> {
        self.store.keys().max().map(|max| *max)
    }
    fn get_entry(&self, seq_num: u64) -> Result<Option<Vec<u8>>> {
        if seq_num == 0 {
            return Ok(None);
        }
        let result = self.store.get(&seq_num).map(|vec| vec.to_vec());
        Ok(result)
    }
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>> {
        if seq_num == 0 {
            return Ok(None);
        }
        let result = self.store.get(&seq_num).map(|vec| vec.as_slice());
        Ok(result)
    }
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>> {
        match self.get_last_seq(){
            Some(seq) => self.get_entry(seq),
            None => Ok(None)
        }
    }
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>> {
        match self.get_last_seq(){
            Some(seq) => self.get_entry_ref(seq),
            None => Ok(None)
        }
    }
    fn add_entry(&mut self, entry: &[u8], seq_num: u64) -> Result<()> {
        let mut vec = Vec::with_capacity(entry.len());
        vec.extend_from_slice(entry);
        self.store.insert(seq_num, vec);
        Ok(())
    }
}

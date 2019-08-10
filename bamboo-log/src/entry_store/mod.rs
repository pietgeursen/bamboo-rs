use crate::error::Result;

#[cfg(feature = "std")]
pub mod memory_entry_store;
#[cfg(feature = "std")]
pub use memory_entry_store::*;

pub trait EntryStore {
    fn get_last_seq(&self) -> u64;
    #[cfg(feature = "std")]
    fn get_entry(&self, seq_num: u64) -> Result<Option<Vec<u8>>>;
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>>;
    #[cfg(feature = "std")]
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>>;
    fn add_entry(&mut self, entry: &[u8], seq_num: u64) -> Result<()>;
}

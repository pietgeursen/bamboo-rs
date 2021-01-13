pub mod memory_entry_store;
use snafu::AsErrorSource;
use core::fmt::Debug;
use core::fmt::Display;
pub use memory_entry_store::*;

pub trait EntryStore {
    type Error: Display + Debug + AsErrorSource;

    fn get_last_seq(&self) -> Option<u64>;
    fn get_entry(&self, seq_num: u64) -> Result<Option<Vec<u8>>, Self::Error>;
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>, Self::Error>;
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>, Self::Error>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>, Self::Error>;
    fn add_entry(&mut self, entry: &[u8], seq_num: u64) -> Result<(), Self::Error>;
}

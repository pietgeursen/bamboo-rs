use super::Result;
use std::io::Write;

pub trait EntryStore {
    fn get_last_seq(&self) -> u64;
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>>; // these are inconsistent. Should be an option?
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>>;
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>>;
    fn append_entry(&mut self, entry: &[u8]) -> Result<()>;
    fn get_writer_for_next_entry<'a>(&'a mut self) -> &'a mut dyn Write;
}

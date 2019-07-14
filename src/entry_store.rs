use snafu::Snafu;
use std::io::Write;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display(
        "Invalid sequence number, sequences start at 1, got sequence: {}",
        seq_num
    ))]
    GetEntrySequenceInvalid { seq_num: u64 },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub trait EntryStore {
    fn get_last_seq(&self) -> u64;
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>>;
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<&'a [u8]>;
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>>;
    fn append_entry(&mut self, entry: &[u8]) -> Result<()>;
    fn get_writer_for_next_entry<'a>(&'a mut self) -> &'a mut dyn Write;
    //fn get_writer_for_entry_num<'a>(&'a mut self, seq_num: u64) -> &'a mut dyn Write;
}

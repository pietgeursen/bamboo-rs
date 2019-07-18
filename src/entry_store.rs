use snafu::Snafu;

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
    fn add_entry(&mut self, entry: &[u8], seq_num: u64) -> Result<()>;
}

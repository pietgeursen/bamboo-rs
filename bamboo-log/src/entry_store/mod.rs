use bamboo_core::error::Result;
use bamboo_core::PublicKey;

pub mod memory_entry_store;
pub use memory_entry_store::*;

/// A Place to store Bamboo Entries.
///
/// Note that it doesn't store / retrieve payloads.
pub trait EntryStorer {

    fn get_last_seq(&self, public_key: PublicKey, log_id: u64) -> Option<u64>;

    /// get_entries should return the same number of results as seq_nums.len()
    fn get_entries(
        &self,
        public_key: PublicKey,
        log_id: u64,
        seq_nums: &[u64],
    ) -> Result<Vec<Option<Vec<u8>>>>;

    /// get_entries ref should return the same number of results as seq_nums.len()
    fn get_entries_ref<'a>(
        &'a self,
        public_key: PublicKey,
        log_id: u64,
        seq_nums: &[u64],
    ) -> Result<Vec<Option<&'a [u8]>>>;

    /// Convenience method to just get one entry, uses get_entries_ref.
    fn get_entry(
        &self,
        public_key: PublicKey,
        log_id: u64,
        seq_num: u64,
    ) -> Result<Option<Vec<u8>>> {
        let entry = self.get_entries_ref(public_key, log_id, &[seq_num])?[0]
            .as_ref()
            .map(|entry| entry.to_vec());
        Ok(entry)
    }

    /// Convenience method to just get one entry ref, uses get_entries_ref.
    fn get_entry_ref<'a>(
        &'a self,
        public_key: PublicKey,
        log_id: u64,
        seq_num: u64,
    ) -> Result<Option<& 'a [u8]>> {
        let entry = self.get_entries_ref(public_key, log_id, &[seq_num])?[0];
        Ok(entry)
    }

    fn add_entries(
        &mut self,
        public_key: PublicKey,
        log_id: u64,
        entries: &[&[u8]],
    ) -> Result<()>;

    // TODO consider adding a method for storing info about broken feeds. Also ended feeds?
    // - Feeds can be forked
    // - Feeds can be tombstoned
    // - ?
}

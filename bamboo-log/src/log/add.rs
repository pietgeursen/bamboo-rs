use super::Log;
use crate::entry_store::EntryStorer;
use bamboo_core::entry::decode;
use bamboo_core::entry::verify;
use bamboo_core::error::*;
use bamboo_core::lipmaa;

impl<Store: EntryStorer> Log<Store> {
    /// Add a valid message to the Log.
    ///
    /// Typically you would use this when you have an entry published by some other author and you
    /// want to add it to your store. This checks to make sure the entry
    /// is legit.
    ///
    /// Caveat:
    /// - the lipmaa link that this message references must already exist in the Log. That means if you
    /// are doing partial replication, you must sort your messages by sequence number and add them
    /// from oldest to newest.

    // TODO batch? Also, it they're batched then we can sort them here
    // What if we changed the types of entry bytes to be a new type that validates that it's all.
    // Actually the public api should be slices of bytes and we do the validation and implement
    // private methods that are more like the domain level that do expect valid types.
    // from a given author + feed id and sorts them by seq.
    // even better would be to be able to throw all messages from all authors and have this sort it for you.
    //
    // Need to decide how to handle broken feeds.
    // - Should entry store expose methods to record broken feeds?
    // - Should entry store expose stuff to handle storing payloads too which can be overridden?
    pub fn add_batch(&mut self, entry_bytes: &[u8], payload: Option<&[u8]>) -> Result<()> {
        // Decode the entry that we want to add.
        let entry = decode(entry_bytes).map_err(|_| Error::AddEntryDecodeFailed)?;

        let lipmaa_seq = match lipmaa(entry.seq_num) {
            0 => 1,
            n => n,
        };

        // Get the lipmaa entry and the backlink entry
        let links = self
            .store
            .get_entries_ref(entry.author, entry.log_id, &[lipmaa_seq, entry.seq_num - 1])?;

        // TODO how do we detect a fork?
        let is_valid = verify(entry_bytes, payload, links[0], links[1])?;

        if !is_valid {
            return Err(Error::AddEntryWithInvalidSignature);
        }

        //Ok, store it!
        self.store
            .add_entries(entry.author, entry.log_id, &[entry_bytes])
            .map_err(|_| Error::AppendFailed)
    }
}

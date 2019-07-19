use super::error::*;
use super::Log;
pub use crate::entry_store::{EntryStore, Error as EntryStoreError};

impl<Store: EntryStore> Log<Store> {
    /// Add a valid message to the Log.
    ///
    /// Caveat:
    /// - the lipmaa link that this message references must already exist in the Log. That means if you
    /// are doing partial replication, you must sort your messages by sequence number and add them
    /// from oldest to newest.
    pub fn add(&mut self, entry: &u8, payload: Option<&u8>) -> Result<()> {
        // Decode the entry that we want to add.

        // If we have the payload, check that its hash and length match what is encoded in the
        // entry.

        // Get the lipmaa entry.
        //
        // Hash the lipmaa entry
        //
        // Make sure the lipmaa entry hash matches what's in the entry.
        //
        // Try and get the backlink entry. If we have it, hash it and check it is correct.
        //
        // Verify the author is the same as the author in the lipmaa link entry
        //
        // Get the last entry in the log and make sure it's not an end of feed message.
        //
        // Verify the signature.
        unimplemented!()
    }
}

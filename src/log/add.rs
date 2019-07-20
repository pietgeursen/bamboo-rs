use super::error::*;
use super::Log;
use crate::entry_store::{EntryStore};
use crate::yamf_hash::YamfHash;
use crate::Entry;
use lipmaa_link::lipmaa;
use snafu::{ensure, ResultExt};

impl<Store: EntryStore> Log<Store> {
    /// Add a valid message to the Log.
    ///
    /// Caveat:
    /// - the lipmaa link that this message references must already exist in the Log. That means if you
    /// are doing partial replication, you must sort your messages by sequence number and add them
    /// from oldest to newest.
    pub fn add(&mut self, entry_bytes: &[u8], payload: Option<&[u8]>) -> Result<()> {
        // Decode the entry that we want to add.
        let entry = Entry::decode(entry_bytes).context(AddEntryDecodeFailed)?;

        // If we have the payload, check that its hash and length match what is encoded in the
        // entry.
        if let Some(payload) = payload {
            let payload_hash = YamfHash::new_blake2b(payload);
            ensure!(
                payload_hash == entry.payload_hash,
                AddEntryPayloadHashDidNotMatch
            );
            ensure!(
                payload.len() as u64 == entry.payload_size,
                AddEntryPayloadLengthDidNotMatch
            );
        }

        // Get the lipmaa entry.
        let lipmaa = self
            .store
            .get_entry_ref(lipmaa(entry.seq_num))
            .context(AddEntryGetLipmaalinkError)?;

        match (lipmaa, entry.lipmaa_link) {
            (Some(lipmaa), Some(entry_lipmaa)) => {
                // Hash the lipmaa entry
                let lipmaa_hash = YamfHash::new_blake2b(lipmaa);
                // Make sure the lipmaa entry hash matches what's in the entry.
                ensure!(lipmaa_hash == entry_lipmaa, AddEntryPayloadHashDidNotMatch);
                // Verify the author of the entry is the same as the author in the lipmaa link entry
                ensure!(
                    entry.author
                        == Entry::decode(lipmaa)
                            .expect("Error decoding entry from store, maybe the store is corrupt")
                            .author,
                    AddEntryAuthorDidNotMatchLipmaaEntry
                );
            }
            (_, None) => {
                // The entry did not have a lipmaa link encoded when it should
                ensure!(entry.seq_num == 1, AddEntryNoLipmaalinkOnEntry)
            }
            (None, _) => {
                // We didn't have it in the store
                ensure!(false, AddEntryNoLipmaalinkInStore)
            }
        };

        // Try and get the backlink entry. If we have it, hash it and check it is correct.
        let backlink = self
            .store
            .get_entry_ref(entry.seq_num - 1)
            .context(AddEntryGetBacklinkError)?;

        if let (Some(backlink), Some(entry_backlink)) = (backlink, entry.backlink) {
            let backlink_hash = YamfHash::new_blake2b(backlink);
            ensure!(
                backlink_hash == entry_backlink,
                AddEntryBacklinkHashDidNotMatch
            )
        }

        // Get the last entry in the log and make sure it's not an end of feed message.
        // Only do this check if the store isn't empty.
        if self.store.get_last_seq() > 0 {
            let last_entry_bytes = self
                .store
                .get_last_entry_ref()
                .context(AddEntryGetLastEntryError)?
                .expect("couldn't get last entry, is the store corrupt?");

            let last_entry = Entry::decode(last_entry_bytes).expect("Unable to decode last entry in store, is it corrupt?");
            ensure!(!last_entry.is_end_of_feed, AddEntryToFeedThatHasEnded)
        }
        
        // Verify the signature.
        let entry_bytes_to_verify = entry_bytes.to_owned();
        let mut entry_to_verify = Entry::decode(&entry_bytes_to_verify).unwrap(); 
        ensure!(entry_to_verify.verify_signature(), AddEntryWithInvalidSignature);

        //Ok, store it!
        self.store.add_entry(&entry_bytes, entry.seq_num).context(AppendFailed)
    }
}

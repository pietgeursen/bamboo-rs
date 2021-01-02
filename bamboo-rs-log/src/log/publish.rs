use core::fmt::Debug;
use lipmaa_link::lipmaa;

use crate::entry_store::EntryStore;
use bamboo_rs_core::entry::publish;
use snafu::ResultExt;
use bamboo_rs_core::entry::{publish, MAX_ENTRY_SIZE};
use bamboo_rs_core::entry::*;
use bamboo_rs_core::lipmaa;

use super::Log;
use super::error::*;

impl<Store: EntryStore + Debug> Log<Store> {
    pub fn publish(&mut self, payload: &[u8], is_end_of_feed: bool) -> Result<(), Error<Store>> {
        let mut buff = [0u8; 512];

        let last_seq_num = self.store.get_last_seq();
        let seq_num = last_seq_num.unwrap_or(0) + 1;
        let lipmaa_link_seq = lipmaa(seq_num);

        let lipmaa_entry_bytes = self
            .store
            .get_entry_ref(lipmaa_link_seq)
            .context(PublishEntryGetLipmaaEntry)?;

        let backlink_bytes = self
            .store
            .get_entry_ref(last_seq_num.unwrap_or(0))
            .context(PublishEntryGetBacklinkEntry)?;
=======
impl<Store: EntryStorer> Log<Store> {
    pub fn publish(
        &mut self,
        payload: &[u8],
        log_id: u64,
        is_end_of_feed: bool,
    ) -> Result<()> {
        let mut buff = [0u8; MAX_ENTRY_SIZE];
        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or_else(|| Error::PublishWithoutKeypair)?;

        let last_seq_num = self.store.get_last_seq(key_pair.public, log_id);
        let seq_num = last_seq_num.unwrap_or(0) + 1;
        let lipmaa_link_seq = lipmaa(seq_num);

        let links = self
            .store
            .get_entries_ref(
                key_pair.public,
                log_id,
                &[lipmaa_link_seq, last_seq_num.unwrap_or(0)],
            )
            .map_err(|_| Error::GetEntryFailed)?;
>>>>>>> 38bf8e64 (Re-write the bamboo store):bamboo-log/src/log/publish.rs

        let length = publish(
            &mut buff,
            self.key_pair.as_ref(),
            log_id,
            payload,
            is_end_of_feed,
            last_seq_num,
            links[0],
            links[1],
        )
        .context(PublishNewEntryFailed)?;

        self.store
<<<<<<< HEAD:bamboo-rs-log/src/log/publish.rs
            .add_entry(&buff[..length], seq_num)
            .context(PublishEntryAppendFailed)
=======
            .add_entries(key_pair.public, log_id, &[&buff[..length]])
            .map_err(|_| Error::AppendFailed)
>>>>>>> 38bf8e64 (Re-write the bamboo store):bamboo-log/src/log/publish.rs
    }
}

#[cfg(test)]
mod tests {
    use crate::entry_store::EntryStorer;
    use crate::entry_store::MemoryEntryStore;
<<<<<<< HEAD:bamboo-rs-log/src/log/publish.rs
    use crate::log::{Log, Error};
    use crate::EntryStore;
    use bamboo_rs_core::entry::decode;
    use bamboo_rs_core::{Keypair};
=======
    use crate::log::Log;
    use bamboo_core::entry::decode;
    use bamboo_core::{Error, Keypair};
>>>>>>> 38bf8e64 (Re-write the bamboo store):bamboo-log/src/log/publish.rs

    use rand::rngs::OsRng;

    #[test]
    fn publish_and_verify_signature() {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let public_key = keypair.public.clone();
        let log_id = 0;

        let mut log = Log::new(MemoryEntryStore::new(), Some(keypair));
        let payload = [1, 2, 3];
        log.publish(&payload, log_id, false).unwrap();
        let entry = log
            .store
            .get_entry_ref(public_key, log_id, 1)
            .unwrap()
            .unwrap();

        let entry = decode(entry).unwrap();
        assert!(entry.verify_signature().unwrap());
    }

    #[test]
    fn publish_after_an_end_of_feed_message_errors() {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let log_id = 0;

        let mut log = Log::new(MemoryEntryStore::new(), Some(keypair));
        let payload = [1, 2, 3];

        //publish an end of feed message.
        log.publish(&payload, log_id, true).unwrap();
        match log.publish(&payload, log_id, false) {
            Err(Error::PublishNewEntryFailed) => {}
            e => panic!("expected publish to fail with an error, got: {:?}", e),
        }
    }

    #[test]
    fn publish_without_secret_key_errors() {
        let log_id = 0;

        let mut log = Log::new(MemoryEntryStore::new(), None);
        let payload = [1, 2, 3];

        match log.publish(&payload, log_id, false) {
            Err(Error::PublishWithoutKeypair) => {}
            e => panic!("expected publish to fail with an error, got: {:?}", e),
        }
    }
}

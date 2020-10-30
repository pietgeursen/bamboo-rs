use core::fmt::Debug;
use lipmaa_link::lipmaa;

use crate::entry_store::EntryStore;
use bamboo_rs_core::entry::publish;
use snafu::ResultExt;

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

        let length = publish(
            &mut buff,
            self.key_pair.as_ref(),
            self.log_id,
            payload,
            is_end_of_feed,
            last_seq_num,
            lipmaa_entry_bytes,
            backlink_bytes,
        )
        .context(PublishNewEntryFailed)?;

        self.store
            .add_entry(&buff[..length], seq_num)
            .context(PublishEntryAppendFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry_store::MemoryEntryStore;
    use crate::log::{Log, Error};
    use crate::EntryStore;
    use bamboo_rs_core::entry::decode;
    use bamboo_rs_core::{Keypair};

    use rand::rngs::OsRng;

    #[test]
    fn publish_and_verify_signature() {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let log_id = 0;

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
            log_id,
        );
        let payload = [1, 2, 3];
        log.publish(&payload, false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let mut entry = decode(entry_bytes).unwrap();
        assert!(entry.verify_signature().unwrap());
    }

    #[test]
    fn publish_after_an_end_of_feed_message_errors() {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let log_id = 0;

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
            log_id,
        );
        let payload = [1, 2, 3];

        //publish an end of feed message.
        log.publish(&payload, true).unwrap();

        match log.publish(&payload, false) {
            Err(Error::PublishNewEntryFailed) => {}
            _ => panic!("expected publish to fail with an error"),
        }
    }

    #[test]
    fn publish_without_secret_key_errors() {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let log_id = 0;

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            None,
            log_id,
        );
        let payload = [1, 2, 3];

        match log.publish(&payload, false) {
            Err(Error::PublishNewEntryFailed) => {}
            e => panic!("expected publish to fail with an error, got: {:?}", e),
        }
    }
}

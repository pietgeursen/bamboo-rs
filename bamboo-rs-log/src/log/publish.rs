use core::fmt::Debug;

use super::error::*;
use crate::entry_store::EntryStorer;
use bamboo_rs_core::entry::{publish, MAX_ENTRY_SIZE};
use bamboo_rs_core::lipmaa;
use snafu::ResultExt;

use super::Log;

impl<Store: EntryStorer + Debug> Log<Store> {
    pub fn publish(
        &mut self,
        payload: &[u8],
        log_id: u64,
        is_end_of_feed: bool,
    ) -> Result<(), Error<Store>> {
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
            .context(PublishEntryGetLipmaaAndBacklinkEntries)?;

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
            .add_entries(key_pair.public, log_id, &[&buff[..length]])
            .context(PublishEntryAppendFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry_store::EntryStorer;
    use crate::entry_store::MemoryEntryStore;
    use crate::log::{Log};
    use bamboo_rs_core::entry::{verify};
    use bamboo_rs_core::Keypair;

    use rand::rngs::OsRng;

    use bamboo_rs_core::entry::verify::Error as VerifyError;
    use bamboo_rs_core::{lipmaa, Entry};
    use std::convert::TryFrom;

    fn n_valid_entries(n: u64) -> Log<MemoryEntryStore> {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(MemoryEntryStore::new(), Some(key_pair));

        (1..n + 1).into_iter().for_each(|i| {
            let payload = format!("message number {}", i);
            log.publish(&payload.as_bytes(), 0, false).unwrap();
        });

        log
    }
    #[test]
    fn publish_and_verify_10_entries() {
        let log = n_valid_entries(10);
        println!("{:?}", log);
        let public_key = log.key_pair.as_ref().unwrap().public.clone();

        log.store
            .get_entries(public_key, 0, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
            .unwrap()
            .iter()
            .map(|bytes| bytes.as_ref().unwrap())
            .map(|bytes| {
                let entry = Entry::try_from(bytes.as_slice()).unwrap();
                let backlink = log
                    .store
                    .get_entry_ref(public_key, 0, entry.seq_num - 1)
                    .unwrap();
                let lipmaalink = log
                    .store
                    .get_entry_ref(public_key, 0, lipmaa(entry.seq_num))
                    .unwrap();
                verify(&bytes, None, lipmaalink, backlink)
            })
            .collect::<Result<(), VerifyError>>()
            .unwrap();
    }
}

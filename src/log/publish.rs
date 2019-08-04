use lipmaa_link::lipmaa;

use super::error::*;
use crate::entry::{decode, Entry};
use crate::entry_store::EntryStore;
use crate::signature::Signature;
use crate::yamf_hash::new_blake2b;
use crate::yamf_signatory::YamfSignatory;
use snafu::{ensure, ResultExt};

use super::Log;

impl<Store: EntryStore> Log<Store> {
    pub fn publish(&mut self, payload: &[u8], is_end_of_feed: bool) -> Result<()> {
        let mut buff = [0u8; 512];

        let last_seq_num = self.store.get_last_seq();
        let seq_num = last_seq_num + 1;
        let lipmaa_link_seq = lipmaa(seq_num);

        let lipmaa_entry_bytes =
            self.store
                .get_entry_ref(lipmaa_link_seq)
                .context(GetEntryFailed {
                    seq_num: lipmaa_link_seq,
                })?;
        let backlink_bytes = self
            .store
            .get_entry_ref(last_seq_num)
            .context(GetEntryFailed {
                seq_num: last_seq_num,
            })?;

        let length = Entry::<&[u8], &[u8], &[u8]>::publish(
            &mut buff,
            &self.key_pair,
            &self.public_key,
            payload,
            is_end_of_feed,
            last_seq_num,
            lipmaa_entry_bytes,
            backlink_bytes,
        )
        .context(PublishNewEntryFailed)?;

        self.store
            .add_entry(&buff[..length], seq_num)
            .context(AppendFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::entry::decode;
    use crate::entry_store::MemoryEntryStore;
    use crate::log::{Error, Log};
    use crate::EntryStore;

    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    #[test]
    fn publish_and_verify_signature() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );
        let payload = [1, 2, 3];
        log.publish(&payload, false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let mut entry = decode(entry_bytes).unwrap();
        assert!(entry.verify_signature().unwrap());
    }
    #[test]
    fn publish_after_an_end_of_feed_message_errors() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );
        let payload = [1, 2, 3];

        //publish an end of feed message.
        log.publish(&payload, true).unwrap();

        match log.publish(&payload, false) {
            Err(Error::PublishNewEntryFailed {
                source: crate::entry::Error::PublishAfterEndOfFeed { backtrace: _ },
            }) => {}
            _ => panic!("expected publish to fail with an error"),
        }
    }
    #[test]
    fn publish_without_secret_key_errors() {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(MemoryEntryStore::new(), keypair.public.clone(), None);
        let payload = [1, 2, 3];

        match log.publish(&payload, false) {
            Err(Error::PublishNewEntryFailed {
                source: crate::entry::Error::TriedToPublishWithoutSecretKey,
            }) => {}
            e => panic!("expected publish to fail with an error, got: {:?}", e),
        }
    }
}

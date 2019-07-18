#[macro_use]
extern crate serde_derive;

extern crate serde_json;

use lipmaa_link::lipmaa;
use ssb_crypto::{sign_detached, PublicKey, SecretKey};
use std::borrow::Cow;

pub mod entry;
pub mod entry_store;
mod hex_serde;
pub mod memory_entry_store;
pub mod signature;
pub mod yamf_hash;
pub mod yamf_signatory;

pub use entry::{Entry, Error as EntryError};
pub use entry_store::{EntryStore, Error as EntryStoreError};
pub use memory_entry_store::MemoryEntryStore;
pub use signature::Signature;
use snafu::{ensure, Backtrace, ResultExt, Snafu};
use yamf_hash::YamfHash;
use yamf_signatory::YamfSignatory;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display(
        "Invalid sequence number, it might not exist or it might be 0. Sequences start at 1. Got sequence: {}",
        seq_num
    ))]
    GetEntryFailed {
        seq_num: u64,
        source: EntryStoreError,
    },
    #[snafu(display(
        "Error unwrapping a None value of the secret key, it must be provided in the constructor"
    ))]
    TriedToPublishWithoutSecretKey,
    #[snafu(display("Failed to encode the entry for signing"))]
    EncodingForSigningFailed { source: EntryError },
    #[snafu(display("Failed to encode the entry for storing in the log"))]
    EncodingForStoringFailed { source: EntryError },
    #[snafu(display("Failed to append the entry to the log"))]
    AppendFailed { source: EntryStoreError },
    #[snafu(display(
        "Attempted to publish a message on a feed that has published an end of feed message"
    ))]
    PublishAfterEndOfFeed { backtrace: Backtrace },
    #[snafu(display("Failed to decode the previous message as an entry"))]
    PreviousDecodeFailed { source: EntryError },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub struct Log<Store: EntryStore> {
    pub store: Store,
    pub public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store, public_key: PublicKey, secret_key: Option<SecretKey>) -> Log<Store> {
        Log {
            store,
            public_key,
            secret_key,
        }
    }

    pub fn publish(&mut self, payload: &[u8], is_end_of_feed: bool) -> Result<()> {
        // get the last seq number
        let last_seq_num = self.store.get_last_seq();
        let author: YamfSignatory =
            YamfSignatory::Ed25519(Cow::Owned(self.public_key.as_ref().to_vec()), None);

        // calc the payload hash
        let payload_hash = YamfHash::new_blake2b(payload);
        let payload_size = payload.len() as u64;

        let seq_num = last_seq_num + 1;

        let mut entry = Entry {
            is_end_of_feed,
            payload_hash,
            payload_size,
            author,
            seq_num,
            backlink: None,
            lipmaa_link: None,
            sig: None,
        };

        // if the seq is larger than 1, we need to append the lipmaa and backlink hashes.
        if seq_num > 1 {
            let lipmaa_link_seq = lipmaa(seq_num);

            let lipmaa_entry_bytes =
                self.store
                    .get_entry_ref(lipmaa_link_seq)
                    .context(GetEntryFailed {
                        seq_num: lipmaa_link_seq,
                    })?;

            let lipmaa_link = YamfHash::new_blake2b(lipmaa_entry_bytes);

            let backlink_bytes = self
                .store
                .get_last_entry_ref()
                .context(GetEntryFailed {
                    seq_num: lipmaa_link_seq,
                })?
                .unwrap();

            //Make sure we're not trying to publish after the end of a feed.
            let backlink_entry =
                Entry::decode(&backlink_bytes[..]).context(PreviousDecodeFailed)?;
            ensure!(!backlink_entry.is_end_of_feed, PublishAfterEndOfFeed);

            let backlink = YamfHash::new_blake2b(backlink_bytes);

            entry.backlink = Some(backlink);
            entry.lipmaa_link = Some(lipmaa_link);
        }

        let mut buff = Vec::new();
        entry
            .encode_write(&mut buff)
            .context(EncodingForSigningFailed)?;

        let secret = self
            .secret_key
            .as_ref()
            .ok_or(Error::TriedToPublishWithoutSecretKey)?;

        let signature = sign_detached(&buff, secret);
        let signature = Signature(signature.as_ref().into());

        entry.sig = Some(signature);

        let mut buff = Vec::new();
        entry
            .encode_write(&mut buff)
            .context(EncodingForStoringFailed)?;

        self.store.add_entry(&buff, seq_num).context(AppendFailed)
    }
}

#[cfg(test)]
mod tests {
    use crate::{Entry, EntryStore, Error, Log, MemoryEntryStore};
    use ssb_crypto::{generate_longterm_keypair, init};

    #[test]
    fn publish_and_verify_signature() {
        init();

        let (pub_key, secret_key) = generate_longterm_keypair();
        let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));
        let payload = [1, 2, 3];
        log.publish(&payload, false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap();

        let mut entry = Entry::decode(entry_bytes).unwrap();
        assert!(entry.verify_signature());
    }
    #[test]
    fn publish_after_an_end_of_feed_message_errors() {
        init();

        let (pub_key, secret_key) = generate_longterm_keypair();
        let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));
        let payload = [1, 2, 3];

        //publish an end of feed message.
        log.publish(&payload, true).unwrap();

        match log.publish(&payload, false) {
            Err(Error::PublishAfterEndOfFeed { backtrace: _ }) => {}
            _ => panic!("expected publish to fail with an error"),
        }
    }
    #[test]
    fn publish_without_secret_key_errors() {
        init();

        let (pub_key, _) = generate_longterm_keypair();
        let mut log = Log::new(MemoryEntryStore::new(), pub_key, None);
        let payload = [1, 2, 3];

        match log.publish(&payload, false) {
            Err(Error::TriedToPublishWithoutSecretKey) => {}
            _ => panic!("expected publish to fail with an error"),
        }
    }
}

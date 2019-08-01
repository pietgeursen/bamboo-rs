use lipmaa_link::lipmaa;

use super::error::*;
use crate::entry::{decode, Entry};
use crate::entry_store::EntryStore;
use crate::signature::{Signature};
use crate::yamf_hash::new_blake2b;
use crate::yamf_signatory::YamfSignatory;
use snafu::{ensure, ResultExt};

use super::Log;

impl<Store: EntryStore> Log<Store> {
    pub fn publish(&mut self, payload: &[u8], is_end_of_feed: bool) -> Result<()> {
        // get the last seq number
        let last_seq_num = self.store.get_last_seq();

        let author = YamfSignatory::<&[u8]>::Ed25519(&self.public_key.as_bytes()[..], None);

        // calc the payload hash
        let payload_hash = new_blake2b(payload);
        let payload_size = payload.len() as u64;

        let seq_num = last_seq_num + 1;

        let mut entry : Entry<_,_,&[u8]> = Entry {
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

            let lipmaa_entry_bytes = self
                .store
                .get_entry_ref(lipmaa_link_seq)
                .context(GetEntryFailed {
                    seq_num: lipmaa_link_seq,
                })?
                .ok_or(Error::EntryNotFound {
                    seq_num: lipmaa_link_seq,
                })?;

            let lipmaa_link = new_blake2b(lipmaa_entry_bytes);

            let backlink_bytes = self
                .store
                .get_last_entry_ref()
                .context(GetEntryFailed {
                    seq_num: lipmaa_link_seq,
                })?
                .unwrap();

            //Make sure we're not trying to publish after the end of a feed.
            let backlink_entry = decode(&backlink_bytes[..]).context(PreviousDecodeFailed)?;
            ensure!(!backlink_entry.is_end_of_feed, PublishAfterEndOfFeed);

            let backlink = new_blake2b(backlink_bytes);

            entry.backlink = Some(backlink);
            entry.lipmaa_link = Some(lipmaa_link);
        }

        let mut buff = [0u8; 512];
        let buff_size = entry
            .encode(&mut buff)
            .context(EncodingForSigningFailed)?;

        let key_pair = self
            .key_pair
            .as_ref()
            .ok_or(Error::TriedToPublishWithoutSecretKey)?;

        let signature = key_pair.sign(&buff[..buff_size]);
        let sig_bytes = &signature.to_bytes()[..];
        let signature = Signature(sig_bytes.into());

        entry.sig = Some(signature);

        let mut buff = [0u8; 512];
        let buff_size = entry
            .encode(&mut buff)
            .context(EncodingForStoringFailed)?;

        self.store.add_entry(&buff[..buff_size], seq_num).context(AppendFailed)
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
            Err(Error::PublishAfterEndOfFeed { backtrace: _ }) => {}
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
            Err(Error::TriedToPublishWithoutSecretKey) => {}
            e => panic!("expected publish to fail with an error, got: {:?}", e),
        }
    }
}

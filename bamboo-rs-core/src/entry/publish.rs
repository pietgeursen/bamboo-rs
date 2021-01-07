pub use crate::BLAKE2B_HASH_SIZE;

use super::decode::decode;
use super::{is_lipmaa_required, Entry};
use crate::error::*;
use crate::signature::Signature;
use crate::yamf_hash::new_blake2b;
use ed25519_dalek::{Keypair, Signer};
use snafu::ensure;

pub fn publish(
    out: &mut [u8],
    key_pair: Option<&Keypair>,
    log_id: u64,
    payload: &[u8],
    is_end_of_feed: bool,
    last_seq_num: Option<u64>,
    lipmaa_entry_bytes: Option<&[u8]>,
    backlink_bytes: Option<&[u8]>,
) -> Result<usize, Error> {
    let author = key_pair
        .as_ref()
        .map(|keys| keys.public.clone())
        .ok_or(Error::PublishWithoutKeypair)?;

    // calc the payload hash
    let payload_hash = new_blake2b(payload);
    let payload_size = payload.len() as u64;

    let seq_num = last_seq_num.unwrap_or(0) + 1;

    let mut entry: Entry<_, &[u8]> = Entry {
        log_id,
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
        let lipmaa_link = new_blake2b(lipmaa_entry_bytes.ok_or(Error::PublishWithoutLipmaaEntry)?);

        let backlink_entry =
            decode(&backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?[..])?;

        // Ensure we're not trying to publish after the end of a feed.
        ensure!(!backlink_entry.is_end_of_feed, PublishAfterEndOfFeed);

        // Avoid publishing to a feed using an incorrect log_id
        ensure!(log_id == backlink_entry.log_id, PublishWithIncorrectLogId);

        let backlink = new_blake2b(backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?);
        entry.backlink = Some(backlink);

        // If the lipmaalink and backlink would be different, we should append the lipmaalink,
        // otherwise we're allowed to omit it to save some bytes.
        if is_lipmaa_required(seq_num) {
            entry.lipmaa_link = Some(lipmaa_link);
        }
    }

    let mut buff = [0u8; 512];
    let buff_size = entry.encode(&mut buff)?;

    let signature = key_pair
        .as_ref()
        .ok_or(Error::PublishWithoutSecretKey)?
        .sign(&buff[..buff_size]);
    let sig_bytes = &signature.to_bytes()[..];
    let signature = Signature(sig_bytes.into());

    entry.sig = Some(signature);

    entry.encode(out)
}

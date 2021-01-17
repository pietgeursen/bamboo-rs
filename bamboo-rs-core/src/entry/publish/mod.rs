pub use crate::BLAKE2B_HASH_SIZE;

use super::decode::decode;
use super::{is_lipmaa_required, Entry};
use crate::signature::Signature;
use crate::yamf_hash::new_blake2b;
use ed25519_dalek::{Keypair, Signer};
use snafu::{ensure, ResultExt};

pub mod error;
pub use error::*;

/// Publish a new entry into the `out` buffer.
///
/// - `out`: A buffer to encode the entry into. Must be >= MAX_ENTRY_SIZE.
/// - `key_pair`: The ed25519 cryptographic key pair used to sign the entry.
/// - `log_id`: The integer that distinguishes different logs by the same author.
/// - `payload`: The payload of the entry. Note that only the hash of the payload becomes part of the entry. It's up to the caller to store the actual payload somewhere.
/// - `is_end_of_feed`: Is this entry the final entry for this `log_id`?
/// - `previous_seq_num`: The seq num of the previous entry. `None` if this is the first entry.
/// - `lipmaa_entry_bytes`: The encoded lipmaa_entry. `None` if this is the first entry.
/// - `backlink_bytes`: The encoded backlkink. `None` if this is the first entry.
///
/// Returns a `Result` of the size of the entry encoded into `out`.
pub fn publish(
    out: &mut [u8],
    key_pair: &Keypair,
    log_id: u64,
    payload: &[u8],
    is_end_of_feed: bool,
    previous_seq_num: Option<u64>,
    lipmaa_entry_bytes: Option<&[u8]>,
    backlink_bytes: Option<&[u8]>,
) -> Result<usize, Error> {
    let author = key_pair.public;

    // calc the payload hash
    let payload_hash = new_blake2b(payload);
    let payload_size = payload.len() as u64;

    let seq_num = previous_seq_num.unwrap_or(0) + 1;

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
        let backlink_entry = decode(&backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?[..])
            .context(DecodeBacklinkEntry)?;

        let lipmaa_entry = decode(&lipmaa_entry_bytes.ok_or(Error::PublishWithoutLipmaaEntry)?[..])
            .context(DecodeLipmaaEntry)?;
        // Ensure we're not trying to publish after the end of a feed.
        ensure!(!backlink_entry.is_end_of_feed, PublishAfterEndOfFeed);

        // Avoid publishing to a feed using an incorrect log_id
        ensure!(
            log_id == backlink_entry.log_id,
            PublishWithIncorrectBacklinkLogId
        );

        // Avoid publishing using a different public key to the backlink
        ensure!(
            author == backlink_entry.author,
            PublishKeypairDidNotMatchBacklinkPublicKey
        );

        // Avoid publishing using a different public key to the lipmaa link
        ensure!(
            author == lipmaa_entry.author,
            PublishKeypairDidNotMatchBacklinkPublicKey
        );

        // Avoid publishing to a feed using an incorrect log_id
        ensure!(
            log_id == lipmaa_entry.log_id,
            PublishWithIncorrectLipmaaLinkLogId
        );

        let backlink = new_blake2b(backlink_bytes.ok_or(Error::PublishWithoutBacklinkEntry)?);
        entry.backlink = Some(backlink);

        // If the lipmaalink and backlink would be different, we should append the lipmaalink,
        // otherwise we're allowed to omit it to save some bytes.
        if is_lipmaa_required(seq_num) {
            let lipmaa_link =
                new_blake2b(lipmaa_entry_bytes.ok_or(Error::PublishWithoutLipmaaEntry)?);
            entry.lipmaa_link = Some(lipmaa_link);
        }
    }

    let buff_size = entry.encode(out).context(EncodeEntryToOutBuffer {
        buffer_size: out.len(),
    })?;

    let signature = key_pair.sign(&out[..buff_size]);
    let sig_bytes = &signature.to_bytes()[..];
    let signature = Signature(sig_bytes.into());

    entry.sig = Some(signature);

    entry.encode(out).context(EncodeEntryToOutBuffer {
        buffer_size: out.len(),
    })
}

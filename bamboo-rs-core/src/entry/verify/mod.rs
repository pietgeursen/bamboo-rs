use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;
use snafu::{ensure, ResultExt, NoneError};

use ed25519_dalek::{Signature as DalekSignature, Verifier};

use super::{decode::decode, is_lipmaa_required, Entry};
use crate::yamf_hash::new_blake2b;
use crate::yamf_hash::YamfHash;

#[cfg(feature = "std")]
pub mod batch;
#[cfg(feature = "std")]
pub use batch::verify_batch;

pub mod error;
pub use error::*;

impl<'a, H, S> Entry<H, S>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    /// Verify the signature of an entry is valid.
    pub fn verify_signature(&self) -> Result<()> {
        let ssb_sig = DalekSignature::try_from(self.sig.as_ref().unwrap().0.borrow())
            .map_err(|_|NoneError)
            .context(DecodeSigError)?;

        let mut buff = [0u8; 512];

        let encoded_size = self.encode_for_signing(&mut buff).unwrap();

        let pub_key = self.author.borrow();

        pub_key
            .verify(&buff[..encoded_size], &ssb_sig)
            .map_err(|_|NoneError)
            .context(InvalidSignature)
    }
}

pub fn verify_links_and_payload(
    entry: &Entry<&[u8], &[u8]>,
    payload: Option<(&[u8], YamfHash<ArrayVec<[u8; 64]>>)>,
    lipmaa_link: Option<(&[u8], YamfHash<ArrayVec<[u8; 64]>>)>,
    backlink: Option<(&[u8], YamfHash<ArrayVec<[u8; 64]>>)>,
) -> Result<(), Error> {
    // If we have the payload, check that its hash and length match what is encoded in the
    // entry.
    if let Some((payload, payload_hash)) = payload {
        ensure!(payload_hash == entry.payload_hash, PayloadHashDidNotMatch);
        ensure!(
            payload.len() == entry.payload_size as usize,
            PayloadLengthDidNotMatch {
                actual: payload.len(),
                expected: entry.payload_size
            }
        );
    }

    let lipmaa_is_required = is_lipmaa_required(entry.seq_num);

    match (
        lipmaa_link,
        entry.lipmaa_link.as_ref(),
        entry.seq_num,
        lipmaa_is_required,
    ) {
        // Happy path 1: this is the first entry, so we won't find a lipmaa link in the store
        (None, None, seq_num, _) if seq_num == 1 => Ok(()),
        // Happy path 2: seq is larger than one and we can find the lipmaa link in the store
        (Some((lipmaa, lipmaa_hash)), Some(ref entry_lipmaa), seq_num, true) if seq_num > 1 => {
            // Make sure the lipmaa entry hash matches what's in the entry.
            ensure!(lipmaa_hash == **entry_lipmaa, LipmaaHashDoesNotMatch);

            let lipmaa_entry = decode(lipmaa).context(DecodeLipmaaEntry)?;

            // Verify that the log_id of the entry is the same as the lipmaa entry
            ensure!(
                entry.log_id == lipmaa_entry.log_id,
                LipmaaLogIdDoesNotMatch {
                    actual: entry.log_id,
                    expected: lipmaa_entry.log_id
                }
            );

            // Verify the author of the entry is the same as the author in the lipmaa link entry
            ensure!(
                entry.author == lipmaa_entry.author,
                LipmaaAuthorDoesNotMatch
            );

            Ok(())
        }
        // Happy path 3: lipmaa link is not required because it would duplicate the backlink.
        (_, _, seq_num, false) if seq_num > 1 => Ok(()),
        (_, _, _, _) => Err(Error::LipmaaLinkRequired),
    }?;

    match (backlink, entry.backlink.as_ref(), entry.seq_num) {
        // Happy path 1: This is the first entry and doesn't have a backlink.
        (_, None, seq_num) if seq_num == 1 => Ok(()),

        //Happy path 2: This does have a backlink and we found it.
        (Some((backlink, backlink_hash)), Some(ref entry_backlink), seq_num) if seq_num > 1 => {
            let backlink_entry = decode(backlink).context(DecodeBacklinkEntry)?;

            // Verify that the log_id of the entry is the same as the lipmaa entry
            ensure!(
                entry.log_id == backlink_entry.log_id,
                BacklinkLogIdDoesNotMatch {
                    actual: entry.log_id,
                    expected: backlink_entry.log_id
                }
            );

            // Verify the author of the entry is the same as the author in the lipmaa link entry
            ensure!(
                entry.author == backlink_entry.author,
                BacklinkAuthorDoesNotMatch
            );

            // Verify this wasn't published after an end of feed message.
            ensure!(!backlink_entry.is_end_of_feed, PublishedAfterEndOfFeed);

            // Verify the backlink hashes match
            ensure!(backlink_hash == **entry_backlink, BacklinkHashDoesNotMatch);

            Ok(())
        }
        //Happy path 3: We don't have the backlink for this entry, happens when doing partial
        //replication.
        (None, Some(_), seq_num) if seq_num > 1 => Ok(()),
        (_, _, _) => Err(Error::BackLinkRequired),
    }?;

    Ok(())
}

pub fn verify(
    entry_bytes: &[u8],
    payload: Option<&[u8]>,
    lipmaa_link: Option<&[u8]>,
    backlink: Option<&[u8]>,
) -> Result<(), Error> {
    // Decode the entry that we want to verify.
    let entry = decode(entry_bytes).context(DecodeEntry)?;

    let payload_and_hash = payload.map(|payload| (payload, new_blake2b(payload)));
    let lipmaa_link_and_hash = lipmaa_link.map(|link| (link, new_blake2b(link)));
    let backlink_and_hash = backlink.map(|link| (link, new_blake2b(link)));

    verify_links_and_payload(
        &entry,
        payload_and_hash,
        lipmaa_link_and_hash,
        backlink_and_hash,
    )?;

    entry.verify_signature()
}

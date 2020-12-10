use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;

use ed25519_dalek::{
    Signature as DalekSignature,
    Verifier
};

use crate::yamf_hash::new_blake2b;
use super::{Entry, is_lipmaa_required, decode::decode};
use crate::error::*;
use crate::yamf_hash::YamfHash;


impl<'a, H, S> Entry<H, S>
where
    H: Borrow<[u8]>,
    S: Borrow<[u8]>,
{
    pub fn verify_signature(&self) -> Result<bool> {
        let ssb_sig = DalekSignature::try_from(self.sig.as_ref().unwrap().0.borrow())
            .map_err(|_| Error::DecodeSsbSigError)?;

        let mut buff = [0u8; 512];

        let encoded_size = self.encode_for_signing(&mut buff).unwrap();

        let pub_key = self.author.borrow();

        let result = pub_key
            .verify(&buff[..encoded_size], &ssb_sig)
            .map(|_| true)
            .unwrap_or(false);

        Ok(result)
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
        if payload_hash != entry.payload_hash {
            return Err(Error::AddEntryPayloadHashDidNotMatch);
        }
        if payload.len() as u64 != entry.payload_size {
            return Err(Error::AddEntryPayloadLengthDidNotMatch);
        }
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
            if lipmaa_hash != **entry_lipmaa {
                return Err(Error::AddEntryLipmaaHashDidNotMatch);
            }

            let lipmaa_entry =
                decode(lipmaa).map_err(|_| Error::AddEntryDecodeLipmaalinkFromStore)?;

            // Verify that the log_id of the entry is the same as the lipmaa entry
            if entry.log_id != lipmaa_entry.log_id {
                return Err(Error::AddEntryLogIdDidNotMatchLipmaaEntry);
            }
            // Verify the author of the entry is the same as the author in the lipmaa link entry
            if entry.author != lipmaa_entry.author {
                return Err(Error::AddEntryAuthorDidNotMatchLipmaaEntry);
            }
            Ok(())
        }
        // Happy path 3: lipmaa link is not required because it would duplicate the backlink.
        (_, _, seq_num, false) if seq_num > 1 => Ok(()),
        (_, _, _, _) => Err(Error::AddEntryNoLipmaalinkInStore),
    }?;

    match (backlink, entry.backlink.as_ref(), entry.seq_num) {
        // Happy path 1: This is the first entry and doesn't have a backlink.
        (_, None, seq_num) if seq_num == 1 => Ok(()),

        //Happy path 2: This does have a backlink and we found it.
        (Some((backlink, backlink_hash)), Some(ref entry_backlink), seq_num) if seq_num > 1 => {
            let backlink_entry = decode(backlink).map_err(|_| Error::AddEntryDecodeLastEntry)?;

            // Verify that the log_id of the entry is the same as the lipmaa entry
            if entry.log_id != backlink_entry.log_id {
                return Err(Error::AddEntryLogIdDidNotMatchPreviousEntry);
            }
            // Verify the author of the entry is the same as the author in the lipmaa link entry
            if entry.author != backlink_entry.author {
                return Err(Error::AddEntryAuthorDidNotMatchPreviousEntry);
            }

            // Verify this wasn't published after an end of feed message.
            if backlink_entry.is_end_of_feed {
                return Err(Error::AddEntryToFeedThatHasEnded);
            }

            if backlink_hash != **entry_backlink {
                return Err(Error::AddEntryBacklinkHashDidNotMatch);
            }
            Ok(())
        }
        //Happy path 3: We don't have the backlink for this entry, happens when doing partial
        //replication.
        (None, Some(_), seq_num) if seq_num > 1 => Ok(()),
        (_, _, _) => Err(Error::AddEntryBacklinkHashDidNotMatch),
    }?;

    Ok(())
}

pub fn verify(
    entry_bytes: &[u8],
    payload: Option<&[u8]>,
    lipmaa_link: Option<&[u8]>,
    backlink: Option<&[u8]>,
) -> Result<bool, Error> {
    // Decode the entry that we want to add.
    let entry = decode(entry_bytes).map_err(|_| Error::AddEntryDecodeFailed)?;

    let payload_and_hash = payload.map(|payload| (payload, new_blake2b(payload)));
    let lipmaa_link_and_hash = lipmaa_link.map(|link| (link, new_blake2b(link)));
    let backlink_and_hash = backlink.map(|link| (link, new_blake2b(link)));

    verify_links_and_payload(
        &entry,
        payload_and_hash,
        lipmaa_link_and_hash,
        backlink_and_hash,
    )?;

    let is_valid = entry
        .verify_signature()
        .map_err(|_| Error::AddEntrySigNotValidError)?;

    Ok(is_valid)
}

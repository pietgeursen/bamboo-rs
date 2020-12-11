use varu64::decode as varu64_decode;

use ed25519_dalek::{PublicKey as DalekPublicKey, PUBLIC_KEY_LENGTH};

use crate::signature::Signature;
use crate::yamf_hash::YamfHash;

use super::{is_lipmaa_required, Entry};
use crate::Error;

pub fn decode<'a>(bytes: &'a [u8]) -> Result<Entry<&'a [u8], &'a [u8]>, Error> {
    // Decode is end of feed
    if bytes.len() == 0 {
        return Err(Error::DecodeInputIsLengthZero);
    }
    let is_end_of_feed = bytes[0] == 1;

    // Decode the author
    if bytes.len() < PUBLIC_KEY_LENGTH + 1 {
        return Err(Error::DecodeAuthorError);
    }

    let author = DalekPublicKey::from_bytes(&bytes[1..PUBLIC_KEY_LENGTH + 1])
        .map_err(|_| Error::DecodeAuthorError)?;

    let remaining_bytes = &bytes[PUBLIC_KEY_LENGTH + 1..];

    // Decode the log id
    let (log_id, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|(err, _)| err)
        .map_err(|_| Error::DecodeLogIdError)?;

    // Decode the sequence number
    let (seq_num, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|(err, _)| err)
        .map_err(|_| Error::DecodeSeqError)?;

    if seq_num == 0 {
        return Err(Error::DecodeSeqIsZero);
    }

    let lipmaa_is_required = is_lipmaa_required(seq_num);

    // Decode the backlink and lipmaa links if its not the first sequence
    let (backlink, lipmaa_link, remaining_bytes) = match (seq_num, lipmaa_is_required) {
        (1, _) => (None, None, remaining_bytes),
        (_, true) => {
            let (lipmaa_link, remaining_bytes) =
                YamfHash::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodeLipmaaError)?;
            let (backlink, remaining_bytes) = YamfHash::<&[u8]>::decode(remaining_bytes)
                .map_err(|_| Error::DecodeBacklinkError)?;
            (Some(backlink), Some(lipmaa_link), remaining_bytes)
        }
        (_, false) => {
            let (backlink, remaining_bytes) = YamfHash::<&[u8]>::decode(remaining_bytes)
                .map_err(|_| Error::DecodeBacklinkError)?;
            (Some(backlink), None, remaining_bytes)
        }
    };

    // Decode the payload size
    let (payload_size, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|(err, _)| err)
        .map_err(|_| Error::DecodePayloadSizeError)?;

    // Decode the payload hash
    let (payload_hash, remaining_bytes) =
        YamfHash::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodePayloadHashError)?;

    // Decode the signature
    let (sig, _) =
        Signature::<&[u8]>::decode(remaining_bytes).map_err(|_| Error::DecodeSigError)?;

    Ok(Entry {
        log_id,
        is_end_of_feed,
        payload_hash,
        payload_size,
        author,
        seq_num,
        backlink,
        lipmaa_link,
        sig: Some(sig),
    })
}

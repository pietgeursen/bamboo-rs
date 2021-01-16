use varu64::decode as varu64_decode;

use ed25519_dalek::{PublicKey as DalekPublicKey, PUBLIC_KEY_LENGTH};

use crate::signature::Signature;
use crate::yamf_hash::YamfHash;

use super::{is_lipmaa_required, Entry};
use snafu::{ensure, NoneError, ResultExt};

pub mod error;
pub use error::*;

pub fn decode<'a>(bytes: &'a [u8]) -> Result<Entry<&'a [u8], &'a [u8]>, Error> {
    ensure!(bytes.len() > 0, DecodeInputIsLengthZero);

    // Decode is end of feed
    let is_end_of_feed = bytes[0] == 1;

    ensure!(bytes.len() >= PUBLIC_KEY_LENGTH + 1, DecodeAuthorError);

    // Decode the author
    let author = DalekPublicKey::from_bytes(&bytes[1..PUBLIC_KEY_LENGTH + 1])
        .map_err(|_| Error::DecodeAuthorError)?;

    let remaining_bytes = &bytes[PUBLIC_KEY_LENGTH + 1..];

    // Decode the log id
    let (log_id, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|_| NoneError)
        .context(DecodeLogIdError)?;

    // Decode the sequence number
    let (seq_num, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|_| NoneError)
        .context(DecodeSeqError)?;

    ensure!(seq_num > 0, DecodeSeqIsZero { seq_num });

    let lipmaa_is_required = is_lipmaa_required(seq_num);

    // Decode the backlink and lipmaa links if its not the first sequence
    let (backlink, lipmaa_link, remaining_bytes) = match (seq_num, lipmaa_is_required) {
        (1, _) => (None, None, remaining_bytes),
        (_, true) => {
            let (lipmaa_link, remaining_bytes) =
                YamfHash::<&[u8]>::decode(remaining_bytes).context(DecodeLipmaaError)?;
            let (backlink, remaining_bytes) =
                YamfHash::<&[u8]>::decode(remaining_bytes).context(DecodeBacklinkError)?;
            (Some(backlink), Some(lipmaa_link), remaining_bytes)
        }
        (_, false) => {
            let (backlink, remaining_bytes) =
                YamfHash::<&[u8]>::decode(remaining_bytes).context(DecodeBacklinkError)?;
            (Some(backlink), None, remaining_bytes)
        }
    };

    // Decode the payload size
    let (payload_size, remaining_bytes) = varu64_decode(remaining_bytes)
        .map_err(|_| NoneError)
        .context(DecodePayloadSizeError)?;

    // Decode the payload hash
    let (payload_hash, remaining_bytes) =
        YamfHash::<&[u8]>::decode(remaining_bytes).context(DecodePayloadHashError)?;

    // Decode the signature
    let (sig, _) = Signature::<&[u8]>::decode(remaining_bytes).context(DecodeSigError)?;

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

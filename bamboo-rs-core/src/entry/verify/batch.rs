use crate::BLAKE2B_HASH_SIZE;
use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;
use ed25519_dalek::PublicKey;
use snafu::{ResultExt, NoneError};
#[cfg(feature = "std")]
use std::collections::HashMap;

use ed25519_dalek::Signature as DalekSignature;

#[cfg(feature = "std")]
use ed25519_dalek::verify_batch as verify_batch_dalek;

use crate::yamf_hash::YamfHash;

use super::verify_links_and_payload;
use super::Entry;
use rayon::prelude::*;

#[cfg(feature = "std")]
use blake2b_simd::blake2b;

use super::error::*;

/// Batch verify a collection of entries that are **all from the same author and same log_id**
///
/// Uses rayon and signature batch verification to utilize multiple processors + SIMD instruction.
#[cfg(feature = "std")]
pub fn verify_batch<E: AsRef<[u8]> + Sync, P: AsRef<[u8]> + Sync>(
    entries_and_payloads: &[(E, Option<P>)],
) -> Result<()> {
    verify_batch_links_and_payload(entries_and_payloads)?;
    let bytes_iter = entries_and_payloads
        .iter()
        .map(|(bytes, _)| bytes.as_ref())
        .collect::<Vec<_>>();
    verify_batch_signatures(&bytes_iter)?;

    Ok(())
}
/// Batch verify the links + payloads of a collection of entries that are **all from the same author and same log_id**
#[cfg(feature = "std")]
pub fn verify_batch_links_and_payload<E: AsRef<[u8]> + Sync, P: AsRef<[u8]> + Sync>(
    entries_and_payloads: &[(E, Option<P>)],
) -> Result<()> {
    // Build a hashmap from seq num to bytes and hashes we need.
    let hash_map = entries_and_payloads[..]
        .par_iter()
        .map(|(bytes, payload)| {
            let entry = Entry::try_from(bytes.as_ref()).context(DecodeEntry)?;
            let entry_hash = blake2b(bytes.as_ref()); //HashManyJob::new(&params, bytes.as_ref());

            let payload_and_hash = payload
                .as_ref()
                .map(|payload| (payload.as_ref(), blake2b(payload.as_ref())));

            Ok((
                entry.seq_num,
                (bytes.as_ref(), entry, entry_hash, payload_and_hash),
            ))
        })
        .collect::<Result<HashMap<u64, (_, _, _, _)>>>()?;

    hash_map
        .par_iter()
        .map(|(seq_num, (_, entry, _, payload_and_hash))| {
            let backlink_and_hash = hash_map.get(&(seq_num - 1)).map(
                |(bytes, _, entry_hash, _)| -> (_, YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>) {
                    (*bytes, (*entry_hash).into())
                },
            );

            let lipmaa_link_and_hash = hash_map.get(&(lipmaa_link::lipmaa(*seq_num))).map(
                |(bytes, _, entry_hash, _)| -> (_, YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>) {
                    (*bytes, (*entry_hash).into())
                },
            );

            let payload_and_hash = payload_and_hash
                .as_ref()
                .map(|(payload, job)| (*payload, (*job).into()));

            verify_links_and_payload(
                entry,
                payload_and_hash,
                lipmaa_link_and_hash,
                backlink_and_hash,
            )
        })
        .collect()
}

/// Batch verify the signatures of a collection of entries that are **all from the same author and same log_id**
#[cfg(feature = "std")]
pub fn verify_batch_signatures<'a, T: AsRef<[u8]>>(entries_bytes: &'a [T]) -> Result<()>
where
    [T]: ParallelSlice<T>,
    T: Sync,
{
    entries_bytes
        .as_parallel_slice()
        .par_chunks(125)
        .try_fold(
            || (),
            |_, chunk| {
                let entries = chunk
                    .into_iter()
                    .map(|bytes| Entry::try_from(bytes.as_ref()).context(DecodeEntry))
                    .collect::<Result<Vec<_>>>()?;

                let unsigned_encoding_vecs = entries
                    .iter()
                    .map(|entry| {
                        // TODO more efficient?
                        let mut vec = Vec::with_capacity(entry.encoding_length());
                        entry
                            .encode_for_signing_write(&mut vec)
                            .context(EncodeEntryForSigning)?;
                        Ok(vec)
                    })
                    .collect::<Result<Vec<Vec<u8>>>>()?;

                let unsigned_encodings = unsigned_encoding_vecs
                    .iter()
                    .map(|entry| entry.as_ref())
                    .collect::<Vec<_>>();

                let signatures = entries
                    .iter()
                    .map(|entry| {
                        let ssb_sig =
                            DalekSignature::try_from(entry.sig.as_ref().unwrap().0.borrow())
                                .map_err(|_|NoneError)
                                .context(DecodeSigError)?;
                        Ok(ssb_sig)
                    })
                    .collect::<Result<Vec<DalekSignature>>>()?;

                let pub_keys = entries
                    .iter()
                    .map(|entry| entry.author.clone())
                    .collect::<Vec<PublicKey>>();

                verify_batch_dalek(&unsigned_encodings, &signatures, &pub_keys[..])
                    .map_err(|_|NoneError)
                    .context(InvalidSignature)?;

                Ok(())
            },
        )
        .try_reduce(|| (), |_, _| Ok(()))
}

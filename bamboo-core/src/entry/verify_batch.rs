use crate::BLAKE2B_HASH_SIZE;
use arrayvec::ArrayVec;
use core::borrow::Borrow;
use core::convert::TryFrom;
use ed25519_dalek::PublicKey;
#[cfg(feature = "std")]
use std::collections::HashMap;

use ed25519_dalek::Signature as DalekSignature;

#[cfg(feature = "std")]
use ed25519_dalek::verify_batch as verify_batch_dalek;

use crate::yamf_hash::YamfHash;

use super::verify::verify_links_and_payload;
use super::Entry;
use crate::error::*;
use rayon::prelude::*;
use std::ops::DerefMut;

#[cfg(feature = "std")]
use blake2b_simd::{
    many::{hash_many, HashManyJob},
    Params,
};

/// Batch verify a collection of entries that are **all from the same author and same log_id**
#[cfg(feature = "std")]
pub fn verify_batch<E: AsRef<[u8]> + Sync, P: AsRef<[u8]> + Sync>(
    entries_and_payloads: &[(E, Option<P>)],
) -> Result<()> {
    verify_batch_links_and_payload(entries_and_payloads)?;
    let bytes_iter = entries_and_payloads.iter().map(|(bytes, _)| bytes.as_ref());
    verify_batch_signatures(bytes_iter)?;

    Ok(())
}
/// Batch verify the links + payloads of a collection of entries that are **all from the same author and same log_id**
#[cfg(feature = "std")]
pub fn verify_batch_links_and_payload<E: AsRef<[u8]> + Sync, P: AsRef<[u8]> + Sync>(
    entries_and_payloads: &[(E, Option<P>)],
) -> Result<()> {
    let params = Params::new();

    // Build a hashmap from seq num to bytes and hashes we need.
    let mut hash_map = entries_and_payloads[..]
        .par_iter()
        .map(|(bytes, payload)| {
            let entry = Entry::try_from(bytes.as_ref())?;
            let entry_job = HashManyJob::new(&params, bytes.as_ref());

            let payload_and_job = payload.as_ref().map(|payload| {
                (
                    payload.as_ref(),
                    HashManyJob::new(&params, payload.as_ref()),
                )
            });

            Ok((
                entry.seq_num,
                (bytes.as_ref(), entry, entry_job, payload_and_job),
            ))
        })
        .collect::<Result<HashMap<u64, (_, _, _, _)>>>()?;

//    let mut jobs = hash_map
//        .iter_mut()
//        .map(|(_, (_, _, job, _))| job)
//        .collect::<Vec<&mut HashManyJob>>();
//
//    jobs.as_parallel_slice_mut()
//        .par_chunks_mut(50)
//        .fold(
//            || (),
//            |_, jobs| hash_many(jobs.iter_mut().map(|j| j.deref_mut())),
//        )
//        .reduce(|| (), |_, _| ());

    //hash_map.as_parallel_slice();
    // Hash all the entries at once.
    hash_many(hash_map.iter_mut().map(|(_, (_, _, job, _))| job));

    let payload_jobs = hash_map
        .iter_mut()
        .filter_map(|(_, (_, _, _, payload_and_job))| payload_and_job.as_mut().map(|(_, job)| job));

    // Hash all the payloads at once.
    hash_many(payload_jobs);

    hash_map
        .par_iter()
        .map(|(seq_num, (_, entry, _, payload_and_job))| {
            let backlink_and_hash = hash_map.get(&(seq_num - 1)).map(
                |(bytes, _, entry_job, _)| -> (_, YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>) {
                    (*bytes, entry_job.to_hash().into())
                },
            );

            let lipmaa_link_and_hash = hash_map.get(&(lipmaa_link::lipmaa(*seq_num))).map(
                |(bytes, _, entry_job, _)| -> (_, YamfHash<ArrayVec<[u8; BLAKE2B_HASH_SIZE]>>) {
                    (*bytes, entry_job.to_hash().into())
                },
            );

            let payload_and_hash = payload_and_job
                .as_ref()
                .map(|(payload, job)| (*payload, job.to_hash().into()));

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
pub fn verify_batch_signatures<'a, I: IntoIterator<Item = &'a [u8]>>(
    entries_bytes: I,
) -> Result<()> {
    let entries = entries_bytes
        .into_iter()
        .map(|bytes| Entry::try_from(bytes))
        .collect::<Result<Vec<_>>>()?;

    let unsigned_encoding_vecs = entries
        .iter()
        .map(|entry| {
            let mut vec = Vec::with_capacity(entry.encoding_length());
            entry.encode_for_signing_write(&mut vec)?;
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
            let ssb_sig = DalekSignature::try_from(entry.sig.as_ref().unwrap().0.borrow())
                .map_err(|_| Error::DecodeSsbSigError)?;
            Ok(ssb_sig)
        })
        .collect::<Result<Vec<DalekSignature>>>()?;

    let pub_keys = entries
        .iter()
        .map(|entry| entry.author.clone())
        .collect::<Vec<PublicKey>>();

    verify_batch_dalek(&unsigned_encodings, &signatures, &pub_keys[..])
        .map_err(|_| Error::SignatureInvalid)?;

    Ok(())
}

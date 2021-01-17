//! # bamboo-rs-core
//!
//! Verify, Publish and Decode [bamboo](https://github.com/AljoschaMeyer/bamboo) entries.
//!
//! ## About
//!
//! From the [spec](https://github.com/AljoschaMeyer/bamboo):
//!
//! > A cryptographically secure, distributed, single-writer append-only log that supports transitive partial replication and local deletion of data.
//! >
//! > Powered by science, this log format can serve as a more efficient alternative to secure-scuttlebutt's linked lists or hypercore's merkle forests.
//!
//! `bamboo-rs-core` exposes low level functions and types which can be built with `no_std`.
//!
//! ## Example
//!
//! `publish`, `verify` and `decode` the first `Entry` in a bamboo log.
//!
//! NB: Publishing and verifying the first entry is the most simple case. The following entries
//! require passing the backlink and lipmaa_link.
//! 
//! ```
//! use bamboo_rs_core::{publish, verify, decode, yamf_hash::new_blake2b, Entry, Signature, YamfHash, Keypair, entry::MAX_ENTRY_SIZE};
//! use rand::rngs::OsRng;
//!
//! let mut csprng: OsRng = OsRng {};
//! let key_pair: Keypair = Keypair::generate(&mut csprng);
//! let log_id = 0;
//!
//! let payload = "hello bamboo!";
//! let mut out = [0u8; MAX_ENTRY_SIZE];
//!
//! let size = publish(
//!     &mut out,
//!     Some(&key_pair),
//!     log_id,
//!     payload.as_bytes(),
//!     false,
//!     None,
//!     None,
//!     None,
//! )
//! .unwrap();
//!
//! let entry = decode(&out[..size]).unwrap();
//!
//! let is_verified = verify(&out[..size], Some(payload.as_bytes()), None, None).is_ok();
//! let payload_hash = new_blake2b(payload.as_bytes());
//!
//! assert!(is_verified);
//! assert_eq!(entry.log_id, log_id);
//! assert_eq!(entry.payload_hash, payload_hash);
//! assert_eq!(entry.author, key_pair.public);
//! assert_eq!(entry.lipmaa_link, None);
//! assert_eq!(entry.backlink, None);
//! assert_eq!(entry.is_end_of_feed, false);
//! ```
#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate static_assertions;

pub mod entry;
pub mod signature;
pub mod yamf_hash;

mod util;

pub use crate::yamf_hash::{YamfHash, BLAKE2B_HASH_SIZE, OUTBYTES};
pub use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError};
#[cfg(feature = "std")]
pub use entry::verify::verify_batch;
pub use entry::{decode, publish, verify, Entry};
pub use lipmaa_link::lipmaa;
pub use signature::{Signature, ED25519_SIGNATURE_SIZE};

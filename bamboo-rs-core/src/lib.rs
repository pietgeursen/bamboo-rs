//! # bamboo-rs-core
//!
//! Verify, and Publish [bamboo](https://github.com/AljoschaMeyer/bamboo) messages.
//!
//!
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

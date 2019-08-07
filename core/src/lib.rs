#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[panic_handler]
#[no_mangle]
pub extern "C" fn panic(panic_info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = panic_info.location() {
        //println!("panic occurred in file '{}' at line {}", location.file(),
        let _line = location.line();
    } else {
        //jprintln!("panic occurred but can't get location information...");
    }
    loop {}
}

#[macro_use]
extern crate serde_derive;

pub mod error;
pub mod entry;
pub mod entry_store;
pub mod log;
pub mod signature;
pub mod yamf_hash;
pub mod yamf_signatory;

mod util;

pub use ed25519_dalek::{Keypair, PublicKey, SecretKey};
pub use entry::Entry;
pub use entry_store::EntryStore;
pub use lipmaa_link::lipmaa;
pub use log::Log;
pub use error::Error;

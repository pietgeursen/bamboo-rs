//! # bamboo-c
//!
//! Sign, and Verify [bamboo](https://github.com/AljoschaMeyer/bamboo) messages.
//!
//! `bamboo-c` exposes a c-friendly api and can be built with `no_std`.
//!
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
#[panic_handler]
#[no_mangle]
/// cbindgen:ignore
pub extern "C" fn panic(panic_info: &core::panic::PanicInfo) -> ! {
    if let Some(location) = panic_info.location() {
        //println!("panic occurred in file '{}' at line {}", location.file(),
        let _line = location.line();
    } else {
        //jprintln!("panic occurred but can't get location information...");
    }
    loop {}
}

pub mod decode;
pub mod publish;
pub mod verify;

pub use bamboo_rs_core::BLAKE2B_HASH_SIZE;

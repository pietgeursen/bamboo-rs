#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate bamboo_core;

use bamboo_core::entry::{decode};

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = decode(data);
});

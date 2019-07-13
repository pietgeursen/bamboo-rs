#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate bamboo_rs;

use bamboo_rs::entry::{Entry};

fuzz_target!(|data: &[u8]| {
    // fuzzed code goes here
    let _ = Entry::decode(data);
});

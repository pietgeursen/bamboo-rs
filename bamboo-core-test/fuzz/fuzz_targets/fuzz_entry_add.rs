#![no_main]
#[macro_use] extern crate libfuzzer_sys;
//extern crate bamboo_rs;
//extern crate ssb_crypto;
//
//use bamboo_rs::{Log};
//use bamboo_rs::memory_entry_store::{MemoryEntryStore};
//use ssb_crypto::{generate_longterm_keypair, init };

fuzz_target!(|data: &[u8]| {
 //   init();
 //   let (pub_key, _) = generate_longterm_keypair();
 //   let mut log = Log::new(MemoryEntryStore::new(), pub_key, None);
 //   // fuzzed code goes here
 //   let _ = log.add(data, None);
});

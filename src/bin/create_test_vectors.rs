#[macro_use]
extern crate serde_json;
extern crate bamboo_rs;

use bamboo_rs::entry::decode;
use bamboo_rs::entry_store::MemoryEntryStore;
use bamboo_rs::{lipmaa, Entry, EntryStore, Log};
use serde_json::Value;
use ssb_crypto::{generate_longterm_keypair, init};

#[cfg_attr(tarpaulin, skip)]
pub fn main() {
    let jsn = json!({
        "validFirstEntry": valid_first_entry(),
        "fiveValidEntries": n_valid_entries(5),
        "valid_partial_replicated_seq_100000": valid_partially_replicated_feed(100001),
    });

    let json_string = serde_json::to_string_pretty(&jsn).unwrap();
    println!("{}", json_string);
}

#[cfg_attr(tarpaulin, skip)]
fn valid_first_entry() -> Value {
    init();

    let (pub_key, secret_key) = generate_longterm_keypair();
    let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));
    let payload = "hello bamboo!";
    log.publish(payload.as_bytes(), false).unwrap();

    let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

    let mut entry = decode(entry_bytes).unwrap();
    assert!(entry.verify_signature().unwrap());

    let encoded_entry = entry.encode();

    json!({
        "description": "A valid first entry. Note that the previous and limpaa links are None / null. And that the seq_num starts at 1.",
        "payload": payload,
        "decoded": entry,
        "encoded": encoded_entry
    })
}

#[cfg_attr(tarpaulin, skip)]
fn n_valid_entries(n: u64) -> Value {
    init();

    let (pub_key, secret_key) = generate_longterm_keypair();
    let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));

    let vals: Vec<Value> = (1..n)
        .into_iter()
        .map(|i| {
            let payload = format!("message number {}", i);
            log.publish(&payload.as_bytes(), false).unwrap();
            let entry_bytes = log.store.get_entry_ref(i).unwrap().unwrap();
            let entry = decode(entry_bytes).unwrap();
            let encoded_entry = entry.encode();

            json!({
                "payload": payload,
                "decoded": entry,
                "encoded": encoded_entry
            })
        })
        .collect();

    json!({
        "description": format!("A valid collection of {} entries.", n),
        "entries": vals
    })
}

#[cfg_attr(tarpaulin, skip)]
fn valid_partially_replicated_feed(n: u64) -> Value {
    init();

    let (pub_key, secret_key) = generate_longterm_keypair();
    let mut log = Log::new(MemoryEntryStore::new(), pub_key, Some(secret_key));

    (1..n).into_iter().for_each(|i| {
        let payload = format!("message number {}", i);
        log.publish(&payload.as_bytes(), false).unwrap();
    });

    let lipmaa_seqs = build_lipmaa_set(n - 1, None);

    let mut partial_log = Log::new(MemoryEntryStore::new(), pub_key, None);

    lipmaa_seqs
        .iter()
        .rev()
        .map(|lipmaa_seq| {
            let entry_bytes = log.store.get_entry_ref(*lipmaa_seq).unwrap().unwrap();
            let entry = decode(entry_bytes).unwrap();
            partial_log.add(entry_bytes, None).unwrap();

            let encoded_entry = entry.encode();

            json!({
                "decoded": entry,
                "encoded": encoded_entry
            })
        })
        .collect()
}

fn build_lipmaa_set(n: u64, mut vec: Option<Vec<u64>>) -> Vec<u64> {
    if n == 0 {
        return vec.unwrap();
    }

    if let None = vec {
        vec = Some(Vec::new());
    }

    let mut vec = vec.unwrap();
    vec.push(n);

    build_lipmaa_set(lipmaa(n), Some(vec))
}

#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde;

extern crate bamboo_core;
extern crate bamboo_log;
extern crate hex;
extern crate rand;

use bamboo_core::entry::decode;
use bamboo_core::{lipmaa, Keypair};
use bamboo_log::entry_store::MemoryEntryStore;
use bamboo_log::{EntryStore, Log};
use serde::Serializer;
use serde_json::Value;

use rand::rngs::OsRng;

pub fn hex_from_bytes<'de, S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    if serializer.is_human_readable() {
        let bytes = hex::encode(bytes);
        serializer.serialize_str(&bytes)
    } else {
        serializer.serialize_bytes(&bytes)
    }
}

#[derive(Serialize)]
struct Bytes<'a>(#[serde(serialize_with = "hex_from_bytes")] &'a [u8]);

#[cfg_attr(tarpaulin, skip)]
pub fn main() {
    let jsn = json!({
        "validFirstEntry": valid_first_entry(),
        "fiveValidEntries": n_valid_entries(5),
        "valid_partial_replicated_seq_100": valid_partially_replicated_feed(101),
    });

    let json_string = serde_json::to_string_pretty(&jsn).unwrap();
    println!("{}", json_string);
}

#[cfg_attr(tarpaulin, skip)]
fn valid_first_entry() -> Value {
    let mut csprng: OsRng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);

    let mut log = Log::new(
        MemoryEntryStore::new(),
        keypair.public.clone(),
        Some(keypair),
        0
    );
    let payload = "hello bamboo!";
    log.publish(payload.as_bytes(), false).unwrap();

    let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

    let mut entry = decode(entry_bytes).unwrap();
    assert!(entry.verify_signature().unwrap());

    let mut buffer = [0u8; 512];
    let buff_size = entry.encode(&mut buffer).unwrap();

    json!({
        "description": "A valid first entry. Note that the previous and limpaa links are None / null. And that the seq_num starts at 1.",
        "payload": payload,
        "decoded": entry,
        "encoded": Bytes(&buffer[..buff_size])
    })
}

#[cfg_attr(tarpaulin, skip)]
fn n_valid_entries(n: u64) -> Value {
    let mut csprng: OsRng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let mut log = Log::new(
        MemoryEntryStore::new(),
        keypair.public.clone(),
        Some(keypair),
        0
    );

    let vals: Vec<Value> = (1..n)
        .into_iter()
        .map(|i| {
            let payload = format!("message number {}", i);
            log.publish(&payload.as_bytes(), false).unwrap();
            let entry_bytes = log.store.get_entry_ref(i).unwrap().unwrap();
            let entry = decode(entry_bytes).unwrap();
            let mut buffer = [0u8; 512];
            let buff_size = entry.encode(&mut buffer).unwrap();

            json!({
                "payload": payload,
                "decoded": entry,
                "encoded": Bytes(&buffer[..buff_size])
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
    let mut csprng: OsRng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    let public = keypair.public.clone();
    let mut log = Log::new(MemoryEntryStore::new(), public.clone(), Some(keypair), 0);

    (1..n).into_iter().for_each(|i| {
        let payload = format!("message number {}", i);
        log.publish(&payload.as_bytes(), false).unwrap();
    });

    let lipmaa_seqs = build_lipmaa_set(n - 1, None);

    let mut partial_log = Log::new(MemoryEntryStore::new(), public.clone(), None, 0);

    lipmaa_seqs
        .iter()
        .rev()
        .map(|lipmaa_seq| {
            let entry_bytes = log.store.get_entry_ref(*lipmaa_seq).unwrap().unwrap();
            let entry = decode(entry_bytes).unwrap();
            partial_log.add(entry_bytes, None).unwrap();

            let mut buffer = [0u8; 512];
            let buff_size = entry.encode(&mut buffer).unwrap();

            json!({
                "decoded": entry,
                "encoded": Bytes(&buffer[..buff_size])
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

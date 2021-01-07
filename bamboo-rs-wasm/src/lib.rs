pub mod utils;

pub use utils::set_panic_hook;

use arrayvec::*;
use bamboo_rs_core::entry::{
    decode as decode_entry, into_owned, publish as publish_entry, verify as verify_entry,
    MAX_ENTRY_SIZE,
};
use bamboo_rs_core::yamf_hash::new_blake2b;
use bamboo_rs_core::{lipmaa, Entry, YamfHash};
use bamboo_rs_core::{Keypair, PublicKey, SecretKey, Signature};
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = "lipmaaLink")]
pub fn lipmaa_link(seq: u64) -> u64 {
    if seq <= 1 {
        return 1;
    }
    lipmaa(seq)
}

#[wasm_bindgen(js_name = "maxEntrySize")]
pub fn max_entry_size() -> u32 {
    MAX_ENTRY_SIZE as u32
}

#[wasm_bindgen(inspectable)]
pub struct BambooEntry {
    hash: YamfHash<ArrayVec<[u8; 64]>>,
    value: Entry<ArrayVec<[u8; 64]>, ArrayVec<[u8; 64]>>,
}

#[wasm_bindgen]
impl BambooEntry {
    #[wasm_bindgen(getter, js_name = "entryHash")]
    pub fn hash(&self) -> Box<[u8]> {
        let mut out = Vec::new();
        self.hash.encode_write(&mut out).unwrap();
        out.into()
    }

    #[wasm_bindgen(getter, js_name = "payloadHash")]
    pub fn payload_hash(&self) -> Box<[u8]> {
        let mut out = Vec::new();
        self.value.payload_hash.encode_write(&mut out).unwrap();
        out.into()
    }

    #[wasm_bindgen(getter, js_name = "lipmaaLinkHash")]
    pub fn lipmaa_link(&self) -> Option<Box<[u8]>> {
        self.value.lipmaa_link.as_ref().map(|hash| {
            let mut out = Vec::new();
            hash.encode_write(&mut out).unwrap();
            out.into()
        })
    }

    #[wasm_bindgen(getter, js_name = "backLinkHash")]
    pub fn back_link(&self) -> Option<Box<[u8]>> {
        self.value.backlink.as_ref().map(|hash| {
            let mut out = Vec::new();
            hash.encode_write(&mut out).unwrap();
            out.into()
        })
    }

    #[wasm_bindgen(getter)]
    pub fn signature(&self) -> Option<Box<[u8]>> {
        match self.value.sig {
            Some(Signature(ref bts)) => Some(bts.as_ref().into()),
            None => None,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn author(&self) -> Box<[u8]> {
        self.value.author.as_bytes().to_vec().into()
    }

    #[wasm_bindgen(getter, js_name = "isEndOfFeed")]
    pub fn is_end_of_feed(&self) -> bool {
        self.value.is_end_of_feed
    }

    #[wasm_bindgen(getter, js_name = "logId")]
    pub fn log_id(&self) -> u64 {
        self.value.log_id
    }

    #[wasm_bindgen(getter, js_name = "payloadSize")]
    pub fn payload_size(&self) -> u64 {
        self.value.payload_size
    }

    #[wasm_bindgen(getter)]
    pub fn sequence(&self) -> u64 {
        self.value.seq_num
    }
}

#[wasm_bindgen]
pub fn decode(buffer: &[u8]) -> Result<BambooEntry, JsValue> {
    let hash = new_blake2b(buffer);
    let entry = decode_entry(buffer).map_err(|err| JsValue::from_str(&err.to_string()))?;

    let entry = into_owned(&entry);
    let bamboo_entry = BambooEntry {
        hash: hash,
        value: entry,
    };

    Ok(bamboo_entry)
}

#[wasm_bindgen]
pub fn verify(
    entry_bytes: &[u8],
    payload: Option<Vec<u8>>,
    lipmaa_link: Option<Vec<u8>>,
    backlink: Option<Vec<u8>>,
) -> Result<(), JsValue> {
    verify_entry(
        entry_bytes,
        payload.as_deref(),
        lipmaa_link.as_deref(),
        backlink.as_deref(),
    )
    .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn publish(
    out: &mut [u8],
    public_key: &[u8],
    secret_key: &[u8],
    log_id: u64,
    payload: &[u8],
    is_end_of_feed: bool,
    last_seq_num: Option<u64>,
    lipmaa_entry_vec: Option<Vec<u8>>,
    backlink_vec: Option<Vec<u8>>,
) -> Result<usize, JsValue> {
    let public_key = PublicKey::from_bytes(public_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let secret_key = SecretKey::from_bytes(secret_key)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let key_pair = Keypair {
        public: public_key.clone(),
        secret: secret_key,
    };

    publish_entry(
        out,
        Some(&key_pair),
        log_id,
        payload,
        is_end_of_feed,
        last_seq_num,
        lipmaa_entry_vec.as_ref().map(|vec| vec.as_slice()),
        backlink_vec.as_ref().map(|vec| vec.as_slice()),
    )
    .map_err(|err| JsValue::from_str(&err.to_string())) 
}

//TODO: keygen.
//Warning, just for dev

#[wasm_bindgen]
pub struct KeyPair {
    inner: Keypair,
}

#[wasm_bindgen]
impl KeyPair {
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        Vec::from(&self.inner.public.as_bytes()[..])
    }
    #[wasm_bindgen(js_name = secretKeyBytes)]
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        Vec::from(&self.inner.secret.as_bytes()[..])
    }
    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyPair {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        KeyPair { inner: keypair }
    }
}

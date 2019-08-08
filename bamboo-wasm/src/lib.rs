mod utils;

use wasm_bindgen::prelude::*;
use bamboo_core::{lipmaa};
use bamboo_core::entry::{Entry};
use bamboo_core::{PublicKey, Keypair, SecretKey};
use rand::rngs::OsRng;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

#[wasm_bindgen]
pub fn lipmaa_link(seq: u64) -> u64 {
    lipmaa(seq)
}

//    pub fn publish(
//        out: &mut [u8],
//        key_pair: &Option<Keypair>,
//        public_key: &PublicKey,
//        payload: &[u8],
//        is_end_of_feed: bool,
//        last_seq_num: u64,
//        lipmaa_entry_bytes: Option<&[u8]>,
//        backlink_bytes: Option<&[u8]>,
//    ) -> Result<usize, Error> {
#[no_mangle]
#[wasm_bindgen]
pub extern "C" fn publish(out: &mut[u8], public_key: &[u8], secret_key: &[u8], payload: &[u8], is_end_of_feed: bool, last_seq_num: u64, lipmaa_entry_vec: Option<Vec<u8>>, backlink_vec: Option<Vec<u8>>)  {
    //TODO: remove unwrap
    let public_key = PublicKey::from_bytes(public_key).unwrap();
    //TODO: remove unwrap
    let secret_key = SecretKey::from_bytes(secret_key).unwrap();
    let key_pair = Keypair{public: public_key.clone(), secret: secret_key};

    //TODO: set the out length
    //TODO: remove unwrap
    Entry::<&[u8], &[u8], &[u8]>::publish(out, &Some(key_pair), &public_key, payload, is_end_of_feed, last_seq_num, lipmaa_entry_vec.as_ref().map(|vec| vec.as_slice()), backlink_vec.as_ref().map(|vec| vec.as_slice()) ).unwrap();
}

//TODO: deserialize from bytes


//TODO: keygen.
//Warning, just for dev

#[wasm_bindgen]
pub struct KeyPair{
    inner: Keypair
}

#[wasm_bindgen]
impl KeyPair{
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
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);
        KeyPair{
            inner: keypair
        }
    }
}




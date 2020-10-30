pub use crate::entry_store::EntryStore;
use bamboo_rs_core::{Keypair, PublicKey};

pub mod add;
pub mod publish;
pub mod error;

pub use add::*;
pub use publish::*;
pub use error::*;

pub struct Log<Store: EntryStore> {
    pub store: Store,
    pub public_key: PublicKey,
    pub log_id: u64,
    key_pair: Option<Keypair>,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store, public_key: PublicKey, key_pair: Option<Keypair>, log_id: u64) -> Log<Store> {
        Log {
            store,
            public_key,
            key_pair,
            log_id
        }
    }
}

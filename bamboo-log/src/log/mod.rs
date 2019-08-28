pub use crate::entry_store::EntryStore;
use bamboo_core::{Keypair, PublicKey};

pub mod add;
pub mod publish;

pub use add::*;
pub use publish::*;

pub struct Log<Store: EntryStore> {
    pub store: Store,
    pub public_key: PublicKey,
    key_pair: Option<Keypair>,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store, public_key: PublicKey, key_pair: Option<Keypair>) -> Log<Store> {
        Log {
            store,
            public_key,
            key_pair,
        }
    }
}

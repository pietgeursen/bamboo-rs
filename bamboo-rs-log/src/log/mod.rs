pub use crate::entry_store::EntryStorer;
use bamboo_rs_core::Keypair;

pub mod add;
pub mod error;
pub mod publish;

pub use add::*;
pub use error::*;
pub use publish::*;

#[derive(Debug)]
pub struct Log<Store: EntryStorer> {
    pub store: Store,
    pub key_pair: Option<Keypair>,
}

impl<Store: EntryStorer> Log<Store> {
    pub fn new(store: Store, key_pair: Option<Keypair>) -> Log<Store> {
        Log { store, key_pair }
    }
}

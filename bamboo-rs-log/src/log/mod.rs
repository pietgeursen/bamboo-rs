<<<<<<< HEAD:bamboo-rs-log/src/log/mod.rs
pub use crate::entry_store::EntryStore;
use bamboo_rs_core::{Keypair, PublicKey};
=======
pub use crate::entry_store::EntryStorer;
use bamboo_core::Keypair;
>>>>>>> 38bf8e64 (Re-write the bamboo store):bamboo-log/src/log/mod.rs

pub mod add;
pub mod publish;
pub mod error;

pub use add::*;
pub use publish::*;
pub use error::*;

pub struct Log<Store: EntryStorer> {
    pub store: Store,
    key_pair: Option<Keypair>,
}

impl<Store: EntryStorer> Log<Store> {
    pub fn new(store: Store, key_pair: Option<Keypair>) -> Log<Store> {
        Log { store, key_pair }
    }
}

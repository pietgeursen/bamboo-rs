pub use crate::entry_store::{EntryStore, Error as EntryStoreError};
use ssb_crypto::{PublicKey, SecretKey};

pub mod add;
pub mod publish;
pub mod error;

pub use error::*;
pub use add::*;
pub use publish::*;

pub struct Log<Store: EntryStore> {
    pub store: Store,
    pub public_key: PublicKey,
    secret_key: Option<SecretKey>,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store, public_key: PublicKey, secret_key: Option<SecretKey>) -> Log<Store> {
        Log {
            store,
            public_key,
            secret_key,
        }
    }
}

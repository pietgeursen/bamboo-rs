use snafu::{Backtrace, Snafu};
pub use crate::entry::{Entry, Error as EntryError};
pub use crate::entry_store::{EntryStore, Error as EntryStoreError};

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(in crate::log)")]
pub enum Error {
    #[snafu(display(
        "Invalid sequence number, it might not exist or it might be 0. Sequences start at 1. Got sequence: {}",
        seq_num
    ))]
    GetEntryFailed {
        seq_num: u64,
        source: EntryStoreError,
    },
    #[snafu(display(
        "Entry at seq_num {} not found",
        seq_num
    ))]
    EntryNotFound {
        seq_num: u64,
    },
    #[snafu(display(
        "Error unwrapping a None value of the secret key, it must be provided in the constructor"
    ))]
    TriedToPublishWithoutSecretKey,
    #[snafu(display("Failed to encode the entry for signing"))]
    EncodingForSigningFailed { source: EntryError },
    #[snafu(display("Failed to encode the entry for storing in the log"))]
    EncodingForStoringFailed { source: EntryError },
    #[snafu(display("Failed to append the entry to the log"))]
    AppendFailed { source: EntryStoreError },
    #[snafu(display(
        "Attempted to publish a message on a feed that has published an end of feed message"
    ))]
    PublishAfterEndOfFeed { backtrace: Backtrace },
    #[snafu(display("Failed to decode the previous message as an entry"))]
    PreviousDecodeFailed { source: EntryError },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;



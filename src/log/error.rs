pub use crate::entry::{Entry, Error as EntryError};
pub use crate::entry_store::{EntryStore, Error as EntryStoreError};
use snafu::{Backtrace, Snafu};

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
    #[snafu(display("Entry at seq_num {} not found", seq_num))]
    EntryNotFound { seq_num: u64 },
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

    #[snafu(display("Failed to decode the entry message as an entry"))]
    AddEntryDecodeFailed { source: EntryError },
    #[snafu(display(
        "The provided payload length did not match the payload length encoded in the entry"
    ))]
    AddEntryPayloadLengthDidNotMatch { backtrace: Backtrace },
    #[snafu(display(
        "The provided lipmaa hash did not match the payload hash encoded in the entry"
    ))]
    AddEntryLipmaaHashDidNotMatch,
    #[snafu(display(
        "The provided payload hash did not match the payload hash encoded in the entry"
    ))]
    AddEntryPayloadHashDidNotMatch { backtrace: Backtrace },
    #[snafu(display(
        "The backlink hash in the store did not match the backlink hash encoded in the entry"
    ))]
    AddEntryBacklinkHashDidNotMatch { backtrace: Backtrace },
    #[snafu(display("The entry store failed to get the backlink"))]
    AddEntryGetBacklinkError { source: EntryStoreError },
    #[snafu(display("The entry store failed to get the lipmaalink"))]
    AddEntryGetLipmaalinkError { source: EntryStoreError },
    #[snafu(display("There is no lipmaalink entry in the store with that seq num"))]
    AddEntryNoLipmaalinkInStore,
    #[snafu(display("Couldn't decode the lipmaa link from the store"))]
    AddEntryDecodeLipmaalinkFromStore{source: EntryError },
    #[snafu(display("The author in the entry did not match the author in the lipmaa link"))]
    AddEntryAuthorDidNotMatchLipmaaEntry,
    #[snafu(display("The entry store failed to get the last entry"))]
    AddEntryGetLastEntryError { source: EntryStoreError },
    #[snafu(display("Attempted to add an entry to a feed that has published an end of feed message"))]
    AddEntryToFeedThatHasEnded { backtrace: Backtrace },
    #[snafu(display("Attempted to add an entry with invalid signature"))]
    AddEntryWithInvalidSignature { backtrace: Backtrace },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

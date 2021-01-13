use crate::entry::decode::Error as EntryDecodeError;
use crate::entry::encode::Error as EntryEncodeError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    PublishAfterEndOfFeed,
    PublishWithIncorrectLogId,
    PublishWithoutSecretKey,
    PublishWithoutKeypair,
    PublishWithoutLipmaaEntry,
    PublishWithoutBacklinkEntry,
    DecodeBacklinkEntry {
        source: EntryDecodeError,
    },
    #[snafu(display(
        "Could not encode the entry into the out buffer. Buffer len: {}, Encoding error: {}",
        buffer_size,
        source
    ))]
    EncodeEntryToOutBuffer {
        source: EntryEncodeError,
        buffer_size: usize,
    },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

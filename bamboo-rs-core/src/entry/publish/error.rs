use crate::entry::decode::Error as EntryDecodeError;
use crate::entry::encode::Error as EntryEncodeError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(super)")]
pub enum Error {
    #[snafu(display("Attempting to publish to a feed that is ended (previous entry has set the `is_end_of_feed` bit"))]
    PublishAfterEndOfFeed,
    #[snafu(display("Attempting to publish an entry with a different log_id to the backlink"))]
    PublishWithIncorrectBacklinkLogId,
    #[snafu(display("Attempting to publish an entry with a different log_id to the lipmaa link"))]
    PublishWithIncorrectLipmaaLinkLogId,
    #[snafu(display("Attempting to publish using a keypair that does not have a secret key"))]
    PublishWithoutSecretKey,
    #[snafu(display("Attempting to publish without a keypair"))]
    PublishWithoutKeypair,
    #[snafu(display("Attempting to publish an entry with a different keypair than the backlink"))]
    PublishKeypairDidNotMatchBacklinkPublicKey,
    #[snafu(display("Attempting to publish an entry with a different keypair than the lipmaa link"))]
    PublishKeypairDidNotMatchLipmaaLinkPublicKey,
    #[snafu(display("Attempting to publish an entry that needs a lipmaa link but None provided"))]
    PublishWithoutLipmaaEntry,
    #[snafu(display("Attempting to publish an entry that needs a backlink but None provided"))]
    PublishWithoutBacklinkEntry,
    #[snafu(display("Failed to decode backlink, encoding error: {}", source))]
    DecodeBacklinkEntry {
        source: EntryDecodeError,
    },
    #[snafu(display("Failed to decode lipmaa link, encoding error: {}", source))]
    DecodeLipmaaEntry {
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

use crate::entry::decode::Error as DecodeError;
use crate::entry::encode::Error as EncodeError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    #[snafu(display("Decode entry signature failed"))]
    DecodeSigError,
    #[snafu(display("Entry signature is invalid!"))]
    InvalidSignature,
    #[snafu(display("The payload hash encoded in the entry does not match the payload provided"))]
    PayloadHashDidNotMatch {},
    #[snafu(display("The payload length encoded in the entry (expected) does not match the payload provided (actual). Expected: {}, actual: {}", expected, actual))]
    PayloadLengthDidNotMatch { actual: usize, expected: u64 },
    #[snafu(display(
        "The lipmaa hash encoded in the entry does not match the lipmaa entry provided"
    ))]
    LipmaaHashDoesNotMatch {},
    #[snafu(display("Decode lipmaa entry failed: {}", source))]
    DecodeLipmaaEntry { source: DecodeError },
    #[snafu(display(
        "Lipmaa entry log_id does not match entry log_id: entry log_id: {}, lipmaa log_id: {}",
        expected,
        actual
    ))]
    LipmaaLogIdDoesNotMatch { actual: u64, expected: u64 },
    #[snafu(display("Lipmaa author does not match entry author"))]
    LipmaaAuthorDoesNotMatch {},
    #[snafu(display("Lipmaa link required but not provided"))]
    LipmaaLinkRequired,
    #[snafu(display("Failed to decode backlink entry: {}", source))]
    DecodeBacklinkEntry { source: DecodeError },
    #[snafu(display(
        "Backlink entry log_id does not match entry log_id: entry log_id: {}, lipmaa log_id: {}",
        expected,
        actual
    ))]
    BacklinkLogIdDoesNotMatch { actual: u64, expected: u64 },
    #[snafu(display("Backlink author does not match entry author"))]
    BacklinkAuthorDoesNotMatch,
    #[snafu(display("Entry was published after the feed was declared ended by setting the `is_end_of_feed` bit in a previous message"))]
    PublishedAfterEndOfFeed,
    #[snafu(display(
        "The backlink hash encoded in the entry does not match the lipmaa entry provided"
    ))]
    BacklinkHashDoesNotMatch {},
    #[snafu(display("Backlink link required but not provided"))]
    BackLinkRequired,
    #[snafu(display("Failed to decode entry: {}", source))]
    DecodeEntry { source: DecodeError },
    #[snafu(display("Failed to encode entry for signing: {}", source))]
    EncodeEntryForSigning { source: EncodeError },
    #[snafu(display("The entry is invalid."))]
    UnknownError,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

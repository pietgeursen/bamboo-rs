use crate::entry::decode::Error as DecodeError;
use crate::entry::encode::Error as EncodeError;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    DecodeSigError,
    InvalidSignature,
    PayloadHashDidNotMatch {},
    PayloadLengthDidNotMatch { actual: usize, expected: u64 },
    LipmaaHashDoesNotMatch {},
    DecodeLipmaaEntry { source: DecodeError },
    LipmaaLogIdDoesNotMatch { actual: u64, expected: u64 },
    LipmaaAuthorDoesNotMatch {},
    LipmaaLinkRequired,
    DecodeBacklinkEntry { source: DecodeError },
    BacklinkLogIdDoesNotMatch { actual: u64, expected: u64 },
    BacklinkAuthorDoesNotMatch,
    PublishedAfterEndOfFeed,
    BacklinkHashDoesNotMatch {},
    BackLinkRequired,
    DecodeEntry { source: DecodeError },
    EncodeEntryForSigning { source: EncodeError },
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

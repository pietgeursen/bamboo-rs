use crate::signature::Error as SigError;
use snafu::Snafu;
use yamf_hash::error::Error as YamfHashError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    EncodeBufferLength,
    EncodeLipmaaError { source: YamfHashError },
    EncodeBacklinkError { source: YamfHashError },
    EncodeEntryHasBacklinksWhenSeqZero,
    EncodePayloadSizeError,
    EncodePayloadHashError { source: YamfHashError },
    EncodeIsEndOfFeedError,
    EncodeAuthorError,
    EncodeLogIdError,
    EncodeSigError { source: SigError },
    EncodeSeqError,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

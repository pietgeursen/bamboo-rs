use crate::signature::error::Error as SigError;
use snafu::Snafu;
use yamf_hash::error::Error as YamfHashError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    #[snafu(display("Could not decode payload hash {}", source))]
    DecodePayloadHashError {
        source: YamfHashError,
    },
    DecodePayloadSizeError,
    DecodeLogIdError,
    DecodeAuthorError,
    DecodeSeqError,
    DecodeSeqIsZero,
    DecodeBacklinkError {
        source: YamfHashError,
    },
    #[snafu(display("Could not decode lipmaa link yamf hash {}", source))]
    DecodeLipmaaError {
        source: YamfHashError,
    },
    DecodeSigError {
        source: SigError,
    },

    DecodeInputIsLengthZero,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

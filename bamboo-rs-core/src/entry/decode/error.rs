use crate::signature::error::Error as SigError;
use snafu::Snafu;
use varu64::DecodeError as Varu64Error;
use yamf_hash::error::Error as YamfHashError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(super)")]
pub enum Error {
    #[snafu(display("Could not decode payload hash {}", source))]
    DecodePayloadHashError { source: YamfHashError },
    #[snafu(display(
        "Could not decode payload size, error with varu64 encoding: {}",
        source
    ))]
    DecodePayloadSizeError { source: Varu64Error },
    #[snafu(display("Could not decode log_id, error with varu64 encoding: {}", source))]
    DecodeLogIdError { source: Varu64Error },
    #[snafu(display("Could not decode author public key from bytes"))]
    DecodeAuthorError,
    #[snafu(display(
        "Could not decode entry sequence number, error with varu64 encoding: {}",
        source
    ))]
    DecodeSeqError { source: Varu64Error },
    #[snafu(display("Entry sequence must be larger than 0 but was {}", seq_num))]
    DecodeSeqIsZero { seq_num: u64 },
    #[snafu(display("Could not decode backlink yamf hash: {}", source))]
    DecodeBacklinkError { source: YamfHashError },
    #[snafu(display("Could not decode lipmaa link yamf hash {}", source))]
    DecodeLipmaaError { source: YamfHashError },
    #[snafu(display("Could not decode signature: {}", source))]
    DecodeSigError { source: SigError },
    #[snafu(display("Bytes to decode had length of 0"))]
    DecodeInputIsLengthZero,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

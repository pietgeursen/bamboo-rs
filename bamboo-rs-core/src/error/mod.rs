use snafu::Snafu;
use yamf_hash::error::Error as YamfHashError;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
#[repr(C)]
pub enum Error {
    NoError,
    EncodeIsEndOfFeedError,
    EncodePayloadHashError{source: YamfHashError},
    EncodePayloadSizeError,
    EncodeAuthorError,
    EncodeSeqError,
    EncodeLogIdError,
    EncodeBacklinkError{source: YamfHashError},
    EncodeLipmaaError{source: YamfHashError},
    EncodeSigError,
    EncodeEntryHasBacklinksWhenSeqZero,
    EncodeBufferLength,
    PublishAfterEndOfFeed,
    PublishWithIncorrectLogId,
    PublishWithoutSecretKey,
    PublishWithoutKeypair,
    PublishWithoutLipmaaEntry,
    PublishWithoutBacklinkEntry,

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
    DecodeSsbSigError,

    DecodeInputIsLengthZero,

    GetEntryFailed,
    EntryNotFound,
    AppendFailed,
    PublishNewEntryFailed,
    AddEntryDecodeFailed,
    AddEntryPayloadLengthDidNotMatch,
    AddEntryLipmaaHashDidNotMatch,
    AddEntryPayloadHashDidNotMatch,
    AddEntryBacklinkHashDidNotMatch,
    AddEntryNoLipmaalinkInStore,
    AddEntryDecodeLipmaalinkFromStore,
    AddEntryAuthorDidNotMatchLipmaaEntry,
    AddEntryLogIdDidNotMatchLipmaaEntry,
    AddEntryAuthorDidNotMatchPreviousEntry,
    AddEntryLogIdDidNotMatchPreviousEntry,
    AddEntryDecodeLastEntry,
    AddEntryToFeedThatHasEnded,
    AddEntryWithInvalidSignature,
    AddEntrySigNotValidError,

    DecodeError,
    EncodeWriteError,
    EncodeError,
    SignatureInvalid,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

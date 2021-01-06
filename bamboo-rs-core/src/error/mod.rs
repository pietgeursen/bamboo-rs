use snafu::Snafu;
use yamf_hash::error::Error as YamfHashError;

#[derive(Debug, Serialize, Snafu)]
#[snafu(visibility = "pub(crate)")]
#[repr(C)]
pub enum Error {
    NoError,
    EncodeIsEndOfFeedError,
    EncodePayloadHashError,
    EncodePayloadSizeError,
    EncodeAuthorError,
    EncodeSeqError,
    EncodeLogIdError,
    EncodeBacklinkError,
    EncodeLipmaaError,
    EncodeSigError,
    EncodeEntryHasBacklinksWhenSeqZero,
    EncodeBufferLength,
    PublishAfterEndOfFeed,
    PublishWithIncorrectLogId,
    PublishWithoutSecretKey,
    PublishWithoutKeypair,
    PublishWithoutLipmaaEntry,
    PublishWithoutBacklinkEntry,

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
    #[snafu(display("Could not decode lipmaa link yamf hash {:?}", source))]
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

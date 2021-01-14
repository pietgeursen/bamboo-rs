use snafu::Snafu;
use bamboo_rs_core::entry::decode::Error as DecodeError;

#[derive(Debug, Snafu)]
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

    DecodePayloadHashError,
    DecodePayloadSizeError,
    DecodeLogIdError,
    DecodeAuthorError,
    DecodeSeqError,
    DecodeSeqIsZero,
    DecodeBacklinkError,
    DecodeLipmaaError,
    DecodeSigError,

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


impl From<DecodeError> for Error {
    fn from(error: DecodeError) -> Error {
        unimplemented!();
    }
}


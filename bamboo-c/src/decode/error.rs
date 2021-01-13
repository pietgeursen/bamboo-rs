use bamboo_rs_core::entry::decode::Error as BambooDecodeError;

#[repr(C)]
/// cbindgen:prefix-with-name=true
pub enum DecodeError {
    NoError,

    PayloadHashError,
    PayloadSizeError,
    LogIdError,
    AuthorError,
    SeqError,
    SeqIsZero,
    BacklinkError,
    LipmaaError,
    SigError,
    InputIsLengthZero,
}

impl From<BambooDecodeError> for DecodeError {
    fn from(err: BambooDecodeError) -> DecodeError {
        match err {
            BambooDecodeError::DecodePayloadHashError { .. } => DecodeError::PayloadHashError,
            BambooDecodeError::DecodePayloadSizeError => DecodeError::PayloadSizeError,
            BambooDecodeError::DecodeLogIdError => DecodeError::LogIdError,
            BambooDecodeError::DecodeAuthorError => DecodeError::AuthorError,
            BambooDecodeError::DecodeSeqError => DecodeError::SeqError,
            BambooDecodeError::DecodeSeqIsZero => DecodeError::SeqIsZero,
            BambooDecodeError::DecodeBacklinkError { .. } => DecodeError::BacklinkError,
            BambooDecodeError::DecodeLipmaaError { .. } => DecodeError::LipmaaError,
            BambooDecodeError::DecodeSigError { .. } => DecodeError::SigError,
            BambooDecodeError::DecodeInputIsLengthZero => DecodeError::InputIsLengthZero,
        }
    }
}

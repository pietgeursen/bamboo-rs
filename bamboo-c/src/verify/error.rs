use bamboo_rs_core::entry::verify::Error as BambooVerifyError;

#[repr(C)]
/// cbindgen:prefix-with-name=true
pub enum VerifyError {
    NoError,

    DecodeSigError,
    InvalidSignature,
    PayloadHashDidNotMatch,
    PayloadLengthDidNotMatch,
    LipmaaHashDoesNotMatch,
    DecodeLipmaaEntry,
    LipmaaLogIdDoesNotMatch,
    LipmaaAuthorDoesNotMatch,
    LipmaaLinkRequired,
    DecodeBacklinkEntry,
    BacklinkLogIdDoesNotMatch,
    BacklinkAuthorDoesNotMatch,
    PublishedAfterEndOfFeed,
    BacklinkHashDoesNotMatch,
    BackLinkRequired,
    DecodeEntry,
    EncodeEntryForSigning,
    UnknownError,
}

impl From<BambooVerifyError> for VerifyError {
    fn from(err: BambooVerifyError) -> VerifyError {
        match err {
            BambooVerifyError::DecodeSigError { .. } => VerifyError::DecodeSigError,
            BambooVerifyError::InvalidSignature { .. } => VerifyError::InvalidSignature,
            BambooVerifyError::PayloadHashDidNotMatch { .. } => VerifyError::PayloadHashDidNotMatch,
            BambooVerifyError::PayloadLengthDidNotMatch { .. } => {
                VerifyError::PayloadLengthDidNotMatch
            }
            BambooVerifyError::LipmaaHashDoesNotMatch { .. } => VerifyError::LipmaaHashDoesNotMatch,
            BambooVerifyError::DecodeLipmaaEntry { .. } => VerifyError::DecodeLipmaaEntry,
            BambooVerifyError::LipmaaLogIdDoesNotMatch { .. } => {
                VerifyError::LipmaaLogIdDoesNotMatch
            }
            BambooVerifyError::LipmaaAuthorDoesNotMatch { .. } => {
                VerifyError::LipmaaAuthorDoesNotMatch
            }
            BambooVerifyError::LipmaaLinkRequired => VerifyError::LipmaaLinkRequired,
            BambooVerifyError::DecodeBacklinkEntry { .. } => VerifyError::DecodeBacklinkEntry,
            BambooVerifyError::BacklinkLogIdDoesNotMatch { .. } => {
                VerifyError::BacklinkLogIdDoesNotMatch
            }
            BambooVerifyError::PublishedAfterEndOfFeed => VerifyError::PublishedAfterEndOfFeed,
            BambooVerifyError::BacklinkHashDoesNotMatch { .. } => {
                VerifyError::BacklinkHashDoesNotMatch
            }
            BambooVerifyError::BackLinkRequired => VerifyError::BackLinkRequired,
            BambooVerifyError::DecodeEntry { .. } => VerifyError::DecodeEntry,
            BambooVerifyError::EncodeEntryForSigning { .. } => VerifyError::EncodeEntryForSigning,
            BambooVerifyError::BacklinkAuthorDoesNotMatch => {
                VerifyError::BacklinkAuthorDoesNotMatch
            }
            BambooVerifyError::UnknownError => VerifyError::UnknownError
        }
    }
}

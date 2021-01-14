use bamboo_rs_core::entry::publish::Error as BambooPublishError;

#[repr(C)]
/// cbindgen:prefix-with-name=true
pub enum PublishError {
    NoError,

    PublishWithoutKeypair,
    PublishAfterEndOfFeed,
    PublishWithIncorrectLogId,
    PublishWithoutSecretKey,
    PublishWithoutLipmaaEntry,
    PublishWithoutBacklinkEntry,
    DecodeBacklinkEntry,
    EncodeEntryToOutBuffer,
    PublishKeypairDidNotMatchBacklinkPublicKey,
    PublishKeypairDidNotMatchLipmaaLinkPublicKey,
    DecodeLipmaaEntry,
    PublishWithIncorrectBacklinkLogId,
    PublishWithIncorrectLipmaaLinkLogId,
}

impl From<BambooPublishError> for PublishError {
    fn from(err: BambooPublishError) -> PublishError {
        match err {
            BambooPublishError::PublishWithoutKeypair => PublishError::PublishWithoutKeypair,
            BambooPublishError::PublishAfterEndOfFeed => PublishError::PublishAfterEndOfFeed,
            BambooPublishError::PublishWithIncorrectBacklinkLogId => {
                PublishError::PublishWithIncorrectLogId
            }
            BambooPublishError::PublishWithIncorrectLipmaaLinkLogId => {
                PublishError::PublishWithIncorrectLipmaaLinkLogId
            }
            BambooPublishError::PublishWithoutSecretKey => PublishError::PublishWithoutSecretKey,
            BambooPublishError::PublishWithoutLipmaaEntry => {
                PublishError::PublishWithoutLipmaaEntry
            }
            BambooPublishError::DecodeBacklinkEntry { .. } => PublishError::DecodeBacklinkEntry,
            BambooPublishError::EncodeEntryToOutBuffer { .. } => {
                PublishError::EncodeEntryToOutBuffer
            }
            BambooPublishError::PublishWithoutBacklinkEntry => {
                PublishError::PublishWithoutBacklinkEntry
            },
            BambooPublishError::DecodeLipmaaEntry { .. } => PublishError::DecodeLipmaaEntry,
            BambooPublishError::PublishKeypairDidNotMatchBacklinkPublicKey => PublishError::PublishKeypairDidNotMatchBacklinkPublicKey,
            BambooPublishError::PublishKeypairDidNotMatchLipmaaLinkPublicKey => PublishError::PublishKeypairDidNotMatchLipmaaLinkPublicKey,
        }
    }
}

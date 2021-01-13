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
}

impl From<BambooPublishError> for PublishError {
    fn from(err: BambooPublishError) -> PublishError {
        match err {
            BambooPublishError::PublishWithoutKeypair => PublishError::PublishWithoutKeypair,
            BambooPublishError::PublishAfterEndOfFeed => PublishError::PublishAfterEndOfFeed,
            BambooPublishError::PublishWithIncorrectLogId => PublishError::PublishWithIncorrectLogId,
            BambooPublishError::PublishWithoutSecretKey => PublishError::PublishWithoutSecretKey,
            BambooPublishError::PublishWithoutLipmaaEntry => PublishError::PublishWithoutLipmaaEntry,
            BambooPublishError::DecodeBacklinkEntry { .. } => PublishError::DecodeBacklinkEntry,
            BambooPublishError::EncodeEntryToOutBuffer { .. } => PublishError::EncodeEntryToOutBuffer,
            BambooPublishError::PublishWithoutBacklinkEntry => PublishError::PublishWithoutBacklinkEntry,
        }
    }
}

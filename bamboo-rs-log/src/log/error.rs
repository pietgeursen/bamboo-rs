use crate::entry_store::EntryStorer;
use bamboo_rs_core::entry::decode::Error as DecodeError;
use bamboo_rs_core::entry::publish::Error as PublishError;
use bamboo_rs_core::entry::verify::Error as VerifyError;
use core::fmt::Debug;
use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error<ES: EntryStorer + Debug> {
    AddEntryDecodeFailed { source: DecodeError },
    AddEntryGetLipmaaEntry { source: ES::Error },
    AddEntryGetBacklinkEntry { source: ES::Error },
    AddEntryFailedVerification { source: VerifyError },
    AddEntryFailedToAddEntryToLog { source: ES::Error },
    AddBatchGetLipmaaAndBacklinkEntries { source: ES::Error },
    PublishEntryGetLipmaaAndBacklinkEntries { source: ES::Error },
    PublishEntryGetBacklinkEntry { source: ES::Error },
    PublishNewEntryFailed { source: PublishError },
    PublishEntryAppendFailed { source: ES::Error },
    PublishWithoutKeypair,
}

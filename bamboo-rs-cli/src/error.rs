use snafu::Snafu;
use std::path::PathBuf;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("Could not create keypair from bytes"))]
    KeypairCreate {},
    #[snafu(display("Could not publish entry"))]
    Publish {},
    #[snafu(display("Entry was invalid"))]
    Verify {},
    #[snafu(display("Could not open entry file at {}: {}", filename.display(), source))]
    DecodeEntryFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open entry file at {}: {}", filename.display(), source))]
    EntryFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open secret key file at {}: {}", filename.display(), source))]
    SecretKeyFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open public key file at {}: {}", filename.display(), source))]
    PubKeyFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open payload file at {}: {}", filename.display(), source))]
    PayloadFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open previous entry file at {}: {}", filename.display(), source))]
    PreviousEntryFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not open lipmaa entry file at {}: {}", filename.display(), source))]
    LipmaaEntryFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not parse sequence number {}", source))]
    ParseSequenceNumber { source: std::num::ParseIntError },
    #[snafu(display("Could not parse log id {}", source))]
    ParseLogId { source: std::num::ParseIntError },
    #[snafu(display("Could not decode entry: {:?}", error))]
    DecodeEntry { error: bamboo_rs_core::error::Error },
    #[snafu(display("Could not decode previous entry: {:?}", error))]
    DecodePreviousEntry { error: bamboo_rs_core::error::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

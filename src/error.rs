use snafu::Snafu;
use std::path::PathBuf;
use varu64::DecodeError as varu64DecodeError;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Invalid sequence number {}", seq_num))]
    GetEntrySequenceInvalid { seq_num: u64 },
    #[snafu(display("IO error when getting entry. {}: {}", filename.display(), source))]
    GetEntryIoError {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("IO error when appending entry. {}: {}", filename.display(), source))]
    AppendEntryIoError {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Error when decoding entry. {}: {}", filename.display(), source))]
    DecodeError {
        filename: PathBuf,
        source: varu64DecodeError,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

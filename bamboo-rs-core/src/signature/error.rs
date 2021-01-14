use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(crate)")]
pub enum Error {
    DecodeError,
    EncodeWriteError,
    EncodeError,
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

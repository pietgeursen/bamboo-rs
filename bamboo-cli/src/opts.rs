use std::path::PathBuf;
use structopt::StructOpt;

/// CLI for publishing and verifying bamboo entries.
///
/// Includes helpers for:
/// - Calculating limpaa numbers.
/// - Generating a new cryptographic key pair.
/// - Decoding an entry and printing it to std out as json.
#[derive(Debug, StructOpt)]
#[structopt(name = "bamboo-cli", verbatim_doc_comment, rename_all = "kebab")]
pub enum Opts {
    /// Publish a new entry and write the bytes to stdout.
    Publish {
        /// The file containing the payload for this entry.
        #[structopt(long, short = "a", parse(from_os_str))]
        payload_file: PathBuf,

        /// The file containing the entry previous to this entry. Said another way, it's the most recently published entry.
        #[structopt(
            long,
            short = "v",
            parse(from_os_str),
            required_unless("is-start-of-feed")
        )]
        previous_entry_file: Option<PathBuf>,

        /// The file containing the lipmaa entry for this entry. You can calculate the lipmaa number by using the lipmaa command.
        #[structopt(
            long,
            short = "l",
            parse(from_os_str),
            required_unless("is-start-of-feed")
        )]
        lipmaa_entry_file: Option<PathBuf>,

        /// The file containing the public key of the author of this entry.
        #[structopt(long, short = "p", parse(from_os_str))]
        public_key_file: PathBuf,

        /// The file containing the secret key of the author of this entry.
        #[structopt(long, short = "s", parse(from_os_str))]
        secret_key_file: PathBuf,

        /// When publishing the very first entry in a feed. If set, then omit the previous-entry-file and lipmaa-entry-file arguments.
        #[structopt(long)]
        is_start_of_feed: bool,

        /// A feed can publish an entry that signals the feed is finished. No more entries can be published to the feed. Requires --force.
        #[structopt(long, requires("force"))]
        is_end_of_feed: bool,

        /// Each author can publish many different independant feeds that are identified by their log-id, a number from 0 to 2^64-1.
        #[structopt(long, default_value = "0")]
        log_id: u64,

        /// Force publishing an is-end-of-feed message.
        #[structopt(long)]
        force: bool,
    },

    /// Verify an entry is a valid bamboo entry with a correct cryptographic signature.
    Verify {
        /// The file containing the bamboo entry to verify.
        #[structopt(long, short = "e", parse(from_os_str))]
        entry_file: PathBuf,

        /// The file containing the payload for this entry.
        #[structopt(long, short = "a", parse(from_os_str))]
        payload_file: Option<PathBuf>,

        /// The file containing the entry previous to this entry. Said another way, it's the most recently published entry.
        #[structopt(long, short = "v", parse(from_os_str))]
        previous_entry_file: Option<PathBuf>,

        /// The file containing the lipmaa entry for this entry. You can calculate the lipmaa number by using the lipmaa command.
        #[structopt(long, short = "l", parse(from_os_str))]
        lipmaa_entry_file: Option<PathBuf>,
    },

    /// Decode a binary bamboo entry and print it out as json.
    Decode {
        /// The file with an entry to decode.
        entry_file: String,
    },

    /// Calculate the hash of the bytes in a file. Useful if you want to know the hash of an entry
    /// or a payload. Uses the blake2b hashing algorithm.
    Hash {
        /// The file path of the file to hash.
        file: String,
    },

    /// Calculate the lipmaa number for the provided sequence number.
    Lipmaa {
        /// The sequence number.
        sequence: String,
    },

    /// Generate a new cryptographic key-pair used for publishing entries. Stores them in two new files.
    GenerateKeys {
        /// The path to the file which will store the new public key.
        #[structopt(long, short = "p", parse(from_os_str))]
        public_key_file: PathBuf,

        /// The path to the file which will store the new secret key.
        #[structopt(long, short = "s", parse(from_os_str))]
        secret_key_file: PathBuf,
    },
}

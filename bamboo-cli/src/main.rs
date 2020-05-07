#[macro_use]
extern crate clap;
use bamboo_core::entry::MAX_ENTRY_SIZE;
use bamboo_core::{decode, lipmaa, publish, verify, Keypair};
use clap::App;
use rand::rngs::OsRng;
use snafu::{ResultExt, Snafu};
use std::fs::File;
use std::io::prelude::*;
use std::path::PathBuf;

#[derive(Debug, Snafu)]
enum Error {
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
    DecodeEntry { error: bamboo_core::error::Error },
    #[snafu(display("Could not decode previous entry: {:?}", error))]
    DecodePreviousEntry { error: bamboo_core::error::Error },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

    match matches.subcommand_matches("verify") {
        Some(matches) => {
            let entry_path = matches.value_of("entry-file").unwrap();
            let entry_bytes = read_file(entry_path)
                .context(EntryFile {
                    filename: entry_path,
                })?;

            let payload = matches
                .value_of("payload-file")
                .map(|payload_path| {
                    read_file(payload_path)
                        .context(PayloadFile {
                            filename: payload_path,
                        })
                })
                .transpose()?;

            let previous = matches
                .value_of("previous-entry-file")
                .map(|previous_path| {
                    read_file(previous_path)
                        .context(PreviousEntryFile {
                            filename: previous_path,
                        })
                })
                .transpose()?;

            let lipmaa = matches
                .value_of("lipmaa-entry-file")
                .map(|lipmaa_path| {
                    read_file(lipmaa_path)
                        .context(PreviousEntryFile {
                            filename: lipmaa_path,
                        })
                })
                .transpose()?;

            let is_valid = verify(
                &entry_bytes,
                payload.as_deref(),
                lipmaa.as_deref(),
                previous.as_deref(),
            )
            .map_err(|_| snafu::NoneError)
            .context(Verify)?;

            if !is_valid {
                return Err(Error::Verify {});
            } else {
                return Ok(());
            }
        }

        None => (),
    }

    match matches.subcommand_matches("publish") {
        Some(matches) => {
            let sk_path = matches.value_of("secret-key-file").unwrap();
            let sk_bytes = read_file(sk_path)
                .context(SecretKeyFile { filename: sk_path })?;

            let pk_path = matches.value_of("public-key-file").unwrap();
            let pk_bytes = read_file(pk_path)
                .context(PubKeyFile { filename: pk_path })?;

            let payload_path = matches.value_of("payload-file").unwrap();
            let payload_bytes = read_file(payload_path)
                .context(PayloadFile { filename: payload_path })?;

            let is_start_of_feed = matches.is_present("is-start-of-feed");
            let is_end_of_feed = matches.is_present("is-end-of-feed");

            let log_id_str = matches.value_of("log-id").unwrap_or("0");
            let log_id = u64::from_str_radix(log_id_str, 10).context(ParseLogId)?;

            let (previous, lipmaa, last_seq_num) = if is_start_of_feed {
                (None, None, 0)
            } else {
                let previous_path = matches.value_of("previous-entry-file").unwrap();
                let previous_bytes = read_file(previous_path)
                    .context(PayloadFile { filename: previous_path })?;

                let lipmaa_path = matches.value_of("lipmaa-entry-file").unwrap();
                let lipmaa_bytes = read_file(lipmaa_path)
                    .context(LipmaaEntryFile { filename: lipmaa_path })?;

                let previous_entry = decode(&previous_bytes)
                    .map_err(|err| Error::DecodePreviousEntry { error: err })?;

                let seq_num = previous_entry.seq_num.clone();

                (Some(previous_bytes), Some(lipmaa_bytes), seq_num)
            };

            let mut entry_buff: [u8; MAX_ENTRY_SIZE] = [0; MAX_ENTRY_SIZE];

            let key_pair = Keypair::from_bytes(&[sk_bytes, pk_bytes].concat())
                .map_err(|_| snafu::NoneError)
                .context(KeypairCreate)?;

            let entry_size = publish(
                &mut entry_buff,
                Some(&key_pair),
                log_id,
                &payload_bytes,
                is_end_of_feed,
                last_seq_num,
                lipmaa.as_deref(),
                previous.as_deref(),
            )
            .map_err(|_| snafu::NoneError)
            .context(Publish)?;

            std::io::stdout()
                .write_all(&entry_buff[..entry_size])
                .unwrap();
        }

        None => (),
    }

    match matches.subcommand_matches("generate-keys") {
        Some(matches) => {
            let mut csprng = OsRng {};
            let key_pair = Keypair::generate(&mut csprng);

            let sk_path = matches.value_of("secret-key-file").unwrap();
            let pk_path = matches.value_of("public-key-file").unwrap();

            let mut sk_file = File::create(sk_path).context(SecretKeyFile { filename: sk_path })?;
            let mut pk_file = File::create(pk_path).context(PubKeyFile { filename: pk_path })?;

            sk_file.write_all(&key_pair.secret.to_bytes()).unwrap();
            pk_file.write_all(&key_pair.public.to_bytes()).unwrap();
        }
        None => (),
    }

    match matches.subcommand_matches("lipmaa") {
        Some(matches) => match matches.value_of("sequence") {
            Some(sequence) => {
                let res = u64::from_str_radix(sequence, 10).context(ParseSequenceNumber)?;

                println!("{}", lipmaa(res))
            }
            None => (),
        },
        None => (),
    }

    match matches.subcommand_matches("decode") {
        Some(matches) => match matches.value_of("entry-file") {
            Some(entry) => {
                let entry = read_file(entry)
                    .context(DecodeEntryFile { filename: entry })?;
                let decoded = decode(&entry).map_err(|err| Error::DecodeEntry { error: err })?;

                println!(
                    "{}",
                    serde_json::to_string_pretty(&decoded)
                        .expect("Unable to serialize decoded entry")
                );
            }
            None => (),
        },
        None => (),
    }

    Ok(())
}

fn read_file(path: &str)-> Result<Vec<u8>, std::io::Error>
{
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("Unable to read to end of file");
    Ok(bytes)
}

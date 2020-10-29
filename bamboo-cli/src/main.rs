use bamboo_core::entry::MAX_ENTRY_SIZE;
use bamboo_core::{decode, lipmaa, publish, verify, YamfHash, Keypair};
use blake2b_simd::blake2b;
use rand::rngs::OsRng;
use snafu::ResultExt;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use structopt::StructOpt;

mod error;
mod opts;

use error::*;
use opts::*;

fn main() -> Result<()> {
    let opts = Opts::from_args();

    match opts {
        Opts::Publish {
            payload_file,
            previous_entry_file,
            lipmaa_entry_file,
            is_start_of_feed,
            is_end_of_feed,
            log_id,
            public_key_file,
            secret_key_file,
            force: _,
        } => {
            let sk_bytes = read_file(&secret_key_file).context(SecretKeyFile {
                filename: secret_key_file,
            })?;
            let pk_bytes = read_file(&public_key_file).context(PubKeyFile {
                filename: public_key_file,
            })?;

            let payload_bytes = read_file(&payload_file).context(PayloadFile {
                filename: payload_file,
            })?;

            let (previous, lipmaa, last_seq_num) = if is_start_of_feed {
                (None, None, None)
            } else {
                let previous_entry_file = previous_entry_file.unwrap();
                let previous_bytes = read_file(&previous_entry_file).context(PayloadFile {
                    filename: previous_entry_file,
                })?;

                let lipmaa_entry_file = lipmaa_entry_file.unwrap();
                let lipmaa_bytes = read_file(&lipmaa_entry_file).context(LipmaaEntryFile {
                    filename: lipmaa_entry_file,
                })?;

                let previous_entry = decode(&previous_bytes)
                    .map_err(|err| Error::DecodePreviousEntry { error: err })?;

                let seq_num = previous_entry.seq_num.clone();

                (Some(previous_bytes), Some(lipmaa_bytes), Some(seq_num))
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
        Opts::Verify {
            entry_file,
            payload_file,
            previous_entry_file,
            lipmaa_entry_file,
        } => {
            let entry_bytes = read_file(&entry_file).context(EntryFile {
                filename: entry_file,
            })?;

            let payload = payload_file
                .map(|payload_file| {
                    read_file(&payload_file).context(PayloadFile {
                        filename: payload_file,
                    })
                })
                .transpose()?;

            let previous = previous_entry_file
                .map(|previous_path| {
                    read_file(&previous_path).context(PreviousEntryFile {
                        filename: previous_path,
                    })
                })
                .transpose()?;

            let lipmaa = lipmaa_entry_file
                .map(|lipmaa_path| {
                    read_file(&lipmaa_path).context(PreviousEntryFile {
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
        Opts::Decode { entry_file } => {
            let entry = read_file(&entry_file).context(DecodeEntryFile {
                filename: entry_file,
            })?;
            let decoded = decode(&entry).map_err(|err| Error::DecodeEntry { error: err })?;

            println!(
                "{}",
                serde_json::to_string_pretty(&decoded).expect("Unable to serialize decoded entry")
            );
        }
        Opts::GenerateKeys {
            public_key_file,
            secret_key_file,
        } => {
            let mut csprng = OsRng {};
            let key_pair = Keypair::generate(&mut csprng);

            let mut sk_file = File::create(&secret_key_file).context(SecretKeyFile {
                filename: secret_key_file,
            })?;
            let mut pk_file = File::create(&public_key_file).context(PubKeyFile {
                filename: public_key_file,
            })?;

            sk_file.write_all(&key_pair.secret.to_bytes()).unwrap();
            pk_file.write_all(&key_pair.public.to_bytes()).unwrap();
        }
        Opts::Lipmaa { sequence } => {
            let res = u64::from_str_radix(&sequence, 10).context(ParseSequenceNumber)?;
            println!("{}", lipmaa(res))
        }
        Opts::Hash { file } => {
            let bytes = read_file(&file).context(DecodeEntryFile { filename: file })?;
            let hash = blake2b(&bytes);
            let yamf_hash = YamfHash::Blake2b(hash.as_bytes());
            let mut yamf_hash_bytes = Vec::new();
            yamf_hash.encode_write(&mut yamf_hash_bytes).unwrap();

            std::io::stdout().write_all(&yamf_hash_bytes).unwrap();
        }
    };
    Ok(())
}

fn read_file<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, std::io::Error> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .expect("Unable to read to end of file");
    Ok(bytes)
}

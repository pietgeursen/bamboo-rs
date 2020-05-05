#[macro_use]
extern crate clap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::io::prelude::*;
use bamboo_core::{lipmaa, publish, verify, decode};
use clap::{App};
use snafu::{Snafu, ResultExt, OptionExt};


#[derive(Debug, Snafu)]
enum Error {
    #[snafu(display("Could not open entry file at {}: {}", filename.display(), source))]
    DecodeEntryFile {
        filename: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("Could not parse sequence number {}", source))]
    ParseSequenceNumber {
        source: std::num::ParseIntError,
    },
    #[snafu(display("Could not decode entry: {:?}", error))]
    DecodeEntry {
        error: bamboo_core::error::Error,
    },
}

type Result<T, E = Error> = std::result::Result<T, E>;

fn main() -> Result<()> {
    let yaml = load_yaml!("cli.yml");
    let matches = App::from_yaml(yaml).get_matches();

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
                let mut file = File::open(entry).context(DecodeEntryFile{filename: entry})?;
                let mut entry = Vec::new();
                file.read_to_end(&mut entry).expect("Unable to read to end of file");

                let decoded = decode(&entry)
                    .map_err(|err| Error::DecodeEntry{error: err})?;

                println!("{}", serde_json::to_string_pretty(&decoded).expect("Unable to serialize decoded entry")); 
            }
            None => (),
        },
        None => (),
    }


    Ok(())
}

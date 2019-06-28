use snafu::{ensure, Backtrace, ErrorCompat, ResultExt, Snafu};
use std::path::PathBuf;

mod entry;
mod yamf_hash;

// publish(content, getHashOfEntry) -> entry
// add(content, getHashOfEntry)
// getHashOfEntry(seq) -> hash
// getEntry(seq) -> entry

// verify(entry, getEntry)
// verifies:
// - signature
// - hashes and signatures of lipmaa link dependencies
// -

// One option is the oo way. A struct to represent a feed with methods.
//
// trait EntryStore {
//   fn getEntry(seq: u64) -> &[u8]
//   fn getLastEntry() -> &[u8]
//   fn appendEntry(entry: &[u8]) -> u64
// }
//
// struct Log<Store: EntryStore> {
//   store: Store
// }

// Entry type
// struct Entry {
//  is_end_of_feed: bool
//  payload_hash: yamfhash or bytes?
//  payload_size: u64,
//  seq_num: u64,
//  backlink: yamf or bytes
//  lipmaa_link: ditto,
//  sig: bytes
// }

#[derive(Debug, Snafu)]
enum Error {
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
}

type Result<T, E = Error> = std::result::Result<T, E>;

trait EntryStore {
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>>; // these are inconsistent. Should be an option?
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>>;
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>>;
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>>;
    fn append_entry(&mut self, entry: &[u8]) -> Result<()>;
}

struct MemoryEntryStore {
    store: Vec<Vec<u8>>,
}

impl EntryStore for MemoryEntryStore {
    fn get_entry(&self, seq_num: u64) -> Result<Vec<u8>> {
        Ok(self.store[seq_num as usize].clone())
    }
    fn get_entry_ref<'a>(&'a self, seq_num: u64) -> Result<Option<&'a [u8]>> {
        let result = self.store.get(seq_num as usize).map(|vec| vec.as_slice());
        Ok(result)
    }
    fn get_last_entry(&self) -> Result<Option<Vec<u8>>> {
        Ok(Some(self.store[0 as usize].clone()))
    }
    fn get_last_entry_ref<'a>(&'a self) -> Result<Option<&'a [u8]>> {
        let result = self.store.get(0 as usize).map(|vec| vec.as_slice());
        Ok(result)
    }
    fn append_entry(&mut self, entry: &[u8]) -> Result<()> {
        let mut vec = Vec::with_capacity(entry.len());
        vec.extend_from_slice(entry);
        self.store.push(vec);
        Ok(())
    }
}

struct Log<Store: EntryStore> {
    store: Store,
}

impl<Store: EntryStore> Log<Store> {
    pub fn new(store: Store) -> Log<Store> {
        Log { store }
    }
    pub fn publish(&mut self, content: &[u8]) -> Result<()> {
        let last_entry = self.store.get_last_entry_ref().unwrap();
        // get the last seq number
        // calc the hash of the last entry
        // get the lipmaa entry
        // calc the hash of the lipmaa entry

        self.store.append_entry(content)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

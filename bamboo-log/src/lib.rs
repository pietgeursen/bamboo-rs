pub mod entry_store;
pub mod log;

pub use entry_store::EntryStore;
pub use log::Log;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

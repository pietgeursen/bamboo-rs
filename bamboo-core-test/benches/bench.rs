#[macro_use]
extern crate criterion;
extern crate varu64;

use bamboo_rs::entry::decode;
use bamboo_rs::entry::Entry;
use bamboo_rs::entry_store::MemoryEntryStore;
use bamboo_rs::signature::Signature;
use bamboo_rs::yamf_hash::{YamfHash, BLAKE2B_HASH_SIZE};
use bamboo_rs::yamf_signatory::YamfSignatory;
use bamboo_rs::{EntryStore, Log};

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

use varu64::encode_write as varu64_encode_write;

use criterion::Criterion;

#[cfg(feature = "std")]
fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("publish", |b| {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );
        let payload = [1, 2, 3];

        b.iter(|| {
            log.publish(&payload, false).unwrap();
            log.store.clear();
        })
    });
    c.bench_function("verify", |b| {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let mut log = Log::new(
            MemoryEntryStore::new(),
            keypair.public.clone(),
            Some(keypair),
        );
        let payload = [1, 2, 3];
        log.publish(&payload, false).unwrap();

        let entry_bytes = log.store.get_entry_ref(1).unwrap().unwrap();

        let mut entry = decode(entry_bytes).unwrap();
        b.iter(|| entry.verify_signature())
    });
    c.bench_function("encode entry into writer", |b| {
        let backlink_bytes = [0xAA; BLAKE2B_HASH_SIZE];
        let backlink = YamfHash::<&[u8]>::Blake2b(backlink_bytes[..].into());
        let payload_hash_bytes = [0xAB; BLAKE2B_HASH_SIZE];
        let payload_hash = YamfHash::<&[u8]>::Blake2b(payload_hash_bytes[..].into());
        let lipmaa_link_bytes = [0xAC; BLAKE2B_HASH_SIZE];
        let lipmaa_link = YamfHash::<&[u8]>::Blake2b(lipmaa_link_bytes[..].into());
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(sig_bytes[..].into());
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes[..], None);

        let entry = Entry {
            is_end_of_feed: false,
            payload_hash,
            payload_size,
            author,
            seq_num,
            lipmaa_link: Some(lipmaa_link),
            backlink: Some(backlink),
            sig: Some(sig),
        };
        let mut vec = Vec::new();
        b.iter(|| {
            entry.encode_write(&mut vec).unwrap();
            vec.clear();
        })
    });
    c.bench_function("decode entry", |b| {
        let backlink_bytes = [0xAA; BLAKE2B_HASH_SIZE];
        let backlink = YamfHash::<&[u8]>::Blake2b(backlink_bytes[..].into());
        let payload_hash_bytes = [0xAB; BLAKE2B_HASH_SIZE];
        let payload_hash = YamfHash::<&[u8]>::Blake2b(payload_hash_bytes[..].into());
        let lipmaa_link_bytes = [0xAC; BLAKE2B_HASH_SIZE];
        let lipmaa_link = YamfHash::<&[u8]>::Blake2b(lipmaa_link_bytes[..].into());
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(sig_bytes[..].into());
        let author_bytes = [0xEE; 32];
        let author = YamfSignatory::Ed25519(&author_bytes[..], None);
        let mut entry_vec = Vec::new();

        entry_vec.push(1u8); // end of feed is true

        payload_hash.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(payload_size, &mut entry_vec).unwrap();
        author.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(seq_num, &mut entry_vec).unwrap();
        backlink.encode_write(&mut entry_vec).unwrap();
        lipmaa_link.encode_write(&mut entry_vec).unwrap();
        sig.encode_write(&mut entry_vec).unwrap();

        b.iter(|| {
            let entry = decode(&entry_vec).unwrap();
            assert_eq!(entry.seq_num, seq_num);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

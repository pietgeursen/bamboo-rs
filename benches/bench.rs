#[macro_use]
extern crate criterion;
extern crate varu64;

use bamboo_rs::entry::Entry;
use bamboo_rs::signature::Signature;
use bamboo_rs::yamf_hash::YamfHash;
use varu64::{
    decode as varu64_decode, encode as varu64_encode, encode_write as varu64_encode_write,
};

use criterion::black_box;
use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("encode entry into writer", |b| {
        let backlink_bytes = [0xAA; 64];
        let backlink = YamfHash::Blake2b(&backlink_bytes);
        let payload_hash_bytes = [0xAB; 64];
        let payload_hash = YamfHash::Blake2b(&payload_hash_bytes);
        let lipmaa_link_bytes = [0xAC; 64];
        let lipmaa_link = YamfHash::Blake2b(&lipmaa_link_bytes);
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes);

        let entry = Entry {
            is_end_of_feed: false,
            payload_hash,
            payload_size,
            seq_num,
            lipmaa_link: Some(lipmaa_link),
            backlink: Some(backlink),
            sig,
        };
        let mut vec = Vec::new();
        b.iter(|| {
            entry.encode_write(&mut vec).unwrap();
            vec.clear();
        })
    });
    c.bench_function("decode entry", |b| {
        let backlink_bytes = [0xAA; 64];
        let backlink = YamfHash::Blake2b(&backlink_bytes);
        let payload_hash_bytes = [0xAB; 64];
        let payload_hash = YamfHash::Blake2b(&payload_hash_bytes);
        let lipmaa_link_bytes = [0xAC; 64];
        let lipmaa_link = YamfHash::Blake2b(&lipmaa_link_bytes);
        let payload_size = 512;
        let seq_num = 2;
        let sig_bytes = [0xDD; 128];
        let sig = Signature(&sig_bytes);

        let mut entry_vec = Vec::new();

        entry_vec.push(1u8); // end of feed is true

        payload_hash.encode_write(&mut entry_vec).unwrap();
        varu64_encode_write(payload_size, &mut entry_vec).unwrap();
        varu64_encode_write(seq_num, &mut entry_vec).unwrap();
        backlink.encode_write(&mut entry_vec).unwrap();
        lipmaa_link.encode_write(&mut entry_vec).unwrap();
        sig.encode_write(&mut entry_vec).unwrap();

        b.iter(|| {
            let entry = Entry::decode(&entry_vec).unwrap();
            assert_eq!(entry.seq_num, seq_num);
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

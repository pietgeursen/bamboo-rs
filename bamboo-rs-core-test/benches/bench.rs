#[macro_use]
extern crate criterion;
extern crate varu64;

use bamboo_rs_core::entry::decode;
use bamboo_rs_core::entry::publish;
use bamboo_rs_core::entry::verify::batch::verify_batch_signatures;
use bamboo_rs_core::entry::verify::Error as VerifyError;
use bamboo_rs_core::entry::verify_batch;
use bamboo_rs_core::verify;
use bamboo_rs_log::entry_store::MemoryEntryStore;
use bamboo_rs_log::*;

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

use criterion::Criterion;

fn encoding_benches(c: &mut Criterion) {
    c.bench_function("encode entry", |b| {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            0,
            payload.as_bytes(),
            false,
            None,
            None,
            None,
        )
        .unwrap();
        let entry = decode(&out[..size]).unwrap();

        b.iter(|| {
            let mut encoded = [0u8; 512];
            entry.encode(&mut encoded).unwrap();
        })
    });

    c.bench_function("decode entry", |b| {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            0,
            payload.as_bytes(),
            false,
            None,
            None,
            None,
        )
        .unwrap();

        b.iter(|| {
            let _ = decode(&out[..size]).unwrap();
        })
    });
}

fn publish_benches(c: &mut Criterion) {
    c.bench_function("publish", |b| {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            0,
            payload.as_bytes(),
            false,
            None,
            None,
            None,
        )
        .unwrap();

        b.iter(|| {
            let mut out2 = [0u8; 512];
            let _ = publish(
                &mut out2,
                Some(&key_pair),
                0,
                payload.as_bytes(),
                false,
                Some(1),
                Some(&out[..size]),
                Some(&out[..size]),
            )
            .unwrap();
        })
    });
}

fn verify_signature_benches(c: &mut Criterion) {
    c.bench_function("verify_signature", |b| {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            0,
            payload.as_bytes(),
            false,
            None,
            None,
            None,
        )
        .unwrap();
        let entry = decode(&out[..size]).unwrap();

        b.iter(|| entry.verify_signature().unwrap())
    });

    c.bench_function("verify_signature_batch_100_entries", |b| {
        let mut csprng: OsRng = OsRng {};
        let key_pair: Keypair = Keypair::generate(&mut csprng);

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = publish(
            &mut out,
            Some(&key_pair),
            0,
            payload.as_bytes(),
            false,
            None,
            None,
            None,
        )
        .unwrap();

        let entries = (0..100).map(|_| &out[..size]).collect::<Vec<_>>();

        b.iter(|| verify_batch_signatures(&entries).unwrap())
    });
}

fn verify_entries_benches(c: &mut Criterion) {
    c.bench_function("verify_1000_entries", |b| {
        let entry_seqs = (1..1000)
            .collect::<Vec<_>>();

        let log = n_valid_entries(1000);
        let public_key = log.key_pair.as_ref().unwrap().public.clone();
        let entries = log.store.get_entries_ref(public_key, 0, &entry_seqs).unwrap();
        b.iter(|| {
            entries
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    let seq_num = index + 1;
                    let lipmaa_num = bamboo_rs_core::lipmaa(seq_num as u64) - 1;

                    let lipmaa_link = entries
                        .get(lipmaa_num as usize)
                        .map(|link| link.unwrap());
                    let backlink = entries
                        .get(seq_num - 1 - 1)
                        .map(|link| link.unwrap());

                    verify(&entry.unwrap(), None, lipmaa_link, backlink)?;
                    Ok(())
                })
                .collect::<Result<(), VerifyError>>()
                .unwrap();
        })
    });

    c.bench_function("batch_verify_100_entries", |b| {
        let entry_seqs = (1..1000)
            .collect::<Vec<_>>();

        let log = n_valid_entries(1000);
        let public_key = log.key_pair.as_ref().unwrap().public.clone();
        let entries = log.store.get_entries_ref(public_key, 0, &entry_seqs).unwrap()
            .iter()
            .map(|entry| (entry.unwrap(), Option::<&[u8]>::None))
            .collect::<Vec<_>>();

        b.iter(|| verify_batch(&entries[..]).unwrap())
    });
}


fn n_valid_entries(n: u64) -> Log<MemoryEntryStore> {
    let mut csprng: OsRng = OsRng {};
    let key_pair: Keypair = Keypair::generate(&mut csprng);

    let mut log = Log::new(MemoryEntryStore::new(), Some(key_pair));

    (1..n + 1).into_iter().for_each(|i| {
        let payload = format!("message number {}", i);
        log.publish(&payload.as_bytes(), 0, false).unwrap();
    });

    log
}
criterion_group!(
    benches,
    verify_entries_benches,
    verify_signature_benches,
    encoding_benches,
    publish_benches
);
criterion_main!(benches);

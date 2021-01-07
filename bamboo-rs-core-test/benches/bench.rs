#[macro_use]
extern crate criterion;
extern crate varu64;

use bamboo_core::Error;
use bamboo_core::verify;
use bamboo_core::entry::verify_batch;
use bamboo_core::entry::verify_batch::verify_batch_signatures;
use bamboo_core::entry::decode;
use bamboo_core::entry::publish;
use bamboo_log::entry_store::MemoryEntryStore;
use bamboo_log::*;

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

        b.iter(|| assert!(entry.verify_signature().unwrap()))
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

    c.bench_function("verify_100_entries", |b| {
        let entries = create_n_entries(1000);
        b.iter(|| {
            entries.iter()
                .enumerate()
                .map(|(index, (entry, payload))|{
                    let seq_num = index + 1;
                    let lipmaa_num = bamboo_core::lipmaa(seq_num as u64) - 1;

                    let lipmaa_link = entries.get(lipmaa_num as usize)
                        .map(|(link, _)| link.as_slice());
                    let backlink = entries.get(seq_num - 1 - 1)
                        .map(|(link, _)| link.as_slice());

                    let payload = payload.as_ref().map(|payload| payload.as_bytes());

                    verify(entry, payload, lipmaa_link, backlink)?;
                    Ok(())
                })
            .collect::<Result<(), Error>>().unwrap();
        })
    });

    c.bench_function("batch_verify_100_entries", |b| {
        let entries = create_n_entries(1000);
        b.iter(|| verify_batch(&entries[..]).unwrap())
    });
}

fn create_n_entries(n: u64) -> Vec<(Vec<u8>, Option<String>)> {
        let mut csprng: OsRng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);

        let public = keypair.public.clone();
        let mut log = Log::new(MemoryEntryStore::new(), public.clone(), Some(keypair), 0);

        (1..n)
            .into_iter()
            .map(|i| {
                let payload = format!("message number {}", i);
                log.publish(&payload.as_bytes(), false).unwrap();
                (log.store.get_entry(i).unwrap().unwrap(), payload)
            })
            .map(|(entry, payload)| (entry, Some(payload)))
            .collect::<Vec<_>>()
}

criterion_group!(
    benches,
    verify_entries_benches,
    verify_signature_benches,
    encoding_benches,
    publish_benches
);
criterion_main!(benches);

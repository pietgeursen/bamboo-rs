#[macro_use]
extern crate criterion;
extern crate varu64;

use bamboo_core::entry::decode;
use bamboo_core::entry::Entry;

use ed25519_dalek::Keypair;
use rand::rngs::OsRng;

use criterion::Criterion;

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("publish", |b| {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);
        let public_key = key_pair.public.clone();

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = Entry::<&[u8], &[u8], &[u8]>::publish(
            &mut out,
            Some(&key_pair),
            &public_key,
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        b.iter(|| {
            let mut out2 = [0u8; 512];
            let _ = Entry::<&[u8], &[u8], &[u8]>::publish(
                &mut out2,
                Some(&key_pair),
                &public_key,
                payload.as_bytes(),
                false,
                1,
                Some(&out[..size]),
                Some(&out[..size]),
            )
            .unwrap();
        })
    });
    c.bench_function("verify", |b| {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);
        let public_key = key_pair.public.clone();

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = Entry::<&[u8], &[u8], &[u8]>::publish(
            &mut out,
            Some(&key_pair),
            &public_key,
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();
        let mut entry = decode(&out[..size]).unwrap();

        b.iter(|| entry.verify_signature())
    });
    c.bench_function("encode entry", |b| {
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);
        let public_key = key_pair.public.clone();

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = Entry::<&[u8], &[u8], &[u8]>::publish(
            &mut out,
            Some(&key_pair),
            &public_key,
            payload.as_bytes(),
            false,
            0,
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
        let mut csprng: OsRng = OsRng::new().unwrap();
        let key_pair: Keypair = Keypair::generate(&mut csprng);
        let public_key = key_pair.public.clone();

        let payload = "hello bamboo!";
        let mut out = [0u8; 512];

        let size = Entry::<&[u8], &[u8], &[u8]>::publish(
            &mut out,
            Some(&key_pair),
            &public_key,
            payload.as_bytes(),
            false,
            0,
            None,
            None,
        )
        .unwrap();

        b.iter(|| {
            let _ = decode(&out[..size]).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

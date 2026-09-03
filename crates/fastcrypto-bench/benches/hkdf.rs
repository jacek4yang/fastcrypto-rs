//! HKDF-SHA256: the TLS 1.3 key schedule primitive.
//!
//! TLS 1.3 derives, per handshake direction, a 32-byte key and a 12-byte IV, so
//! the interesting output length is 88 bytes (client key, client IV, server key,
//! server IV). Both the extract step and the full extract+expand path are
//! measured because a real handshake repeats them many times.

mod common;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main};
use sha2::Sha256;

const TLS_TRAFFIC_SECRET_LEN: usize = 2 * 32 + 2 * 12; // two keys and two IVs

/// Output length adapter for ring and aws-lc-rs, whose HKDF-Expand APIs
/// size the output through a trait instead of a slice length.
struct OkmLen(usize);

impl ring::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

impl aws_lc_rs::hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn extract(c: &mut criterion::Criterion) {
    let salt = common::key(32);
    let ikm = common::key(32);
    let mut group = c.benchmark_group("hkdf-sha256/extract");

    group.bench_function("fastcrypto", |b| {
        b.iter(|| {
            black_box(fastcrypto::HkdfSha256::new(
                black_box(&salt),
                black_box(&ikm),
            ))
        });
    });

    group.bench_function("rustcrypto-hkdf", |b| {
        b.iter(|| black_box(hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm)));
    });

    group.bench_function("ring", |b| {
        b.iter(|| {
            let salt_key = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt);
            black_box(salt_key.extract(&ikm))
        });
    });

    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| {
            let salt_key = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, &salt);
            black_box(salt_key.extract(&ikm))
        });
    });

    group.finish();
}

fn expand(c: &mut criterion::Criterion) {
    let salt = common::key(32);
    let ikm = common::key(32);
    let info = common::message(16);
    let len = TLS_TRAFFIC_SECRET_LEN;

    let our_prk = fastcrypto::HkdfSha256::new(&salt, &ikm);
    let rc_prk = hkdf::Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let ring_prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt).extract(&ikm);
    let lc_prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, &salt).extract(&ikm);

    let mut group = c.benchmark_group("hkdf-sha256/expand-88B");

    group.bench_function("fastcrypto", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            our_prk.expand_into(black_box(&info), &mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("rustcrypto-hkdf", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            rc_prk.expand(&info, &mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("ring", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let info_refs: [&[u8]; 1] = [&info];
            let okm = ring_prk.expand(&info_refs, OkmLen(len)).unwrap();
            okm.fill(&mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("aws-lc-rs", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let info_refs: [&[u8]; 1] = [&info];
            lc_prk
                .expand(&info_refs, OkmLen(len))
                .unwrap()
                .fill(&mut out)
                .unwrap();
            black_box(out)
        });
    });

    group.finish();
}

/// Full extract+expand, i.e. one TLS 1.3 traffic-secret derivation.
fn full(c: &mut criterion::Criterion) {
    let salt = common::key(32);
    let ikm = common::key(32);
    let info = common::message(16);
    let mut group = c.benchmark_group("hkdf-sha256/extract+expand-88B");

    group.bench_function("fastcrypto", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let prk = fastcrypto::HkdfSha256::new(black_box(&salt), black_box(&ikm));
            prk.expand_into(&info, &mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("rustcrypto-hkdf", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let (_, hk) = hkdf::Hkdf::<Sha256>::extract(Some(&salt), &ikm);
            hk.expand(&info, &mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("ring", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let prk = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA256, &salt).extract(&ikm);
            let info_refs: [&[u8]; 1] = [&info];
            let okm = prk
                .expand(&info_refs, OkmLen(TLS_TRAFFIC_SECRET_LEN))
                .unwrap();
            okm.fill(&mut out).unwrap();
            black_box(out)
        });
    });

    group.bench_function("aws-lc-rs", |b| {
        let mut out = [0u8; TLS_TRAFFIC_SECRET_LEN];
        b.iter(|| {
            let prk = aws_lc_rs::hkdf::Salt::new(aws_lc_rs::hkdf::HKDF_SHA256, &salt).extract(&ikm);
            let info_refs: [&[u8]; 1] = [&info];
            prk.expand(&info_refs, OkmLen(TLS_TRAFFIC_SECRET_LEN))
                .unwrap()
                .fill(&mut out)
                .unwrap();
            black_box(out)
        });
    });

    group.finish();
}

/// HKDF-Expand-Label style derivation of several secrets from one PRK, as done
/// for the multiple labels of a TLS 1.3 handshake.
fn multi_label(c: &mut criterion::Criterion) {
    let prk_ours = fastcrypto::HkdfSha256::new(&common::key(32), &common::key(32));
    let labels: Vec<Vec<u8>> = (0..4u8)
        .map(|i| common::message(8 + usize::from(i)))
        .collect();
    let mut group = c.benchmark_group("hkdf-sha256/four-labels-32B");

    group.bench_function("fastcrypto", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            for label in &labels {
                prk_ours.expand_into(black_box(label), &mut out).unwrap();
            }
            black_box(out)
        });
    });

    group.bench_function("rustcrypto-hkdf", |b| {
        let (_, hk) = hkdf::Hkdf::<Sha256>::extract(Some(&common::key(32)), &common::key(32));
        let mut out = [0u8; 32];
        b.iter(|| {
            for label in &labels {
                hk.expand(label, &mut out).unwrap();
            }
            black_box(out)
        });
    });

    group.finish();
}

/// Four labels from one PRK using a prepared HMAC key state.
///
/// This is the TLS 1.3 shape: one pseudorandom key, several labels. The
/// comparison against the `multi_label` group, which re-prepares the key
/// per label, is the measured value of the prepared-state API.
fn multi_label_prepared_key(c: &mut criterion::Criterion) {
    let salt = common::key(32);
    let ikm = common::key(32);
    let labels: Vec<Vec<u8>> = (0..4u8)
        .map(|i| common::message(8 + usize::from(i)))
        .collect();

    let prk = fastcrypto::HkdfSha256::new(&salt, &ikm);
    let mut expander = prk.expander();
    let mut group = c.benchmark_group("hkdf-sha256_four-labels-prepared-key");
    group.bench_function("fastcrypto", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            for label in &labels {
                expander.expand_into(black_box(label), &mut out).unwrap();
                expander.reset();
            }
            black_box(out)
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = extract, expand, full, multi_label, multi_label_prepared_key
}
criterion_main!(benches);

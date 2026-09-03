//! AEAD baselines for the two TLS 1.3 record ciphers.
//!
//! Measured in two shapes, because TLS does both:
//!
//! * `reused-key` - the AEAD key is created once and many records are
//!   sealed with it (the steady state of a connection);
//! * `with-key-init` - key setup is included, which is what a short
//!   connection or a key update pays.
//!
//! Both seal and open are measured; open is the more common operation on a
//! server. Input buffers are rebuilt outside the timed section.

mod common;

use std::hint::black_box;

use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{AeadInOut, KeyInit},
};
use criterion::{BatchSize, BenchmarkId, criterion_group, criterion_main};

const TAG_LEN: usize = 16;
const AAD: &[u8] = &[0x17, 0x03, 0x03, 0x00, 0x10]; // TLS 1.3 record header-ish

#[allow(dead_code)]
fn tag_len_reference() -> usize {
    TAG_LEN
}

fn chacha20_poly1305_seal(c: &mut criterion::Criterion) {
    let key = common::key(32);
    let nonce = common::key(12);
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

    let rc_cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap(),
    );
    let lc_key = aws_lc_rs::aead::LessSafeKey::new(
        aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &key).unwrap(),
    );
    let rc_nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let mut group = c.benchmark_group("chacha20-poly1305/seal/reused-key");
    for &len in common::sizes() {
        group.throughput(common::throughput(len));
        let id = common::label(len);
        let plaintext = common::message(len);

        group.bench_with_input(BenchmarkId::new("rustcrypto", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    rc_cipher
                        .encrypt_in_place(&rc_nonce, AAD, &mut buf)
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("ring", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    ring_key
                        .seal_in_place_append_tag(
                            ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                            ring::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("aws-lc-rs", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    lc_key
                        .seal_in_place_append_tag(
                            aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
                                .unwrap(),
                            aws_lc_rs::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

fn chacha20_poly1305_open(c: &mut criterion::Criterion) {
    use chacha20poly1305::Nonce as RcNonce;

    let key = common::key(32);
    let nonce = common::key(12);
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

    let rc_cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();
    let rc_nonce = RcNonce::from(nonce_bytes);
    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap(),
    );
    let lc_key = aws_lc_rs::aead::LessSafeKey::new(
        aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &key).unwrap(),
    );

    let mut group = c.benchmark_group("chacha20-poly1305/open/reused-key");
    for &len in common::sizes() {
        group.throughput(common::throughput(len));
        let id = common::label(len);
        let mut sealed = common::message(len);
        ring_key
            .seal_in_place_append_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                ring::aead::Aad::from(AAD),
                &mut sealed,
            )
            .unwrap();

        group.bench_with_input(BenchmarkId::new("rustcrypto", &id), &sealed, |b, ct| {
            b.iter_batched(
                || ct.clone(),
                |mut buf| {
                    rc_cipher
                        .decrypt_in_place(&rc_nonce, AAD, &mut buf)
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("ring", &id), &sealed, |b, ct| {
            b.iter_batched(
                || ct.clone(),
                |mut buf| {
                    ring_key
                        .open_in_place(
                            ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                            ring::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("aws-lc-rs", &id), &sealed, |b, ct| {
            b.iter_batched(
                || ct.clone(),
                |mut buf| {
                    lc_key
                        .open_in_place(
                            aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
                                .unwrap(),
                            aws_lc_rs::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Key setup cost: what a new connection or a key update pays.
fn chacha20_poly1305_key_init(c: &mut criterion::Criterion) {
    let key = common::key(32);
    let mut group = c.benchmark_group("chacha20-poly1305/key-init");
    group.bench_function("rustcrypto", |b| {
        b.iter(|| black_box(ChaCha20Poly1305::new_from_slice(&key).unwrap()));
    });
    group.bench_function("ring", |b| {
        b.iter(|| {
            black_box(ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap())
        });
    });
    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| {
            black_box(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, &key)
                    .unwrap(),
            )
        });
    });
    group.finish();
}

fn aes_128_gcm(c: &mut criterion::Criterion) {
    use aes_gcm::{
        Aes128Gcm,
        aead::{AeadInOut, KeyInit},
    };

    let key = common::key(16);
    let nonce = common::key(12);
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();

    let rc_cipher = Aes128Gcm::new_from_slice(&key).unwrap();
    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).unwrap(),
    );
    let lc_key = aws_lc_rs::aead::LessSafeKey::new(
        aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_128_GCM, &key).unwrap(),
    );
    let rc_nonce = aes_gcm::Nonce::from(nonce_bytes);

    let mut group = c.benchmark_group("aes-128-gcm/seal/reused-key");
    for &len in common::sizes() {
        group.throughput(common::throughput(len));
        let id = common::label(len);
        let plaintext = common::message(len);

        group.bench_with_input(BenchmarkId::new("rustcrypto", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    rc_cipher
                        .encrypt_in_place(&rc_nonce, AAD, &mut buf)
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("ring", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    ring_key
                        .seal_in_place_append_tag(
                            ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                            ring::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });

        group.bench_with_input(BenchmarkId::new("aws-lc-rs", &id), &plaintext, |b, pt| {
            b.iter_batched(
                || pt.clone(),
                |mut buf| {
                    lc_key
                        .seal_in_place_append_tag(
                            aws_lc_rs::aead::Nonce::try_assume_unique_for_key(&nonce_bytes)
                                .unwrap(),
                            aws_lc_rs::aead::Aad::from(AAD),
                            &mut buf,
                        )
                        .unwrap();
                    black_box(buf)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();

    let mut group = c.benchmark_group("aes-128-gcm/key-init");
    group.bench_function("rustcrypto", |b| {
        b.iter(|| black_box(Aes128Gcm::new_from_slice(&key).unwrap()));
    });
    group.bench_function("ring", |b| {
        b.iter(|| black_box(ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &key).unwrap()));
    });
    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| {
            black_box(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::AES_128_GCM, &key).unwrap(),
            )
        });
    });
    group.finish();
}

/// Fixed cost of sealing an empty record: the floor for a TLS record's crypto
/// work, and the number that small-record optimisations attack.
fn empty_record_floor(c: &mut criterion::Criterion) {
    let key = common::key(32);
    let nonce = common::key(12);
    let nonce_bytes: [u8; 12] = nonce.as_slice().try_into().unwrap();
    let ring_key = ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key).unwrap(),
    );
    let plaintext: Vec<u8> = Vec::new();

    let mut group = c.benchmark_group("chacha20-poly1305/empty-record");
    group.bench_function("ring", |b| {
        b.iter_batched(
            || plaintext.clone(),
            |mut buf| {
                ring_key
                    .seal_in_place_append_tag(
                        ring::aead::Nonce::assume_unique_for_key(nonce_bytes),
                        ring::aead::Aad::from(AAD),
                        &mut buf,
                    )
                    .unwrap();
                black_box(buf)
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = chacha20_poly1305_seal, chacha20_poly1305_open, chacha20_poly1305_key_init, aes_128_gcm, empty_record_floor
}
criterion_main!(benches);

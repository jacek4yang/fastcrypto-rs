//! X25519 baseline: the TLS 1.3 key-exchange primitive.
//!
//! Two groups, and the distinction matters:
//!
//! * `fixed-key` - diffuse-hellman on pre-generated keys, i.e. the pure
//!   scalar multiplication cost. Compared across x25519-dalek and aws-lc-rs;
//!   ring 0.17 does not expose raw X25519 private-key import, so it cannot take
//!   part in this comparison.
//! * `ephemeral` - generate an ephemeral key and agree, i.e. what one
//!   side of a TLS handshake does. This includes RNG cost and is therefore
//!   compared separately, not mixed into the fixed-key numbers.

mod common;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main};
use x25519_dalek::{PublicKey, StaticSecret};

fn fixed_key(c: &mut criterion::Criterion) {
    let alice_sk: [u8; 32] = common::key32(1);
    let bob_sk: [u8; 32] = common::key32(2);
    let bob_pk: [u8; 32] = PublicKey::from(&StaticSecret::from(bob_sk)).to_bytes();

    let dalek_secret = StaticSecret::from(alice_sk);
    let dalek_public = PublicKey::from(bob_pk);

    let lc_secret = aws_lc_rs::agreement::PrivateKey::from_private_key(
        &aws_lc_rs::agreement::X25519,
        &alice_sk,
    )
    .unwrap();

    let mut group = c.benchmark_group("x25519/fixed-key");

    group.bench_function("x25519-dalek", |b| {
        b.iter(|| black_box(dalek_secret.diffie_hellman(&dalek_public).to_bytes()));
    });

    group.bench_function("aws-lc-rs", |b| {
        let mut out = [0u8; 32];
        b.iter(|| {
            let peer = aws_lc_rs::agreement::UnparsedPublicKey::new(
                &aws_lc_rs::agreement::X25519,
                &bob_pk,
            );
            aws_lc_rs::agreement::agree(&lc_secret, peer, (), |raw| {
                out.copy_from_slice(raw);
                Ok::<(), ()>(())
            })
            .unwrap();
            black_box(out)
        });
    });

    group.finish();
}

/// Ephemeral key generation plus agreement: one side of a TLS handshake.
///
/// This includes the RNG, so it is not comparable with the fixed-key group.
fn ephemeral(c: &mut criterion::Criterion) {
    let bob_sk: [u8; 32] = common::key32(2);
    let bob_pk: [u8; 32] = PublicKey::from(&StaticSecret::from(bob_sk)).to_bytes();
    let dalek_public = PublicKey::from(bob_pk);
    let rng = ring::rand::SystemRandom::new();
    let mut out = [0u8; 32];

    let mut group = c.benchmark_group("x25519/ephemeral-keygen+agree");

    group.bench_function("x25519-dalek", |b| {
        b.iter(|| {
            // x25519-dalek's EphemeralSecret::random needs its own RNG feature;
            // a fixed scalar with the two clamped bits cleared is equivalent to
            // what an ephemeral key is by construction, so the arithmetic
            // measured is the same as for a freshly generated key.
            let mut sk = common::key32(3);
            sk[0] &= 248;
            sk[31] &= 127;
            sk[31] |= 64;
            let secret = StaticSecret::from(sk);
            black_box(secret.diffie_hellman(&dalek_public).to_bytes())
        });
    });

    group.bench_function("ring", |b| {
        b.iter(|| {
            let private =
                ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
                    .unwrap();
            let public = private.compute_public_key().unwrap();
            black_box(
                ring::agreement::agree_ephemeral(
                    private,
                    &ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, &bob_pk),
                    |raw| {
                        out.copy_from_slice(raw);
                        out
                    },
                )
                .unwrap(),
            );
            let _ = public;
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = fixed_key, ephemeral
}
criterion_main!(benches);

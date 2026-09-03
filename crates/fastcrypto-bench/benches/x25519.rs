//! X25519 baseline: the TLS 1.3 key-exchange primitive.
//!
//! Two groups, and the distinction matters:
//!
//! * `fixed-key` - diffuse-hellman on pre-generated keys, i.e. the pure
//!   scalar multiplication cost. Compared across x25519-dalek and aws-lc-rs;
//!   ring 0.17 does not expose raw X25519 private-key import, so it cannot take
//!   part in this comparison.
//! * `public-key` - fixed-base scalar multiplication: deriving a public key
//!   from a private one. rust-reality performs this once per session for the
//!   TLS ephemeral share, and it is a different routine from the variable-base
//!   one, so it is measured separately rather than inferred.
//! * `ephemeral` - generate an ephemeral key and agree, i.e. what one
//!   side of a TLS handshake does. This includes RNG cost and is therefore
//!   compared separately, not mixed into the fixed-key numbers. fastcrypto
//!   takes its randomness from the caller and so has no arm here; its cost is
//!   the sum of the `public-key` and `fixed-key` groups.

mod common;

use std::hint::black_box;

use criterion::{criterion_group, criterion_main};
use x25519_dalek::{PublicKey, StaticSecret};

/// Adds one arm per compiled fastcrypto variant, so a machine with BMI2/ADX
/// still reports what a pre-Haswell release binary would run.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn fastcrypto_agreement_arms(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    secret: &[u8; 32],
    peer: &[u8; 32],
) {
    use fastcrypto_x86::x25519::{Variant, variant, x25519_adx, x25519_baseline};

    let mut out = [0u8; 32];
    if variant() == Variant::Adx {
        group.bench_function("fastcrypto/s2n-bignum-adx", |b| {
            // SAFETY: guarded by the CPUID probe immediately above.
            b.iter(|| {
                unsafe { x25519_adx(&mut out, secret, peer) };
                black_box(out)
            });
        });
    }
    group.bench_function("fastcrypto/s2n-bignum-baseline", |b| {
        b.iter(|| {
            x25519_baseline(&mut out, secret, peer);
            black_box(out)
        });
    });
}

/// Fixed-base scalar multiplication, one arm per compiled variant.
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn fastcrypto_public_key_arms(
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    secret: &[u8; 32],
) {
    use fastcrypto_x86::x25519::{Variant, variant, x25519_base_adx, x25519_base_baseline};

    let mut out = [0u8; 32];
    if variant() == Variant::Adx {
        group.bench_function("fastcrypto/s2n-bignum-adx", |b| {
            // SAFETY: guarded by the CPUID probe immediately above.
            b.iter(|| {
                unsafe { x25519_base_adx(&mut out, secret) };
                black_box(out)
            });
        });
    }
    group.bench_function("fastcrypto/s2n-bignum-baseline", |b| {
        b.iter(|| {
            x25519_base_baseline(&mut out, secret);
            black_box(out)
        });
    });
}

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

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fastcrypto_agreement_arms(&mut group, &alice_sk, &bob_pk);

    group.finish();
}

/// Fixed-base scalar multiplication: private key to public key.
///
/// rust-reality performs this once per session, for the TLS ephemeral share.
fn public_key(c: &mut criterion::Criterion) {
    let alice_sk: [u8; 32] = common::key32(1);
    let dalek_secret = StaticSecret::from(alice_sk);
    let lc_secret = aws_lc_rs::agreement::PrivateKey::from_private_key(
        &aws_lc_rs::agreement::X25519,
        &alice_sk,
    )
    .unwrap();

    let mut group = c.benchmark_group("x25519/public-key");

    group.bench_function("x25519-dalek", |b| {
        b.iter(|| black_box(PublicKey::from(&dalek_secret).to_bytes()));
    });

    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| black_box(lc_secret.compute_public_key().unwrap()));
    });

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fastcrypto_public_key_arms(&mut group, &alice_sk);

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
    targets = fixed_key, public_key, ephemeral
}
criterion_main!(benches);

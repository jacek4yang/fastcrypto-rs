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
//! * `ephemeral-session` - the whole TLS ephemeral shape: generate a key pair,
//!   read its public share, agree once. **This is the group that decides**,
//!   because `aws-lc-rs` computes the public key inside key generation and
//!   cannot be measured on the fixed-base multiplication alone. Both arms
//!   include their own system randomness.
//!   All four implementations appear, so the incumbent is not compared only
//!   against us.

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
/// `aws-lc-rs` has no arm that isolates this. `PrivateKey::compute_public_key`
/// only marshals a public key that `from_private_key` already computed and
/// stored in the `EVP_PKEY` — measured at 27 ns, which is a memcpy, not a
/// scalar multiplication. The incumbent's real cost for this operation is
/// inside key import and key generation, so it is compared in the
/// `ephemeral-session` group below, where both sides pay it once.
fn public_key(c: &mut criterion::Criterion) {
    let alice_sk: [u8; 32] = common::key32(1);
    let dalek_secret = StaticSecret::from(alice_sk);

    let mut group = c.benchmark_group("x25519/public-key");

    group.bench_function("x25519-dalek", |b| {
        b.iter(|| black_box(PublicKey::from(&dalek_secret).to_bytes()));
    });

    // Import computes and stores the public key, so this is the incumbent's
    // fixed-base multiplication plus its EVP_PKEY allocation. Labelled for what
    // it is rather than presented as a like-for-like arm.
    group.bench_function("aws-lc-rs/import-including-base-mul", |b| {
        b.iter(|| {
            black_box(
                aws_lc_rs::agreement::PrivateKey::from_private_key(
                    &aws_lc_rs::agreement::X25519,
                    &alice_sk,
                )
                .unwrap(),
            );
        });
    });

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    fastcrypto_public_key_arms(&mut group, &alice_sk);

    group.finish();
}

/// The whole TLS ephemeral shape: one key pair, its public share, one
/// agreement — what rust-reality performs once per session.
///
/// This is the group that decides, because it is the only one where both sides
/// pay for the same work: allocation, object construction and the caller's
/// random draw, not only the scalar multiplication the `fixed-key` group
/// isolates.
///
/// **The entropy source is part of the shape, so there are two fastcrypto
/// arms.** The incumbent draws from AWS-LC's internal DRBG no matter what is
/// passed to it. rust-reality's candidate calls `getrandom::fill`, which on a
/// kernel with the vDSO entry point never enters the kernel. Measuring
/// fastcrypto against AWS-LC's DRBG isolates the X25519 API — useful, and not
/// what ships; measuring it against `getrandom` is the combination the server
/// actually compiles. Reporting only the first would attribute a whole-product
/// difference to the wrong component.
fn ephemeral_session(c: &mut criterion::Criterion) {
    let peer_sk: [u8; 32] = common::key32(2);
    let peer_pk: [u8; 32] = PublicKey::from(&StaticSecret::from(peer_sk)).to_bytes();
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let mut out = [0u8; 32];

    let mut group = c.benchmark_group("x25519/ephemeral-session");

    group.bench_function("aws-lc-rs", |b| {
        b.iter(|| {
            let private = aws_lc_rs::agreement::EphemeralPrivateKey::generate(
                &aws_lc_rs::agreement::X25519,
                &rng,
            )
            .unwrap();
            let public = private.compute_public_key().unwrap();
            black_box(public.as_ref()[0]);
            aws_lc_rs::agreement::agree_ephemeral(
                private,
                aws_lc_rs::agreement::UnparsedPublicKey::new(
                    &aws_lc_rs::agreement::X25519,
                    &peer_pk,
                ),
                (),
                |raw| {
                    out.copy_from_slice(raw);
                    Ok::<(), ()>(())
                },
            )
            .unwrap();
            black_box(out)
        });
    });

    // Holds the entropy source fixed at the incumbent's, so the difference is
    // the X25519 API and nothing else.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    group.bench_function("fastcrypto/aws-lc-rng", |b| {
        b.iter(|| {
            let mut seed = [0u8; 32];
            aws_lc_rs::rand::fill(&mut seed).unwrap();
            let secret = fastcrypto::x25519::EphemeralSecret::from_bytes(seed);
            black_box(secret.public_key()[0]);
            let shared = secret.agree(&peer_pk).unwrap();
            black_box(*shared.as_bytes())
        });
    });

    // Exactly what `EphemeralX25519Key::generate` compiles to in rust-reality's
    // candidate: `getrandom::fill` into a 32-byte seed, then the agreement.
    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    group.bench_function("fastcrypto/getrandom", |b| {
        b.iter(|| {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).unwrap();
            let secret = fastcrypto::x25519::EphemeralSecret::from_bytes(seed);
            black_box(secret.public_key()[0]);
            let shared = secret.agree(&peer_pk).unwrap();
            black_box(*shared.as_bytes())
        });
    });

    // The entropy draw on its own, so the two arms above can be read apart.
    group.bench_function("entropy/aws-lc-rs-drbg-32B", |b| {
        b.iter(|| {
            let mut seed = [0u8; 32];
            aws_lc_rs::rand::fill(&mut seed).unwrap();
            black_box(seed[0])
        });
    });
    group.bench_function("entropy/getrandom-32B", |b| {
        b.iter(|| {
            let mut seed = [0u8; 32];
            getrandom::fill(&mut seed).unwrap();
            black_box(seed[0])
        });
    });

    group.bench_function("ring", |b| {
        let ring_rng = ring::rand::SystemRandom::new();
        b.iter(|| {
            let private =
                ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &ring_rng)
                    .unwrap();
            let public = private.compute_public_key().unwrap();
            black_box(public.as_ref()[0]);
            black_box(
                ring::agreement::agree_ephemeral(
                    private,
                    &ring::agreement::UnparsedPublicKey::new(&ring::agreement::X25519, &peer_pk),
                    |raw| {
                        out.copy_from_slice(raw);
                        out
                    },
                )
                .unwrap(),
            )
        });
    });

    // x25519-dalek's `EphemeralSecret::random` needs its own RNG feature; a
    // fixed scalar is equivalent arithmetic, so this arm measures the curve
    // work without a random draw and is *favourable* to dalek by that much.
    group.bench_function("x25519-dalek/without-rng", |b| {
        b.iter(|| {
            let secret = StaticSecret::from(common::key32(3));
            black_box(PublicKey::from(&secret).to_bytes()[0]);
            black_box(secret.diffie_hellman(&PublicKey::from(peer_pk)).to_bytes())
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = common::criterion();
    targets = fixed_key, public_key, ephemeral_session
}
criterion_main!(benches);

//! X25519 differential tests against two independent implementations.
//!
//! `aws-lc-rs` is rust-reality's incumbent and `x25519-dalek` is a wholly
//! independent Rust implementation. They are the oracles, not the subject: a
//! disagreement here is a defect in this repository until proven otherwise.
//!
//! Both compiled variants are exercised. On a machine without BMI2/ADX only
//! the baseline one exists, which is the case a pre-Haswell release binary
//! runs, and the test narrows accordingly rather than silently passing.

#![cfg(target_arch = "x86_64")]

use aws_lc_rs::agreement::{PrivateKey, UnparsedPublicKey, X25519, agree};
use fastcrypto::x25519::{EphemeralSecret, StaticSecret};
use fastcrypto_bench::Prng;
use fastcrypto_x86::x25519::{
    Variant, variant, x25519_adx, x25519_base_adx, x25519_base_baseline, x25519_baseline,
};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret as DalekSecret};

type Agree = fn(&mut [u8; 32], &[u8; 32], &[u8; 32]);
type Base = fn(&mut [u8; 32], &[u8; 32]);

fn agree_adx(out: &mut [u8; 32], scalar: &[u8; 32], point: &[u8; 32]) {
    // SAFETY: only reachable through `variants`, which includes this pair
    // solely when CPUID reported BMI2 and ADX.
    unsafe { x25519_adx(out, scalar, point) }
}

fn base_adx(out: &mut [u8; 32], scalar: &[u8; 32]) {
    // SAFETY: as for `agree_adx`.
    unsafe { x25519_base_adx(out, scalar) }
}

/// Every compiled variant this machine can execute, with its name.
fn variants() -> Vec<(&'static str, Agree, Base)> {
    let mut all: Vec<(&'static str, Agree, Base)> = Vec::new();
    all.push(("baseline", x25519_baseline, x25519_base_baseline));
    if variant() == Variant::Adx {
        all.push(("adx", agree_adx, base_adx));
    }
    all
}

fn key(seed: u64) -> [u8; 32] {
    let mut out = [0_u8; 32];
    Prng::new(seed).fill(&mut out);
    out
}

fn dalek_public(secret: &[u8; 32]) -> [u8; 32] {
    DalekPublic::from(&DalekSecret::from(*secret)).to_bytes()
}

fn dalek_agree(secret: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    DalekSecret::from(*secret)
        .diffie_hellman(&DalekPublic::from(*peer))
        .to_bytes()
}

fn aws_lc_public(secret: &[u8; 32]) -> [u8; 32] {
    PrivateKey::from_private_key(&X25519, secret)
        .expect("private key")
        .compute_public_key()
        .expect("public key")
        .as_ref()
        .try_into()
        .expect("32 bytes")
}

/// `aws-lc-rs` refuses a non-contributory share, so `None` means "rejected"
/// rather than "failed".
fn aws_lc_agree(secret: &[u8; 32], peer: &[u8; 32]) -> Option<[u8; 32]> {
    let key = PrivateKey::from_private_key(&X25519, secret).expect("private key");
    agree(
        &key,
        UnparsedPublicKey::new(&X25519, &peer[..]),
        (),
        |raw| <[u8; 32]>::try_from(raw).map_err(drop),
    )
    .ok()
}

/// The oracles must agree with each other, or a failure below is ambiguous.
#[test]
fn the_two_oracles_agree_with_each_other() {
    for seed in 1..64_u64 {
        let secret = key(seed);
        let peer_public = dalek_public(&key(seed + 1000));
        assert_eq!(dalek_public(&secret), aws_lc_public(&secret), "seed {seed}");
        assert_eq!(
            dalek_agree(&secret, &peer_public),
            aws_lc_agree(&secret, &peer_public).expect("contributory"),
            "seed {seed}"
        );
    }
}

#[test]
fn public_key_derivation_matches_both_oracles() {
    for (name, _, base) in variants() {
        for seed in 1..256_u64 {
            let secret = key(seed);
            let mut ours = [0_u8; 32];
            base(&mut ours, &secret);
            assert_eq!(ours, dalek_public(&secret), "{name}, seed {seed}");
            assert_eq!(ours, aws_lc_public(&secret), "{name}, seed {seed}");
        }
    }
}

#[test]
fn agreement_matches_both_oracles() {
    for (name, agree_fn, _) in variants() {
        for seed in 1..256_u64 {
            let secret = key(seed);
            let peer_public = dalek_public(&key(seed + 4096));
            let mut ours = [0_u8; 32];
            agree_fn(&mut ours, &secret, &peer_public);
            assert_eq!(ours, dalek_agree(&secret, &peer_public), "{name} {seed}");
            assert_eq!(
                ours,
                aws_lc_agree(&secret, &peer_public).expect("contributory"),
                "{name} {seed}"
            );
        }
    }
}

/// Random 32-byte strings are mostly *not* valid curve points, and the
/// implementations must still agree on what they compute for them. This is the
/// case a peer can drive directly, so it matters more than the well-formed one.
#[test]
fn arbitrary_peer_encodings_match_both_oracles() {
    for (name, agree_fn, _) in variants() {
        for seed in 1..512_u64 {
            let secret = key(seed);
            let peer = key(seed.wrapping_mul(7919) | 1);
            let mut ours = [0_u8; 32];
            agree_fn(&mut ours, &secret, &peer);
            assert_eq!(ours, dalek_agree(&secret, &peer), "{name}, seed {seed}");
            match aws_lc_agree(&secret, &peer) {
                Some(expected) => assert_eq!(ours, expected, "{name}, seed {seed}"),
                None => assert_eq!(
                    ours, [0_u8; 32],
                    "{name}, seed {seed}: rejected but non-zero"
                ),
            }
        }
    }
}

/// The high bit of a peer u-coordinate is ignored by RFC 7748, which is a
/// classic source of implementation disagreement.
#[test]
fn the_ignored_high_bit_matches_both_oracles() {
    for (name, agree_fn, _) in variants() {
        for seed in 1..64_u64 {
            let secret = key(seed);
            let mut peer = dalek_public(&key(seed + 77));
            let mut with_high_bit = peer;
            with_high_bit[31] |= 0x80;
            peer[31] &= 0x7f;

            let (mut clear, mut set) = ([0_u8; 32], [0_u8; 32]);
            agree_fn(&mut clear, &secret, &peer);
            agree_fn(&mut set, &secret, &with_high_bit);
            assert_eq!(clear, set, "{name}, seed {seed}: high bit was not ignored");
            assert_eq!(clear, dalek_agree(&secret, &with_high_bit), "{name} {seed}");
        }
    }
}

/// The safe API must make the same accept/reject decision the incumbent makes,
/// because rust-reality maps that decision straight onto an authentication
/// failure.
#[test]
fn the_accept_or_reject_decision_matches_the_incumbent() {
    const LOW_ORDER: &[[u8; 32]] = &[[0; 32], {
        let mut point = [0_u8; 32];
        point[0] = 1;
        point
    }];

    for seed in 1..256_u64 {
        let secret = key(seed);
        let peer = key(seed.wrapping_mul(31337) | 1);
        let ours = StaticSecret::from_bytes(secret).agree(&peer);
        assert_eq!(
            ours.is_some(),
            aws_lc_agree(&secret, &peer).is_some(),
            "seed {seed}"
        );
        if let (Some(ours), Some(expected)) = (ours, aws_lc_agree(&secret, &peer)) {
            assert_eq!(ours.as_bytes(), &expected, "seed {seed}");
        }
    }

    for peer in LOW_ORDER {
        assert!(StaticSecret::from_bytes(key(1)).agree(peer).is_none());
        assert!(aws_lc_agree(&key(1), peer).is_none());
    }
}

/// The ephemeral shape end to end: our public share must be usable by the
/// incumbent, and both sides must reach the same secret.
#[test]
fn the_ephemeral_shape_interoperates_with_the_incumbent() {
    for seed in 1..128_u64 {
        let ours = EphemeralSecret::from_bytes(key(seed));
        let our_public = *ours.public_key();
        let peer_secret = key(seed + 9001);
        let peer_public = aws_lc_public(&peer_secret);

        let from_us = ours.agree(&peer_public).expect("contributory");
        let from_them = aws_lc_agree(&peer_secret, &our_public).expect("contributory");
        assert_eq!(from_us.as_bytes(), &from_them, "seed {seed}");
    }
}

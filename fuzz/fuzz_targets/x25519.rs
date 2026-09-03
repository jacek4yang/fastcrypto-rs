//! Differential fuzzing: our X25519 against `x25519-dalek`.
//!
//! The interesting input is the *peer* share, because that is the byte string
//! an attacker chooses: most 32-byte strings are not well-formed points, RFC
//! 7748 says the top bit of the u-coordinate is ignored, and small-order points
//! must agree to zero. `x25519-dalek` is the oracle rather than `aws-lc-rs`
//! because it computes a value for every input instead of returning an error,
//! so a disagreement is always visible.
//!
//! Three properties per input:
//! * agreement matches the oracle, for arbitrary secret and arbitrary peer;
//! * public-key derivation matches the oracle;
//! * the safe API rejects exactly the non-contributory shares.

#![no_main]

use libfuzzer_sys::fuzz_target;
use x25519_dalek::{PublicKey, StaticSecret as DalekSecret};

fuzz_target!(|data: &[u8]| {
    if data.len() < 64 {
        return;
    }
    let mut secret = [0u8; 32];
    let mut peer = [0u8; 32];
    secret.copy_from_slice(&data[..32]);
    peer.copy_from_slice(&data[32..64]);

    let oracle_public = PublicKey::from(&DalekSecret::from(secret)).to_bytes();
    let oracle_shared = DalekSecret::from(secret)
        .diffie_hellman(&PublicKey::from(peer))
        .to_bytes();

    let ours = fastcrypto::x25519::StaticSecret::from_bytes(secret);
    assert_eq!(ours.public_key(), oracle_public);

    match ours.agree(&peer) {
        Some(shared) => assert_eq!(shared.as_bytes(), &oracle_shared),
        None => assert_eq!(oracle_shared, [0u8; 32], "rejected a contributory share"),
    }

    // The ephemeral type must reach the same secret as the static one from the
    // same bytes, and must expose the same public share.
    let ephemeral = fastcrypto::x25519::EphemeralSecret::from_bytes(secret);
    assert_eq!(ephemeral.public_key(), &oracle_public);
    match ephemeral.agree(&peer) {
        Some(shared) => assert_eq!(shared.as_bytes(), &oracle_shared),
        None => assert_eq!(oracle_shared, [0u8; 32]),
    }
});

//! Differential fuzzing: our SHA-256 against RustCrypto sha2.
//!
//! Two properties are checked for every input:
//! * the one-shot digest equals the reference digest;
//! * the incremental digest equals the one-shot digest for several chunkings,
//!   which is the property TLS transcript hashing depends on.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::Digest;

fuzz_target!(|data: &[u8]| {
    let ours = fastcrypto::sha256(data);
    let theirs = sha2::Sha256::digest(data);
    assert_eq!(ours.as_slice(), theirs.as_slice());

    // Chunking must not change the result. Chunk sizes are taken from the data
    // so that the fuzzer explores them instead of us enumerating them.
    let mut h = fastcrypto::Sha256::new();
    for part in data.chunks(1 + data.len() % 97) {
        h.update(part);
    }
    assert_eq!(h.finalize(), ours);

    // Finalize must be non-destructive: a second digest after more input must
    // match the one-shot digest of the longer message.
    let mut h = fastcrypto::Sha256::new();
    h.update(data);
    let first = h.finalize();
    h.update(&[0x00]);
    let second = h.finalize();
    let mut extended = data.to_vec();
    extended.push(0x00);
    assert_eq!(first, ours);
    assert_eq!(second, fastcrypto::sha256(&extended));
});


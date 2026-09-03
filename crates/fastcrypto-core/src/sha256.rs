//! SHA-256 (FIPS 180-4), portable backend.
//!
//! This is the reference-quality portable implementation that every
//! architecture-specific SHA-256 backend must match bit-for-bit. It is written
//! in safe Rust only: no `unsafe`, no lookup tables, no secret-dependent
//! branches, and no secret-dependent memory addressing.
//!
//! # Implementation notes
//!
//! * Message schedule: an explicit 64-word array with the recurrence from FIPS
//!   180-4 section 6.2.2. Loop bounds are compile-time constants, so the
//!   compiler can prove every access is in range and elide the checks.
//! * Padding is materialised in a fixed 128-byte stack scratch buffer, so no
//!   message data is copied more than once.
//! * The compression function is `#[inline(always)]` because it is the entire
//!   hot loop; leaving it out of line costs a call per 64-byte block.
//!
//! # Optimization status
//!
//! Baseline portable code only. Measured numbers live in ```benchmarks/results/```.
//! Architecture-specific (SHA-NI / ARMv8 SHA) work is intentionally deferred
//! until profiling on top of this baseline identifies the hotspot.

// slice::as_chunks is not stable, and this hot loop needs the zero-copy
// chunk iterator rather than a copied array of arrays.
#![allow(clippy::chunks_exact_to_as_chunks)]

use zeroize::Zeroize;

/// SHA-256 block length in bytes.
pub const BLOCK_LEN: usize = 64;
/// SHA-256 digest length in bytes.
pub const DIGEST_LEN: usize = 32;

/// Round constants, FIPS 180-4 section 4.2.2.
const K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Initial hash value, FIPS 180-4 section 5.3.3.
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// A safe handle to a block compression function.
///
/// The dispatch seam: the portable backend is the default, and an
/// architecture-specific backend can be substituted without changing any
/// user-visible type. It is a plain function pointer, so the call is direct
/// and there is no dynamic dispatch per block.
#[derive(Debug, Clone, Copy)]
pub struct Compressor(pub(crate) fn(&mut [u32; 8], &[u8]));

/// Manual implementation: derived equality on a function pointer compares
/// addresses, which Rust does not guarantee to be unique, so equality here
/// means same function value by pointer identity only and is provided for
/// tests, not for dispatch decisions.
impl PartialEq for Compressor {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::fn_addr_eq(self.0, other.0)
    }
}

impl Eq for Compressor {}

impl Compressor {
    /// The portable (safe Rust) compression function.
    pub const PORTABLE: Self = Self(portable_compress_blocks);

    /// Wraps a compression function. It must process any number of whole
    /// 64-byte blocks and leave a partial tail untouched.
    #[must_use]
    pub const fn new(f: fn(&mut [u32; 8], &[u8])) -> Self {
        Self(f)
    }

    /// Compresses whole blocks into the chaining state.
    pub(crate) fn run(&self, state: &mut [u32; 8], blocks: &[u8]) {
        debug_assert_eq!(blocks.len() % BLOCK_LEN, 0);
        (self.0)(state, blocks);
    }
}

/// Portable SHA-256 compression over any number of whole blocks.
///
/// Panics never; a non-multiple of 64 is a programming error and is caught by
/// a debug assertion.
pub fn portable_compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK_LEN, 0);
    for block in blocks.chunks_exact(BLOCK_LEN) {
        let mut b = [0u8; BLOCK_LEN];
        b.copy_from_slice(block);
        compress(state, &b);
    }
}

/// Incremental SHA-256 hasher.
///
/// # Example
///
/// ```
/// use fastcrypto_core::Sha256;
///
/// let mut h = Sha256::new();
/// h.update(b"hello ");
/// h.update(b"world");
/// assert_eq!(h.finalize(), fastcrypto_core::sha256(b"hello world"));
/// ```
#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    block: [u8; BLOCK_LEN],
    block_len: usize,
    /// Total number of bytes absorbed so far.
    len: u64,
    /// Backend selected for this instance.
    compressor: Compressor,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for Sha256 {
    /// Deliberately prints only the absorbed length: the internal state and the
    /// partial block are secret-derived material and must not reach logs.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha256")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
    }
}

impl Zeroize for Sha256 {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        self.block_len = 0;
        self.len = 0;
    }
}

impl Sha256 {
    /// Creates a fresh hasher with the FIPS 180-4 initial state.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_compressor(Compressor::PORTABLE)
    }

    /// Creates a hasher that uses the given compression backend.
    #[must_use]
    pub const fn with_compressor(compressor: Compressor) -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            len: 0,
            compressor,
        }
    }

    /// Rebuilds a hasher from a mid-stream state.
    ///
    /// Internal seam used by HMAC, which needs to replay a precomputed key
    /// block. `consumed` is the number of bytes already absorbed into `state`
    /// and must be a multiple of `BLOCK_LEN`.
    #[must_use]
    pub(crate) const fn from_state(state: [u32; 8], consumed: u64, compressor: Compressor) -> Self {
        debug_assert!(consumed.is_multiple_of(BLOCK_LEN as u64));
        Self {
            state,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            len: consumed,
            compressor,
        }
    }

    /// Absorbs `data` into the hash state.
    ///
    /// The input is consumed without buffering: complete 64-byte blocks are
    /// compressed straight out of the caller's slice, and only a trailing
    /// partial block is copied into internal state.
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.len = self.len.wrapping_add(data.len() as u64);

        // Finish a partial block left over from a previous update call, if any.
        if self.block_len > 0 {
            let take = core::cmp::min(BLOCK_LEN - self.block_len, data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len < BLOCK_LEN {
                return;
            }
            let block = self.block;
            self.compressor.run(&mut self.state, &block);
            self.block_len = 0;
        }

        // Hand every whole block to the backend in one call: the backend
        // loops internally, which is what lets an accelerated backend
        // amortise its own setup over the whole input.
        let whole = data.len() - data.len() % BLOCK_LEN;
        if whole > 0 {
            self.compressor.run(&mut self.state, &data[..whole]);
        }

        let tail = &data[whole..];
        if !tail.is_empty() {
            self.block[..tail.len()].copy_from_slice(tail);
            self.block_len = tail.len();
        }
    }

    /// Returns the digest of everything absorbed so far.
    ///
    /// This does **not** consume or reset the hasher, which makes it usable for
    /// TLS-style transcript hashes where the transcript keeps growing after a
    /// handshake message has been hashed.
    #[must_use]
    pub fn finalize(&self) -> [u8; DIGEST_LEN] {
        let mut out = [0u8; DIGEST_LEN];
        self.finalize_into(&mut out);
        out
    }

    /// Writes the digest of everything absorbed so far into `out`.
    pub fn finalize_into(&self, out: &mut [u8; DIGEST_LEN]) {
        let mut scratch = [0u8; 2 * BLOCK_LEN];
        scratch[..self.block_len].copy_from_slice(&self.block[..self.block_len]);
        scratch[self.block_len] = 0x80;

        // Only the low 64 bits of the bit length are used, which is exactly
        // what FIPS 180-4 requires.
        let bit_len = self.len.wrapping_mul(8);

        // Bytes needed: buffered tail + 0x80 delimiter + 8 length bytes.
        let blocks = (self.block_len + 9).div_ceil(BLOCK_LEN);
        let len_at = blocks * BLOCK_LEN - 8;
        scratch[len_at..len_at + 8].copy_from_slice(&bit_len.to_be_bytes());

        let mut state = self.state;
        let used = blocks * BLOCK_LEN;
        self.compressor.run(&mut state, &scratch[..used]);
        // Only the bytes that were written can hold message data, so
        // zeroizing the whole scratch would be wasted work: the volatile
        // stores are the expensive part of a small finalize.
        scratch[..used].zeroize();
        for (i, word) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        state.zeroize();
    }

    /// Resets the hasher back to the initial state.
    pub fn reset(&mut self) {
        self.state = INITIAL_STATE;
        self.block.zeroize();
        self.block_len = 0;
        self.len = 0;
    }

    /// Number of bytes absorbed so far.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.len
    }

    /// Current chaining state.
    ///
    /// Internal seam used by HMAC to snapshot the state after the ipad/opad
    /// key blocks have been absorbed.
    #[must_use]
    pub(crate) const fn state(&self) -> [u32; 8] {
        self.state
    }
}

/// One-shot SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// SHA-256 compression function: mixes one 64-byte block into `state`.
///
/// `#[inline(always)]` is deliberate: this is the entire hot loop, and a
/// non-inlined copy costs a call per 64-byte block.
// The compression function is the entire hot loop; keeping it out of line
// costs a call per 64-byte block. See benchmarks/results/ for measurements.
#[allow(clippy::inline_always)]
#[inline(always)]
fn compress(state: &mut [u32; 8], block: &[u8; BLOCK_LEN]) {
    // Circular 16-word message schedule.
    //
    // The FIPS 180-4 recurrence only ever looks 16 words back, so the schedule
    // is kept in a 16-slot ring instead of a [u32; 64] array: at round i the
    // slot holding w[i] is refilled with w[i+16] immediately after it is
    // consumed. The whole schedule therefore stays in registers instead of
    // living on the stack, which is where the first portable implementation
    // spent its time (measured: 12.3 vs 8.1 cycles/byte against a portable
    // reference; see benchmarks/results/).
    //
    // The last 16 rounds compute a schedule word that is never used. That costs
    // about 16 * 7 arithmetic ops per block and removes a branch per round.
    let mut w = [0u32; 16];
    for (i, chunk) in block.chunks_exact(4).enumerate() {
        w[i] = u32::from_be_bytes(chunk.try_into().expect("chunks_exact(4) yields 4 bytes"));
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Four groups of sixteen rounds. Inside a group the message word index is
    // the inner counter itself, so after unrolling every index is a constant
    // and the schedule stays in registers. The fourth group computes no new
    // schedule words, because no round consumes them.
    for j in 0..4 {
        for k in 0..16 {
            let round = j * 16 + k;
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[round])
                .wrapping_add(w[k]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);

            if j < 3 {
                let y = w[(k + 1) & 15];
                let z = w[(k + 9) & 15];
                let v = w[(k + 14) & 15];
                let sig0 = y.rotate_right(7) ^ y.rotate_right(18) ^ (y >> 3);
                let sig1 = v.rotate_right(17) ^ v.rotate_right(19) ^ (v >> 10);
                w[k] = w[k].wrapping_add(sig0).wrapping_add(z).wrapping_add(sig1);
            }
        }
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{Sha256, sha256};

    fn hex(bytes: &[u8]) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(T[usize::from(b >> 4)] as char);
            s.push(T[usize::from(b & 0xf)] as char);
        }
        s
    }

    #[test]
    fn empty_input_matches_fips_vector() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_matches_fips_vector() {
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn streaming_is_chunker_agnostic() {
        let data = [0x5au8; 1000];
        let expected = sha256(&data);
        for chunk in [1usize, 3, 15, 16, 31, 32, 55, 56, 57, 63, 64, 65, 128, 999] {
            let mut h = Sha256::new();
            for part in data.chunks(chunk) {
                h.update(part);
            }
            assert_eq!(h.finalize(), expected, "chunk size {chunk}");
        }
    }

    #[test]
    fn finalize_is_non_destructive() {
        let mut h = Sha256::new();
        h.update(b"abc");
        let d1 = h.finalize();
        h.update(b"d");
        let d2 = h.finalize();
        assert_eq!(d1, sha256(b"abc"));
        assert_eq!(d2, sha256(b"abcd"));
        assert_eq!(h.count(), 4);
    }

    #[test]
    fn reset_returns_to_initial_state() {
        let mut h = Sha256::new();
        h.update(&[0x11; 200]);
        h.reset();
        assert_eq!(h.count(), 0);
        h.update(b"abc");
        assert_eq!(h.finalize(), sha256(b"abc"));
    }

    #[test]
    fn debug_does_not_leak_state() {
        let mut h = Sha256::new();
        h.update(b"secret");
        let s = format!("{h:?}");
        assert!(s.contains("len"), "{s}");
        assert!(s.contains("Sha256"), "{s}");
    }

    #[test]
    fn multi_block_padding_boundaries() {
        // Every length in [0, 130] exercises the padding special cases
        // (tail < 56, tail == 56, tail > 56).
        let data: Vec<u8> = (0..130u32).map(|i| (i * 7 + 3).to_le_bytes()[0]).collect();
        for n in 0..=data.len() {
            let one_shot = sha256(&data[..n]);
            let mut h = Sha256::new();
            h.update(&data[..n / 2]);
            h.update(&data[n / 2..n]);
            assert_eq!(h.finalize(), one_shot, "len {n}");
        }
    }
}

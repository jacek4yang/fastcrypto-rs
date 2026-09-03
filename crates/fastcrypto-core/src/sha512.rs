//! Portable SHA-512 and SHA-384.
//!
//! rust-reality performs both per session: a SHA-384 transcript and key
//! schedule for the `AES-256-GCM-SHA384` suite, and one HMAC-SHA512 for the
//! Xray certificate binding. Ed25519 needs SHA-512 internally.
//!
//! Unlike SHA-256 there is no hardware backend to dispatch to on x86_64 — the
//! SHA extensions cover SHA-1 and SHA-256 only — so this is a single portable
//! implementation with no indirection. Measured dispatch cost in the SHA-256
//! path is +38 instructions per call, which is not worth paying for a choice
//! that does not exist. An AArch64 SHA-512 backend would be a reason to add it
//! later; today it would be overhead with no alternative to select.
//!
//! The round function is unrolled for the same reason it is in `sha256`: the
//! working-variable rotation is free when the compiler does it by name and
//! costs eight register moves per round when it does not.

// `as_chunks` would be tidier, but `chunks_exact` compiles to the same loop
// here and keeps the two digest modules structurally identical.
#![allow(clippy::chunks_exact_to_as_chunks)]

use zeroize::Zeroize;

/// SHA-512 block size in bytes.
pub const BLOCK_LEN: usize = 128;
/// SHA-512 digest length in bytes.
pub const SHA512_DIGEST_LEN: usize = 64;
/// SHA-384 digest length in bytes.
pub const SHA384_DIGEST_LEN: usize = 48;

/// FIPS 180-4 §4.2.3: the first 64 bits of the fractional parts of the cube
/// roots of the first eighty primes.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// FIPS 180-4 §5.3.5: square roots of the first eight primes.
const IV_512: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// FIPS 180-4 §5.3.4: square roots of the ninth through sixteenth primes.
const IV_384: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

macro_rules! round {
    ($a:ident, $b:ident, $c:ident, $d:ident, $e:ident, $f:ident, $g:ident, $h:ident,
     $i:expr, $w:expr) => {{
        let s1 = $e.rotate_right(14) ^ $e.rotate_right(18) ^ $e.rotate_right(41);
        let ch = ($e & $f) ^ ((!$e) & $g);
        let t1 = $h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[$i])
            .wrapping_add($w);
        let s0 = $a.rotate_right(28) ^ $a.rotate_right(34) ^ $a.rotate_right(39);
        let maj = ($a & $b) ^ ($a & $c) ^ ($b & $c);
        $d = $d.wrapping_add(t1);
        $h = t1.wrapping_add(s0).wrapping_add(maj);
    }};
}

macro_rules! schedule {
    ($w:expr, $i:expr) => {{
        let y = $w[($i + 1) & 15];
        let v = $w[($i + 14) & 15];
        let s0 = y.rotate_right(1) ^ y.rotate_right(8) ^ (y >> 7);
        let s1 = v.rotate_right(19) ^ v.rotate_right(61) ^ (v >> 6);
        $w[$i & 15] = $w[$i & 15]
            .wrapping_add(s0)
            .wrapping_add($w[($i + 9) & 15])
            .wrapping_add(s1);
        $w[$i & 15]
    }};
}

macro_rules! rounds8 {
    ($w:expr, $base:expr, $a:ident, $b:ident, $c:ident, $d:ident,
     $e:ident, $f:ident, $g:ident, $h:ident) => {
        round!($a, $b, $c, $d, $e, $f, $g, $h, $base, $w[$base & 15]);
        round!(
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $base + 1,
            $w[($base + 1) & 15]
        );
        round!(
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $base + 2,
            $w[($base + 2) & 15]
        );
        round!(
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $base + 3,
            $w[($base + 3) & 15]
        );
        round!(
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $base + 4,
            $w[($base + 4) & 15]
        );
        round!(
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $base + 5,
            $w[($base + 5) & 15]
        );
        round!(
            $c,
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $base + 6,
            $w[($base + 6) & 15]
        );
        round!(
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $base + 7,
            $w[($base + 7) & 15]
        );
    };
}

macro_rules! rounds8_extending {
    ($w:expr, $base:expr, $a:ident, $b:ident, $c:ident, $d:ident,
     $e:ident, $f:ident, $g:ident, $h:ident) => {
        round!($a, $b, $c, $d, $e, $f, $g, $h, $base, schedule!($w, $base));
        round!(
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $base + 1,
            schedule!($w, $base + 1)
        );
        round!(
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $f,
            $base + 2,
            schedule!($w, $base + 2)
        );
        round!(
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $e,
            $base + 3,
            schedule!($w, $base + 3)
        );
        round!(
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $d,
            $base + 4,
            schedule!($w, $base + 4)
        );
        round!(
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $c,
            $base + 5,
            schedule!($w, $base + 5)
        );
        round!(
            $c,
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $b,
            $base + 6,
            schedule!($w, $base + 6)
        );
        round!(
            $b,
            $c,
            $d,
            $e,
            $f,
            $g,
            $h,
            $a,
            $base + 7,
            schedule!($w, $base + 7)
        );
    };
}

/// Compresses whole 128-byte blocks into the chaining state.
///
/// A non-multiple of the block length is a programming error; the remainder is
/// ignored, which `chunks_exact` makes memory-safe regardless.
pub fn compress_blocks(state: &mut [u64; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK_LEN, 0);
    for block in blocks.chunks_exact(BLOCK_LEN) {
        compress(state, block);
    }
}

#[allow(
    clippy::inline_always,
    reason = "the compression function is the hot loop"
)]
#[inline(always)]
fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 16];
    for (i, chunk) in block.chunks_exact(8).enumerate() {
        w[i] = u64::from_be_bytes(chunk.try_into().expect("chunks_exact(8) yields 8 bytes"));
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    rounds8!(w, 0, a, b, c, d, e, f, g, h);
    rounds8!(w, 8, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 16, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 24, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 32, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 40, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 48, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 56, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 64, a, b, c, d, e, f, g, h);
    rounds8_extending!(w, 72, a, b, c, d, e, f, g, h);

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Incremental SHA-512 / SHA-384 hasher.
///
/// One type parameterised by initial state and output length, because the two
/// functions differ only in those two things. Cloning is supported because the
/// TLS transcript needs a snapshot at four milestones per handshake without
/// disturbing the running state.
#[derive(Clone)]
pub struct Sha512Core {
    state: [u64; 8],
    block: [u8; BLOCK_LEN],
    block_len: usize,
    /// Total message bytes absorbed. FIPS 180-4 encodes a 128-bit bit-length;
    /// `u64` bytes cannot overflow it, so the high half is always zero.
    len: u64,
    /// High-water mark of `block`, so drop only clears what was written.
    block_filled: usize,
}

impl core::fmt::Debug for Sha512Core {
    /// Deliberately opaque: the chaining state is secret in keyed use.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sha512Core").finish_non_exhaustive()
    }
}

impl Drop for Sha512Core {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block[..self.block_filled].zeroize();
    }
}

impl Zeroize for Sha512Core {
    fn zeroize(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        self.block_len = 0;
        self.block_filled = 0;
        self.len = 0;
    }
}

impl Sha512Core {
    /// Creates a hasher with the given initial chaining state.
    #[must_use]
    pub const fn with_state(state: [u64; 8]) -> Self {
        Self {
            state,
            block: [0u8; BLOCK_LEN],
            block_len: 0,
            len: 0,
            block_filled: 0,
        }
    }

    /// Absorbs more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        let mut data = data;
        self.len = self.len.wrapping_add(data.len() as u64);

        if self.block_len > 0 {
            let take = core::cmp::min(BLOCK_LEN - self.block_len, data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            self.block_filled = self.block_filled.max(self.block_len);
            data = &data[take..];
            if self.block_len < BLOCK_LEN {
                return;
            }
            let block = self.block;
            compress_blocks(&mut self.state, &block);
            self.block_len = 0;
        }

        // Whole blocks go straight from the caller's slice: they never touch
        // the buffer, so a block-aligned message leaves `block_filled` at zero.
        let whole = data.len() - data.len() % BLOCK_LEN;
        if whole > 0 {
            compress_blocks(&mut self.state, &data[..whole]);
            data = &data[whole..];
        }
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
            self.block_filled = self.block_filled.max(self.block_len);
        }
    }

    /// Finalises a *copy* of the state, leaving `self` usable.
    fn finalize_state(&self) -> [u64; 8] {
        // Padding needs the tail, one 0x80 byte and a 16-byte length, so one
        // block when the tail is short enough and two otherwise.
        let blocks = (self.block_len + 17).div_ceil(BLOCK_LEN);
        let used = blocks * BLOCK_LEN;
        let mut scratch = [0u8; 2 * BLOCK_LEN];
        scratch[..self.block_len].copy_from_slice(&self.block[..self.block_len]);
        scratch[self.block_len] = 0x80;

        let bit_len = u128::from(self.len).wrapping_mul(8);
        scratch[used - 16..used].copy_from_slice(&bit_len.to_be_bytes());

        let mut state = self.state;
        compress_blocks(&mut state, &scratch[..used]);

        // Only the message tail, the 0x80 and the length bytes are values this
        // function did not write as zero.
        scratch[..self.block_len + 1].zeroize();
        scratch[used - 16..used].zeroize();
        state
    }

    /// Writes the first `N` digest bytes, which is what SHA-384 truncation is.
    pub fn finalize_into<const N: usize>(&self, out: &mut [u8; N]) {
        let mut state = self.finalize_state();
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            let word = state[i].to_be_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
        state.zeroize();
    }

    /// Resets to the given initial state.
    pub fn reset(&mut self, state: [u64; 8]) {
        self.state = state;
        self.block[..self.block_filled].zeroize();
        self.block_len = 0;
        self.block_filled = 0;
        self.len = 0;
    }
}

/// SHA-512.
#[derive(Clone, Debug)]
pub struct Sha512(Sha512Core);

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Creates a SHA-512 hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sha512Core::with_state(IV_512))
    }

    /// Absorbs more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest of everything absorbed so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; SHA512_DIGEST_LEN] {
        let mut out = [0u8; SHA512_DIGEST_LEN];
        self.0.finalize_into(&mut out);
        out
    }

    /// Writes the digest into `out`.
    pub fn finalize_into(&self, out: &mut [u8; SHA512_DIGEST_LEN]) {
        self.0.finalize_into(out);
    }

    /// Resets to the initial state.
    pub fn reset(&mut self) {
        self.0.reset(IV_512);
    }
}

/// SHA-384: SHA-512 with a different initial state, truncated to 48 bytes.
#[derive(Clone, Debug)]
pub struct Sha384(Sha512Core);

impl Default for Sha384 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha384 {
    /// Creates a SHA-384 hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sha512Core::with_state(IV_384))
    }

    /// Absorbs more message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// Returns the digest of everything absorbed so far.
    #[must_use]
    pub fn finalize(&self) -> [u8; SHA384_DIGEST_LEN] {
        let mut out = [0u8; SHA384_DIGEST_LEN];
        self.0.finalize_into(&mut out);
        out
    }

    /// Writes the digest into `out`.
    pub fn finalize_into(&self, out: &mut [u8; SHA384_DIGEST_LEN]) {
        self.0.finalize_into(out);
    }

    /// Resets to the initial state.
    pub fn reset(&mut self) {
        self.0.reset(IV_384);
    }
}

/// One-shot SHA-512.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; SHA512_DIGEST_LEN] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-384.
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; SHA384_DIGEST_LEN] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use alloc::vec;

    use super::{Sha384, Sha512, sha384, sha512};

    fn hex(bytes: &[u8]) -> String {
        const T: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(T[usize::from(b >> 4)] as char);
            s.push(T[usize::from(b & 15)] as char);
        }
        s
    }

    /// FIPS 180-4 and NIST CAVP known-answer vectors.
    #[test]
    fn published_vectors() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        // FIPS 180-4 D.2: 112-byte message crossing into a second block.
        assert_eq!(
            hex(&sha512(
                b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
            )),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
        assert_eq!(
            hex(&sha384(b"")),
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
             274edebfe76f65fbd51ad2f14898b95b"
        );
        assert_eq!(
            hex(&sha384(b"abc")),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
             8086072ba1e7cc2358baeca134c825a7"
        );
    }

    /// The padding boundary: a message whose tail leaves fewer than 17 bytes
    /// forces a second compression block.
    #[test]
    fn padding_spills_into_a_second_block() {
        for len in [0usize, 1, 111, 112, 113, 127, 128, 129, 255, 256, 257] {
            let data = vec![0x61u8; len];
            let mut incremental = Sha512::new();
            for chunk in data.chunks(7).filter(|c| !c.is_empty()) {
                incremental.update(chunk);
            }
            assert_eq!(incremental.finalize(), sha512(&data), "len {len}");
        }
    }

    /// The transcript shape: a snapshot must not disturb the running state.
    #[test]
    fn a_clone_snapshot_leaves_the_hasher_usable() {
        let mut h = Sha384::new();
        h.update(b"client hello");
        let snapshot = h.clone().finalize();
        assert_eq!(snapshot, sha384(b"client hello"));
        h.update(b"server hello");
        assert_eq!(h.finalize(), sha384(b"client helloserver hello"));
        // And finalising twice must be idempotent, because `finalize` works on
        // a copy rather than consuming the state.
        assert_eq!(h.finalize(), sha384(b"client helloserver hello"));
    }

    #[test]
    fn reset_returns_the_initial_state() {
        let mut h = Sha512::new();
        h.update(b"discarded");
        h.reset();
        h.update(b"abc");
        assert_eq!(h.finalize(), sha512(b"abc"));
    }
}

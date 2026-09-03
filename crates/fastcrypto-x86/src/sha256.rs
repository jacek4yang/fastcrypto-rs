//! SHA-256 with Intel SHA Extensions (SHA-NI).
//!
//! This is the x86_64 accelerated compression function. It follows the
//! formulation from Intel's Fast SHA-256 Implementations on Intel Architecture
//! Processors: the message schedule is computed with sha256msg1/sha256msg2 and
//! four rounds at a time with sha256rnds2, over a state laid out as
//! abef = [A, B, E, F] and cdgh = [C, D, G, H].
//!
//! # Safety contract
//!
//! `compress_blocks` executes SHA instructions unconditionally.
//! Callers must check `crate::Features::cached().sha_ni()` first; the dispatch in the
//! fastcrypto crate does exactly that, and keeps the portable backend as the
//! fallback.

#![cfg(target_arch = "x86_64")]
// slice::as_chunks is not stable; the zero-copy chunk iterator is what this
// loop needs.
#![allow(clippy::chunks_exact_to_as_chunks)]

use core::arch::x86_64::{
    __m128i, _mm_add_epi32, _mm_alignr_epi8, _mm_blend_epi16, _mm_loadu_si128, _mm_set_epi32,
    _mm_set_epi64x, _mm_sha256msg1_epu32, _mm_sha256msg2_epu32, _mm_sha256rnds2_epu32,
    _mm_shuffle_epi8, _mm_shuffle_epi32, _mm_storeu_si128,
};

/// SHA-256 block length in bytes.
pub const BLOCK_LEN: usize = 64;

/// SHA-256 round constants grouped in fours, in lane order: index 0 is the
/// constant for the first of the four rounds.
const K32X4: [[i32; 4]; 16] = [
    [
        0x428a_2f98u32 as i32,
        0x7137_4491u32 as i32,
        0xb5c0_fbcfu32 as i32,
        0xe9b5_dba5u32 as i32,
    ],
    [
        0x3956_c25bu32 as i32,
        0x59f1_11f1u32 as i32,
        0x923f_82a4u32 as i32,
        0xab1c_5ed5u32 as i32,
    ],
    [
        0xd807_aa98u32 as i32,
        0x1283_5b01u32 as i32,
        0x2431_85beu32 as i32,
        0x550c_7dc3u32 as i32,
    ],
    [
        0x72be_5d74u32 as i32,
        0x80de_b1feu32 as i32,
        0x9bdc_06a7u32 as i32,
        0xc19b_f174u32 as i32,
    ],
    [
        0xe49b_69c1u32 as i32,
        0xefbe_4786u32 as i32,
        0x0fc1_9dc6u32 as i32,
        0x240c_a1ccu32 as i32,
    ],
    [
        0x2de9_2c6fu32 as i32,
        0x4a74_84aau32 as i32,
        0x5cb0_a9dcu32 as i32,
        0x76f9_88dau32 as i32,
    ],
    [
        0x983e_5152u32 as i32,
        0xa831_c66du32 as i32,
        0xb003_27c8u32 as i32,
        0xbf59_7fc7u32 as i32,
    ],
    [
        0xc6e0_0bf3u32 as i32,
        0xd5a7_9147u32 as i32,
        0x06ca_6351u32 as i32,
        0x1429_2967u32 as i32,
    ],
    [
        0x27b7_0a85u32 as i32,
        0x2e1b_2138u32 as i32,
        0x4d2c_6dfcu32 as i32,
        0x5338_0d13u32 as i32,
    ],
    [
        0x650a_7354u32 as i32,
        0x766a_0abbu32 as i32,
        0x81c2_c92eu32 as i32,
        0x9272_2c85u32 as i32,
    ],
    [
        0xa2bf_e8a1u32 as i32,
        0xa81a_664bu32 as i32,
        0xc24b_8b70u32 as i32,
        0xc76c_51a3u32 as i32,
    ],
    [
        0xd192_e819u32 as i32,
        0xd699_0624u32 as i32,
        0xf40e_3585u32 as i32,
        0x106a_a070u32 as i32,
    ],
    [
        0x19a4_c116u32 as i32,
        0x1e37_6c08u32 as i32,
        0x2748_774cu32 as i32,
        0x34b0_bcb5u32 as i32,
    ],
    [
        0x391c_0cb3u32 as i32,
        0x4ed8_aa4au32 as i32,
        0x5b9c_ca4fu32 as i32,
        0x682e_6ff3u32 as i32,
    ],
    [
        0x748f_82eeu32 as i32,
        0x78a5_636fu32 as i32,
        0x84c8_7814u32 as i32,
        0x8cc7_0208u32 as i32,
    ],
    [
        0x90be_fffau32 as i32,
        0xa450_6cebu32 as i32,
        0xbef9_a3f7u32 as i32,
        0xc671_78f2u32 as i32,
    ],
];

/// Compresses any number of whole 64-byte blocks into the chaining state.
///
/// # Safety
///
/// The CPU must support SHA-NI, SSE2, SSSE3 and SSE4.1, and the length of
/// `blocks` must be a multiple of 64.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn compress_blocks_sha_ni(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % BLOCK_LEN, 0);
    // SAFETY:
    // * The target_feature attribute above enables sha, sse2, ssse3 and sse4.1
    //   for this function, and the caller verified the CPU implements them, so
    //   every intrinsic used here is executable.
    // * state is 8 u32 = 32 bytes = two 16-byte vectors, so the two loads and
    //   two stores stay in bounds; the unaligned forms are used deliberately,
    //   so no alignment requirement is imposed on the caller.
    // * blocks.len() is a multiple of 64, so the four 16-byte loads per block
    //   are in bounds.
    // * state is exclusively borrowed and blocks is read-only for the duration,
    //   so no aliasing is possible.
    unsafe {
        // Reverse the bytes of every 32-bit word: SHA-256 is big-endian, the
        // vector registers are little-endian.
        let mask = _mm_set_epi64x(
            0x0c0d_0e0f_0809_0a0bu64 as i64,
            0x0405_0607_0001_0203u64 as i64,
        );

        let state_ptr = state.as_ptr().cast::<__m128i>();
        let dcba = _mm_loadu_si128(state_ptr.add(0));
        let hgfe = _mm_loadu_si128(state_ptr.add(1));

        // Rearrange [a,b,c,d] [e,f,g,h] into the [A,B,E,F] / [C,D,G,H] layout
        // that sha256rnds2 expects.
        let cdab = _mm_shuffle_epi32(dcba, 0xb1);
        let efgh = _mm_shuffle_epi32(hgfe, 0x1b);
        let mut abef = _mm_alignr_epi8(cdab, efgh, 8);
        let mut cdgh = _mm_blend_epi16(efgh, cdab, 0xf0);

        for block in blocks.chunks_exact(BLOCK_LEN) {
            let abef_save = abef;
            let cdgh_save = cdgh;

            let block_ptr = block.as_ptr().cast::<__m128i>();
            let mut w0 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(0)), mask);
            let mut w1 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(1)), mask);
            let mut w2 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(2)), mask);
            let mut w3 = _mm_shuffle_epi8(_mm_loadu_si128(block_ptr.add(3)), mask);
            let mut w4;

            rounds4!(abef, cdgh, w0, 0);
            rounds4!(abef, cdgh, w1, 1);
            rounds4!(abef, cdgh, w2, 2);
            rounds4!(abef, cdgh, w3, 3);
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 4);
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 5);
            schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 6);
            schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 7);
            schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 8);
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 9);
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 10);
            schedule_rounds4!(abef, cdgh, w2, w3, w4, w0, w1, 11);
            schedule_rounds4!(abef, cdgh, w3, w4, w0, w1, w2, 12);
            schedule_rounds4!(abef, cdgh, w4, w0, w1, w2, w3, 13);
            schedule_rounds4!(abef, cdgh, w0, w1, w2, w3, w4, 14);
            schedule_rounds4!(abef, cdgh, w1, w2, w3, w4, w0, 15);

            abef = _mm_add_epi32(abef, abef_save);
            cdgh = _mm_add_epi32(cdgh, cdgh_save);
        }

        // Back to [a,b,c,d] [e,f,g,h].
        let feba = _mm_shuffle_epi32(abef, 0x1b);
        let dchg = _mm_shuffle_epi32(cdgh, 0xb1);
        let dcba = _mm_blend_epi16(feba, dchg, 0xf0);
        let hgef = _mm_alignr_epi8(dchg, feba, 8);

        let state_mut = state.as_mut_ptr().cast::<__m128i>();
        _mm_storeu_si128(state_mut.add(0), dcba);
        _mm_storeu_si128(state_mut.add(1), hgef);
    }
}

/// Compresses whole 64-byte blocks, using SHA-NI when the CPU has it.
///
////// This is the safe entry point used by dispatch: it performs the runtime
/// feature check itself and falls back to the portable backend, so callers
/// cannot select an instruction the CPU does not implement. The check is a
/// relaxed atomic load after the first call.
#[inline]
pub fn compress_blocks(state: &mut [u32; 8], blocks: &[u8]) {
    if crate::Features::cached().sha_ni() {
        // SAFETY: sha_ni was just verified for this CPU, so the SHA, SSE2,
        // SSSE3 and SSE4.1 instructions used by the function are executable.
        unsafe { compress_blocks_sha_ni(state, blocks) }
    } else {
        fastcrypto_core::sha256::portable_compress_blocks(state, blocks);
    }
}

/// Four SHA-256 rounds from four already-computed message words.
///
/// Each sha256rnds2 instruction performs two rounds, so one macro expansion is
/// four rounds: two from cdgh and two from abef, with the message words swapped
/// between them.
macro_rules! rounds4 {
    ($abef:ident, $cdgh:ident, $w:expr, $i:expr) => {
        let k = K32X4[$i];
        let kv = _mm_set_epi32(k[3], k[2], k[1], k[0]);
        let t1 = _mm_add_epi32($w, kv);
        $cdgh = _mm_sha256rnds2_epu32($cdgh, $abef, t1);
        let t2 = _mm_shuffle_epi32(t1, 0x0e);
        $abef = _mm_sha256rnds2_epu32($abef, $cdgh, t2);
    };
}

/// The next four message words, then four rounds over them.
///
/// w[i+16] = w[i] + sigma0(w[i+1]) + w[i+9] + sigma1(w[i+14)], computed by
/// sha256msg1 (the sigma0 part) and sha256msg2 (the sigma1 part and the sum).
macro_rules! schedule_rounds4 {
    ($abef:ident, $cdgh:ident, $w0:expr, $w1:expr, $w2:expr, $w3:expr, $w4:expr, $i:expr) => {
        let t1 = _mm_sha256msg1_epu32($w0, $w1);
        let t2 = _mm_alignr_epi8($w3, $w2, 4);
        let t3 = _mm_add_epi32(t1, t2);
        $w4 = _mm_sha256msg2_epu32(t3, $w3);
        rounds4!($abef, $cdgh, $w4, $i);
    };
}

use rounds4;
use schedule_rounds4;

#[cfg(test)]
mod tests {
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    use super::{BLOCK_LEN, compress_blocks_sha_ni};

    fn hex(state: &[u32; 8]) -> String {
        state.iter().map(|w| format!("{w:08x}")).collect()
    }

    /// The accelerated path must reproduce FIPS 180-4 exactly.
    #[test]
    fn matches_known_answers() {
        if !crate::Features::cached().sha_ni() {
            std::eprintln!("skipped: no SHA-NI on this CPU");
            return;
        }
        let cases: [(&[u8], &str); 3] = [
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abc",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ];
        for (msg, expected) in cases {
            let mut padded = msg.to_vec();
            padded.push(0x80);
            while padded.len() % BLOCK_LEN != BLOCK_LEN - 8 {
                padded.push(0);
            }
            let bit_len = u64::try_from(msg.len()).unwrap() * 8;
            padded.extend_from_slice(&bit_len.to_be_bytes());

            let mut state = [
                0x6a09_e667u32,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ];
            // SAFETY: sha_ni was verified above and padded.len() is a multiple
            // of 64.
            unsafe { compress_blocks_sha_ni(&mut state, &padded) };
            assert_eq!(hex(&state), expected);
        }
    }

    /// Two blocks in one call must equal the same blocks compressed one by one.
    #[test]
    fn multiple_blocks_match_single_blocks() {
        if !crate::Features::cached().sha_ni() {
            return;
        }
        let data = vec![0x5au8; 128];
        let mut once = [
            0x6a09_e667u32,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let mut twice = once;
        // SAFETY: sha_ni verified above, both slices are multiples of 64.
        unsafe {
            compress_blocks_sha_ni(&mut once, &data);
            compress_blocks_sha_ni(&mut twice, &data[..64]);
            compress_blocks_sha_ni(&mut twice, &data[64..]);
        }
        assert_eq!(once, twice);
    }
}

//! Tiny deterministic PRNG for benchmark and test inputs.
//!
//! Benchmarks must use reproducible data: a run that feeds random bytes to one
//! implementation and different random bytes to another is not a comparison.
//! This is xorshift64*, which is fast, seedable, and has no dependencies.

/// Deterministic, allocation-free PRNG.
#[derive(Debug, Clone)]
pub struct Prng(u64);

impl Prng {
    /// Creates a PRNG from a seed. Seed 0 is rejected by construction.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    /// Next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Fills a buffer with deterministic bytes.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let v = self.next_u64().to_le_bytes();
            for b in v {
                if i == out.len() {
                    return;
                }
                out[i] = b;
                i += 1;
            }
        }
    }

    /// Returns a fresh 32-byte value, e.g. a key or nonce.
    #[must_use]
    pub fn array32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.fill(&mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Prng;

    #[test]
    fn is_deterministic() {
        let mut a = Prng::new(42);
        let mut b = Prng::new(42);
        assert_eq!(a.array32(), b.array32());
        assert_eq!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn different_seeds_differ() {
        assert_ne!(Prng::new(1).array32(), Prng::new(2).array32());
    }

    #[test]
    fn fill_covers_whole_buffer() {
        let mut p = Prng::new(7);
        let mut buf = [0u8; 100];
        p.fill(&mut buf);
        assert!(buf.iter().any(|b| *b != 0));
    }
}

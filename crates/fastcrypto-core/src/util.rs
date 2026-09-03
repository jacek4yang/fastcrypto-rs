//! Small internal helpers shared by the portable primitives.

/// XOR `rhs` into `lhs` in place.
///
/// Used to build the HMAC ipad/opad blocks. Data-independent: no branches, no
/// secret-dependent indexing.
#[inline]
pub(crate) fn xor_into(lhs: &mut [u8], rhs: &[u8]) {
    debug_assert_eq!(lhs.len(), rhs.len());
    for (l, r) in lhs.iter_mut().zip(rhs.iter()) {
        *l ^= *r;
    }
}

/// Constant-time comparison of two byte strings.
///
/// Runs over the full input and accumulates differences, so the number of
/// executed instructions does not depend on where the first difference is.
/// Length is compared explicitly; lengths are not treated as secret here.
#[inline]
#[must_use]
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

#[cfg(test)]
mod tests {
    use super::{ct_eq, xor_into};

    #[test]
    fn ct_eq_detects_any_difference() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"\0"));
        // A bit flip in the very last byte must still be detected.
        let mut v = [0u8; 32];
        v[31] = 1;
        assert!(!ct_eq(&[0u8; 32], &v));
    }

    #[test]
    fn xor_into_works() {
        let mut a = [0b1010_1010u8, 0x00, 0xff];
        xor_into(&mut a, &[0b0101_0101, 0xff, 0x0f]);
        assert_eq!(a, [0xff, 0xff, 0xf0]);
    }
}

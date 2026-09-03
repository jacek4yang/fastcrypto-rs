//! Message sizes used by every benchmark group.
//!
//! The list is deliberately anchored on real TLS behaviour: 0 bytes (empty
//! handshake fragments and zero-length application data), the small records
//! that dominate request-heavy traffic, the 1350/1400/1500 cluster around
//! typical MTUs, and the larger buffers that show streaming throughput.

/// Sizes in bytes: small TLS records first, then streaming sizes.
pub const TLS_SIZES: &[usize] = &[
    0, 16, 32, 64, 128, 256, 512, 1024, 1350, 1400, 1500, 4096, 8192, 16384, 65536,
];

/// Short labels for each size, used in benchmark IDs.
#[must_use]
pub fn label(size: usize) -> String {
    if size >= 1024 && size.is_multiple_of(1024) {
        format!("{}KiB", size / 1024)
    } else {
        format!("{size}B")
    }
}

#[cfg(test)]
mod tests {
    use super::{TLS_SIZES, label};

    #[test]
    fn sizes_are_sorted_and_unique() {
        let mut sorted = TLS_SIZES.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(&sorted[..], TLS_SIZES);
    }

    #[test]
    fn labels_are_readable() {
        assert_eq!(label(0), "0B");
        assert_eq!(label(1350), "1350B");
        assert_eq!(label(1024), "1KiB");
        assert_eq!(label(65536), "64KiB");
    }
}

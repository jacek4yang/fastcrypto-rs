//! Error type shared by every primitive in the workspace.

use core::fmt;

/// Errors returned by the public API.
///
/// The set is deliberately small and every variant is Copy, so that error
/// handling never allocates and never needs to be deferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Error {
    /// An output buffer was too long for the construction (for example an HKDF
    /// output longer than 255 * `HashLen`).
    OutputTooLong {
        /// Number of bytes that were requested.
        requested: usize,
        /// Maximum number of bytes the construction can produce.
        max: usize,
    },
    /// A provided key had a length that the construction cannot accept.
    InvalidKeyLength {
        /// Number of bytes that were provided.
        got: usize,
        /// Number of bytes that are required.
        expected: usize,
    },
}

impl Error {
    /// Short human-readable description of the error.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        match self {
            Self::OutputTooLong { .. } => "output too long for this construction",
            Self::InvalidKeyLength { .. } => "invalid key length",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutputTooLong { requested, max } => write!(
                f,
                "output too long: requested {requested} bytes, maximum is {max} bytes"
            ),
            Self::InvalidKeyLength { got, expected } => {
                write!(
                    f,
                    "invalid key length: got {got} bytes, expected {expected}"
                )
            }
        }
    }
}

// core::error::Error is the same trait that std re-exports, so this impl is
// available in no_std builds as well.
impl core::error::Error for Error {}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::Error;

    #[test]
    fn display_is_actionable() {
        let e = Error::OutputTooLong {
            requested: 9000,
            max: 8160,
        };
        assert_eq!(
            e.to_string(),
            "output too long: requested 9000 bytes, maximum is 8160 bytes"
        );
        assert_eq!(e.message(), "output too long for this construction");
    }
}

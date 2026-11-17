//! Errors. Everything that can go wrong at a party boundary, plus the arithmetic cases the
//! protocol treats as an abort.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A message did not decode: bad length, bad point, non-canonical form.
    Wire(&'static str),
    /// A proof, share check or final pairing check failed.
    Verify(&'static str),
    /// The caller violated the protocol's preconditions.
    Protocol(&'static str),
    /// A value had no inverse, or a discrete logarithm was not in the expected subgroup.
    Arithmetic(&'static str),
    /// A round-`k` message from a party in the quorum is missing.
    Missing(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(reason) => write!(f, "wire error: {reason}"),
            Error::Verify(reason) => write!(f, "verification failed: {reason}"),
            Error::Protocol(reason) => write!(f, "protocol error: {reason}"),
            Error::Arithmetic(reason) => write!(f, "arithmetic error: {reason}"),
            Error::Missing(reason) => write!(f, "missing message: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

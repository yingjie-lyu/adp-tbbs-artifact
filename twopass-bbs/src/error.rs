//! Errors.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A message did not decode.
    Wire(&'static str),
    /// A proof, VRF output or the final pairing check failed.
    Verify(&'static str),
    /// The caller violated a protocol precondition (wrong role, reused `sid`, ...).
    Protocol(&'static str),
    /// A value had no inverse, or a randomness bound was violated.
    Arithmetic(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Wire(reason) => write!(f, "wire error: {reason}"),
            Error::Verify(reason) => write!(f, "verification failed: {reason}"),
            Error::Protocol(reason) => write!(f, "protocol error: {reason}"),
            Error::Arithmetic(reason) => write!(f, "arithmetic error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

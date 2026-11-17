//! Errors.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Wire(&'static str),
    Verify(&'static str),
    Protocol(&'static str),
    Arithmetic(&'static str),
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
            Error::Missing(reason) => write!(f, "missing material: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

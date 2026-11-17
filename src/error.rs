//! Errors surfaced by the threshold layer. Nothing here is a panic: a misbehaving peer
//! must produce an `Err`, never an abort.

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A configuration value is unusable (threshold out of range, empty quorum, ...).
    InvalidParameters(&'static str),
    /// The quorum is smaller than the threshold or contains unknown parties.
    InvalidQuorum,
    /// A round-1 proof failed to verify.
    InvalidProof { from: usize },
    /// The combined denominator `u` is zero, so `A = S^{1/u}` does not exist.
    ZeroDenominator,
    /// The assembled signature does not verify under the group public key.
    InvalidSignature,
    /// A party required by the session has no key material.
    MissingShare(usize),
    /// A pairwise seed with a peer is missing.
    MissingSeed { from: usize, to: usize },
    /// A round-1 message from a quorum member is missing.
    MissingRound1(usize),
    /// A round-2 message from a quorum member is missing.
    MissingRound2(usize),
    /// The message length does not match the setup's message bases.
    WrongMessageLength { expected: usize, actual: usize },
    /// A wire-format message could not be parsed.
    Wire(&'static str),
    /// A message arrived on the wrong channel, round, or session.
    UnexpectedMessage(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidParameters(reason) => write!(f, "invalid parameters: {reason}"),
            Error::InvalidQuorum => write!(f, "invalid quorum"),
            Error::InvalidProof { from } => write!(f, "invalid presigning proof from party {from}"),
            Error::ZeroDenominator => write!(f, "u = 0, cannot invert"),
            Error::InvalidSignature => write!(f, "combined signature does not verify"),
            Error::MissingShare(id) => write!(f, "no key share for party {id}"),
            Error::MissingSeed { from, to } => write!(f, "missing seed between {from} and {to}"),
            Error::MissingRound1(id) => write!(f, "missing round-1 message from party {id}"),
            Error::MissingRound2(id) => write!(f, "missing round-2 message from party {id}"),
            Error::WrongMessageLength { expected, actual } => {
                write!(f, "expected {expected} messages, got {actual}")
            }
            Error::Wire(reason) => write!(f, "malformed wire message: {reason}"),
            Error::UnexpectedMessage(reason) => write!(f, "unexpected message: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

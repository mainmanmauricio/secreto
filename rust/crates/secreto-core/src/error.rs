//! Error type shared by all `secreto-core` modules.
//!
//! Every variant maps onto one of the normative exit codes of `spec/cli.md`
//! via [`Error::exit_code`]. Error messages never contain secret material.

use thiserror::Error;

/// Result alias used throughout the crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors produced while encrypting, decrypting or handling keys.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// Usage error or invalid key / recipient / identity input (exit 1).
    #[error("invalid input: {0}")]
    InvalidKey(&'static str),

    /// I/O failure (exit 2).
    #[error("i/o error: {0}")]
    Io(String),

    /// No matching identity, or wrong passphrase (exit 3).
    #[error("no matching identity or wrong passphrase")]
    NoMatch,

    /// Malformed or unauthenticated ciphertext (exit 4).
    #[error("format error: {0}")]
    Format(&'static str),

    /// Signature missing, invalid, or from the wrong signer (exit 5).
    #[error("signature error: {0}")]
    Signature(&'static str),
}

impl Error {
    /// Normative process exit code for this error (see `spec/cli.md`).
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::InvalidKey(_) => 1,
            Error::Io(_) => 2,
            Error::NoMatch => 3,
            Error::Format(_) => 4,
            Error::Signature(_) => 5,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes() {
        assert_eq!(Error::InvalidKey("x").exit_code(), 1);
        assert_eq!(Error::Io("x".into()).exit_code(), 2);
        assert_eq!(Error::NoMatch.exit_code(), 3);
        assert_eq!(Error::Format("x").exit_code(), 4);
        assert_eq!(Error::Signature("x").exit_code(), 5);
    }
}

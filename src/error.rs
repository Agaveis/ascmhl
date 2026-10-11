//! The crate's own error type. Reading the `ascmhl/` directory, a manifest or
//! a file it names can fail; a hash mismatch is not an error and is reported
//! in the outcome instead.

use std::path::{Path, PathBuf};

/// Errors from reading an `ascmhl/` directory or hashing the files it names.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory could not be read.
    #[error("{path}: {source}")]
    Io {
        /// The path that could not be read.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A request this crate cannot satisfy, such as an algorithm it does not
    /// recompute.
    #[error("{0}")]
    Invalid(String),
}

impl Error {
    pub(crate) fn io_at(path: &Path, source: std::io::Error) -> Self {
        Error::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// `Result` with this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

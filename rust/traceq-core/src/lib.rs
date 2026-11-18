//! Shared validated semantics used by the CLI and capture product. Successful
//! queries must wait for replay to validate the complete END and suffix.
#![forbid(unsafe_code)]
pub mod arm64_memory;
pub mod memory;
pub mod replay;
pub mod wire;

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub message: String,
}
impl Error {
    pub fn trace(message: impl Into<String>) -> Self {
        Self {
            code: "TRACE_ERROR",
            message: message.into(),
        }
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self {
            code: "UNSUPPORTED",
            message: message.into(),
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::trace(if error.kind() == std::io::ErrorKind::UnexpectedEof {
            "truncated execution-state stream".to_string()
        } else {
            error.to_string()
        })
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

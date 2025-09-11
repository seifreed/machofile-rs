use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid magic number: {0:#x}")]
    InvalidMagic(u32),

    #[error("Invalid file format")]
    InvalidFormat,

    #[error("Parse error: {0}")]
    ParseError(String),

    #[error("Unsupported architecture: {0}")]
    UnsupportedArchitecture(String),

    #[error("Invalid offset: {0}")]
    InvalidOffset(usize),

    #[error("Invalid size: {0}")]
    InvalidSize(usize),

    #[error("UTF-8 conversion error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    #[error("String conversion error: {0}")]
    StringError(#[from] std::string::FromUtf8Error),
}

pub type Result<T> = std::result::Result<T, Error>;

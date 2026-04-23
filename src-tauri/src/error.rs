use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CoilSnifferError {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("database error: {0}")]
    Db(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl Serialize for CoilSnifferError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

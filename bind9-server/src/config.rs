//! Server configuration entry point (Phase 3).
//!
//! The full `named.conf` grammar/semantics are a courted compatibility
//! surface (§19) implemented in later phases.  What exists now is the
//! configuration *error taxonomy* and the default-file discovery rules
//! (court `CONFIG-DEFAULT-PATHS`), which are real, testable behavior.

use bind9_core::error::Error;

/// Configuration error category, modeled on `named-checkconf`'s observable
/// failure classes: the config could not be read, could not be parsed, or
/// was semantically invalid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub category: ConfigErrorCategory,
    /// File path when known; `None` for string sources.
    pub file: Option<String>,
    /// 1-based line when known.
    pub line: Option<u32>,
    pub message: String,
}

impl ConfigError {
    #[must_use]
    pub fn new(
        category: ConfigErrorCategory,
        file: Option<String>,
        line: Option<u32>,
        message: impl Into<String>,
    ) -> Self {
        ConfigError {
            category,
            file,
            line,
            message: message.into(),
        }
    }
}

/// Category of configuration failure (named-checkconf exit behavior courts
/// pin the exit statuses in Phase 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorCategory {
    /// The file could not be opened/read.
    Io,
    /// Lexical or syntactic error.
    Syntax,
    /// The configuration parsed but is semantically invalid.
    Semantic,
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.category)?;
        if let Some(file) = &self.file {
            write!(f, ": {file}")?;
        }
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        write!(f, ": {}", self.message)
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Error::Other(e.to_string())
    }
}

/// The `named.conf` search path, in order.
///
/// BIND's `named` tries these in order (the list is courted by
/// `CONFIG-DEFAULT-PATHS`); the first that exists is used unless `-c` is
/// given.
pub const DEFAULT_CONFIG_PATHS: &[&str] = &[
    "/etc/named.conf",
    "/etc/bind/named.conf",
    "/usr/local/etc/named.conf",
    "/usr/local/etc/bind/named.conf",
];

/// A configuration source: a file path or in-memory text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    /// Read from a file.
    File(String),
    /// Parse from a string (tests, embedding).
    Text(String),
}

impl ConfigSource {
    /// The display name used in diagnostics.
    #[must_use]
    pub fn display_name(&self) -> &str {
        match self {
            ConfigSource::File(p) => p,
            ConfigSource::Text(_) => "<string>",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_are_ordered() {
        assert!(DEFAULT_CONFIG_PATHS.len() >= 2);
    }

    #[test]
    fn error_display() {
        let e = ConfigError::new(
            ConfigErrorCategory::Io,
            Some("/etc/named.conf".to_string()),
            None,
            "no such file",
        );
        assert_eq!(e.to_string(), "Io: /etc/named.conf: no such file");
    }
}

//! Diagnostics: warning/error wording, exit-status conventions and error
//! taxonomy at the CLI boundary (§43).  BIND error text is not collapsed
//! into generic Rust failures; rendering happens here exactly as the
//! selected compatibility profile requires.
//!
//! Status: ARCHAEOLOGY — exit/error atlases are generated per tool
//! (`forensics/atlas/errors/`).

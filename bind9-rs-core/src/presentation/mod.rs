//! Masterfile presentation: the `dns_lex`-compatible lexer, then the
//! `dns_master_*`-compatible parser as it lands (§18).

pub mod lexer;

pub use lexer::{Lexer, Position, Token};

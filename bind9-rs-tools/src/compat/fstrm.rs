//! Frame Streams (fstrm) — BIND: DNSTAP transport (§26).
//!
//! Control frames (READY/ACCEPT/START/STOP/FINISH) and data frames;
//! bidirectional and unidirectional operation; partial reads/writes;
//! backpressure; connection closure.  Frame boundaries are preserved
//! byte-for-byte; the control-frame payloads are protobuf-encoded
//! (see [`crate::compat::protobuf_c`]).
//!
//! Four-corner interchange is the courted contract (§38): C produces → C
//! consumes, C produces → Rust consumes, Rust produces → C consumes, Rust
//! produces → Rust consumes — with DNSTAP as the higher-order integration
//! court (§61).
//!
//! Status: ARCHAEOLOGY — C surface archived; implementation is Phase 1 of
//! §64.

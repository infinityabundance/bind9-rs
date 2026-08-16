//! Native Rust conservation modules for the infrastructure BIND's tools
//! depend upon (§3): LMDB, fstrm, libcap, libidn2, libedit, liburcu, libuv,
//! protobuf-c, libmaxminddb, zlib, json-c.
//!
//! These are NOT generic replacements inspired by the originals; they are
//! forensic conservation implementations of the behavior the BIND ecosystem
//! requires (Layer C, §4).  Where BIND observes or relies upon a dependency
//! behavior, preserve it; where existing files/streams encode
//! dependency-specific state, preserve interoperability; where the C API
//! matters to archaeology, model and test it (§36).
//!
//! An underlying Rust library may be used ONLY if forensic courts prove the
//! required compatibility surface — the oracle decides, not architectural
//! preference (§3).
//!
//! Implementation order (§64): Phase 1 fstrm/libcap/libidn2/libmaxminddb/
//! json-c; Phase 5 LMDB; Phase 9 zlib/protobuf-c/libedit; Phase 10 liburcu;
//! Phase 11 libuv.

pub mod fstrm;
pub mod json_c;
pub mod libcap;
pub mod libedit;
pub mod libidn2;
pub mod liburcu;
pub mod libuv;
pub mod lmdb;
pub mod maxminddb;
pub mod protobuf_c;
pub mod zlib;

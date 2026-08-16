# bind9-rs

Native Rust reimplementation of BIND 9 with **forensic residual parity**:
a custodian archive of BIND's observable semantics from 9.0.0 through the
current development tree, where every compatibility claim is backed by
executable differential evidence against pinned real-BIND oracles.

This crate is the public compatibility facade.  The implementation is
split into six first-party crates:

| Crate | Role |
|---|---|
| `bind9-rs` | Public compatibility facade (§4.1) |
| `bind9-rs-core` | DNS semantics and protocol machinery (§4.2) |
| `bind9-rs-server` | The `named` runtime (§4.3) |
| `bind9-rs-tools` | BIND command-line utilities (§4.4) |
| `bind9-rs-forensics` | Courts, residuals, receipts, archaeology, oracle machinery (§4.5) |
| `bind9-rs-platform` | OS-specific behavior and audited unsafe boundaries (§4.6) |

The compatibility target is **observable BIND behavior**, not merely
standards compliance.  A divergence from an RFC is not permission to
silently "correct" BIND; a mismatch with real BIND is a *residual* — raw
evidence, classification, minimization, and a reproducible receipt —
until proven equivalent (spec §13).

See the repository for the forensic courts, receipts, and the
machine-readable behavior atlas:
<https://github.com/infinityabundance/bind9-rs>

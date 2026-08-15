# bind9-rs

**Forensic Residual-Parity Native Rust Reimplementation of BIND 9**

A native Rust implementation of BIND 9 whose compatibility is continuously
demonstrated by executable forensic evidence, whose deviations are
represented as residuals rather than hidden, whose historical archive
explains how BIND behavior evolved from 9.0.0 onward, and whose code captures
the accumulated operational reasoning behind that behavior.

This is not a toy DNS server, not a partial BIND-inspired implementation, not
a wrapper around BIND, and not an FFI façade. The reference BIND
implementation exists only on the oracle/testing side (spec §2).

## Architecture (spec §3)

Exactly six first-party crates:

| Crate | Responsibility |
|---|---|
| `bind9-rs` | Public compatibility façade, version reporting, profiles (§4.1) |
| `bind9-core` | DNS semantics and protocol machinery (§4.2) |
| `bind9-server` | The `named` runtime (§4.3) |
| `bind9-tools` | All command-line utilities (dig, host, ..., dnssec-*) (§4.4) |
| `bind9-forensics` | Courts, residuals, receipts, archaeology, oracle machinery (§4.5) |
| `bind9-platform` | OS-specific behavior and audited unsafe boundaries (§4.6) |

Feature decomposition happens through modules; there are no other first-party
crates.

## Current evidence

| Court | Question | Corpus | Residuals | Receipt |
|---|---|---|---|---|
| `CORE-NAME-TEXT-0001` | `dns_name_fromtext`/`totext`/`towire` | 578 cases | 0 | `forensics/receipts/` |
| `CORE-NAME-WIRE-0001` | `dns_name_fromwire` | 50 cases | 0 | `forensics/receipts/` |

The API coverage ledger (`forensics/archaeology/api-atlas/`) tracks all 5,679
functions of BIND 9.20.26 (Doxygen-derived) against archaeology records,
courts and Rust modules. Statuses follow the §47 taxonomy; nothing is
`PROVEN` without receipts.

## Reproducing

```sh
# Build the workspace (Rust 1.96 stable)
cargo build --workspace
cargo test --workspace

# Bootstrap the oracle (pinned BIND 9.20.26; see forensics/sources/)
scripts/oracle/build-oracle-probes.sh

# Run courts
cargo run -p bind9-forensics --bin bind9-court -- list
cargo run -p bind9-forensics --bin bind9-court -- run CORE-NAME-TEXT-0001

# Coverage ledger
cargo run -p bind9-forensics --bin bind9-api-coverage -- summary

# API atlas regeneration (needs a configured BIND tree)
scripts/archaeology/doxygen-atlas.sh
```

See `docs/` for the architecture, the parity ledger, the unknowns ledger and
the security lineage atlas.

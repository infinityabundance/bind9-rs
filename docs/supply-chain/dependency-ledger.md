# Dependency Ledger

Dependency policy (spec §54): every significant dependency requires
justification.  Prefer Rust-native dependencies where mature and appropriate.
Avoid dependencies merely to save fifty lines.  For each material dependency
record: purpose, maintenance state, license, unsafe use, transitive risk,
security history where relevant, alternatives considered.

Supply-chain state is part of the evidence pack; release CI runs
`cargo audit` / `cargo deny` / `cargo vet` (spec §54, §72).

## Workspace dependencies (as of the initial publish, 0.1.0)

| Dependency | Version | Consumed by | Purpose | Unsafe use | Alternatives considered |
|---|---|---|---|---|---|
| `getrandom` | 0.2 | `bind9-rs-platform` | Audited OS CSPRNG for entropy (§4.6). | Yes (platform backends), isolated in the crate dedicated to unsafe boundaries. | `/dev/urandom` file reads (fragile across platforms), bespoke entropy (forbidden). |
| `serde` | 1 | `bind9-rs-forensics` | Machine-readable archive schemas (§70): courts, residuals, receipts, atlas. | No. | Manual TOML/JSON code (rejected: error-prone, no derive). |
| `serde_json` | 1 | `bind9-rs-forensics` | JSON evidence files (§45, §46). | No. | — |
| `toml` | 0.8 | `bind9-rs-forensics` | Court manifests (`manifest.toml`, §12). | No. | — |
| `sha2` | 0.10 | `bind9-rs-forensics` | Evidence hashing: receipts, capture digests (§45, §46). | No (RustCrypto pure-Rust). | — |

## First-party crates (spec §3 — exactly six)

| Crate | Role |
|---|---|
| `bind9-rs` | Public compatibility facade (§4.1) |
| `bind9-rs-core` | DNS semantics and protocol machinery (§4.2); zero external dependencies |
| `bind9-rs-server` | The `named` runtime (§4.3) |
| `bind9-rs-tools` | BIND command-line utilities (§4.4) |
| `bind9-rs-forensics` | Courts, residuals, receipts, archaeology, oracle machinery (§4.5) |
| `bind9-rs-platform` | OS-specific behavior and audited unsafe boundaries (§4.6) |

## Cryptography note

No cryptographic primitives are implemented bespoke (spec §25).  When DNSSEC
validation/signing lands it will use a heavily reviewed implementation as a
deliberately audited dependency, and this ledger will be updated with the
full justification.

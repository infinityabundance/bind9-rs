//! Time formatting: dig's `when_text` uses a hand-rolled local-date
//! routine with `%Z` from the process timezone (read from `/etc/localtime`
//! where the platform requires) — courted against real dig output
//! (CLI-DIG-*).  Also TTL rendering and the `dns_ttl`/`dns_counter`
//! syntaxes shared with zone tooling.
//!
//! Status: ARCHAEOLOGY — first courted consumer is `tools::dig::output`.

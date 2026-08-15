# Security Lineage Atlas

For each public BIND vulnerability that can be responsibly studied: CVE,
affected releases, subsystem, trigger class, root cause, observable symptom,
upstream fix, the new invariant introduced by the fix, whether Rust's
type/memory model eliminates the class, whether it does NOT, reproduction
availability, regression fixture, corresponding bind9-rs invariant, and court
ID (spec §9).

Never write "Rust makes this secure".  Write: this particular failure class
is prevented by invariant X, while logic/resource/protocol classes remain
independently tested by courts Y and Z.

Populated as the archaeology proceeds.  The mechanical source is the ISC
security advisories list (spec §9 source hierarchy item 11) cross-referenced
against the CHANGES entries and fix commits.

| CVE | Affected | Subsystem | Trigger class | Root cause | Symptom | Fix | New invariant | Rust eliminates? | Rust does NOT eliminate | Reproducer | Fixture | bind9-rs invariant | Court |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| _(pending archaeology)_ | | | | | | | | | | | | | |

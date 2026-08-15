# Unsafe Inventory

Every `unsafe` item in the workspace, with its safety invariant, caller
obligations, platform, test coverage, Miri status, sanitizer status, fuzz
coverage and audit status (spec §55).  Workspace policy: `unsafe_code =
"forbid"` everywhere except `bind9-platform`, the designated boundary crate
(§4.6).

| Location | Reason | Invariant | Caller obligations | Platform | Tests | Miri | Sanitizers | Fuzz | Audit |
|---|---|---|---|---|---|---|---|---|---|
| _(none yet — bind9-platform has no unsafe blocks at this time; `#![allow(unsafe_code)]` is the crate's declaration of intent, not a license to add unsafe casually)_ | | | | | | | | | |

Policy: any new `unsafe` must be isolated, justified, documented with its
safety invariant, tested, located at an intentional boundary, audited, and
kept out of protocol/business logic.

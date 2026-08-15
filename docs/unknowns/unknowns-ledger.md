# Unknowns Ledger

World-class engineering includes explicit ignorance (spec §48).  An entry is
resolved by evidence, never by assumption.  Every "UNKNOWN" status in the
parity ledger and coverage matrix traces to an entry here or to a court that
has not yet been built.

| ID | Question | Evidence searched | Versions inspected | Experiments attempted | Current hypothesis | Confidence | What would resolve it |
|---|---|---|---|---|---|---|---|
| UNKNOWN-0001 | When did BIND change `\DDD` escapes in `dns_name_fromtext` from octal to decimal? | 9.20.26 source (decimal); no older trees yet | 9.20.26 only | none yet | The change landed in some 9.16/9.18-era release | likely | Download 9.11/9.16/9.18 trees; run the CORE-NAME-TEXT court against each; record the transition in the version-delta database |
| UNKNOWN-0002 | Does BIND's masterfile lexer accept `\DDD` escapes inside quoted strings the same way as unquoted (decimal, 3 digits)? | lex.c (raw tokens), rdata.c commatxt (decimal) | 9.20.26 | none yet | Yes, via commatxt_fromtext | likely | named-checkzone differential court with quoted-string corpora |
| UNKNOWN-0003 | What is the exact `named` response behavior for queries with qdcount=0 or qdcount>1 (FORMERR vs NOTIMP)? | message.c parse rules | 9.20.26 | none yet | FORMERR | likely | Live named + dig court (network loopback) |
| UNKNOWN-0004 | Historical BIND name compression table behavior (hash collisions affecting output bytes) | none | — | none | Hash-dependent output differs across releases | unknown | Historical-version oracle builds + RENDER-COMPRESS courts |
| UNKNOWN-0005 | Which BIND release moved dig's EDNS defaults (bufsize 1232)? | dig.c DEFAULT_EDNS_BUFSIZE=1232 | 9.20.26 | none | — | unknown | Historical dig + packet-capture courts |

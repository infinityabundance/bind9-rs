# Lore Archive (addendum §29)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## DNS-LORE-0001 — `isc_lex` checks the `;` comment before every state switch, so a comment splits tokens mid-string

The DNSMASTERFILE comment check (`!escaped && c == ';'`, gated on
`comment_ok` and the DNSMASTERFILE comment bit) runs at the top of the
`isc_lex_gettoken` loop — *before* the `lexstate_*` switch — not only in
the start state.  Inside the string state, `a;b c` therefore yields the
token `a` (the `;` is never appended; the whole comment is consumed to the
newline) and the resuming newline is re-processed by the saved state as a
delimiter.  An *escaped* `;` (`a\;b`) survives: the string state consumed
the backslash, the escape flag suppresses the comment check, and the `;` is
appended raw.  The Rust lexer mirrors this with the comment check inside
`string_continue`/`number_token` (the number state can never be escaped, so
`42;x` is `NUMBER 42` followed by a comment, never `42;x`).  Court:
ISC-LEX-0001.

## DNS-LORE-0002 — newlines inside `(...)` are whitespace, but still delimit tokens

While `paren_count > 0` (DNSMULTILINE) BIND clears `IWSEOL` from the
options, so the start state emits no EOL token for `\n` — it is skipped like
a space.  The *string and number states are unaffected*: `\n` is still a
token delimiter there (`a\nb` inside parens is two tokens), and the closing
`)` restores the EOL option.  A group left open at EOF is
`ISC_R_UNBALANCED` with `paren_count` reset.  Court: ISC-LEX-0001.

## DNS-LORE-0003 — the string state re-processes its entry character, so a leading backslash sets the escape flag

The start state's fallback is `state = lexstate_string; goto no_read;` —
the character that triggered the transition is *not* consumed.  The string
state therefore applies its escape tracking to the first character too:
`\"` at EOF is the single token `\"` (the `"` is not a delimiter because
the escape flag is set), and only a *trailing* backslash at EOF is
`ISC_R_UNEXPECTEDEND`.  A backslash at end-of-line is not an error: `a\` +
`\n` is the token `a\` followed by EOL.  The number→string junk fallback is
different: BIND's fall-through appends the junk byte without touching the
escape state (`42\ x` is the token `42\`).  Court: ISC-LEX-0001.

## DNS-LORE-0004 — numeric overflow in a lexer number is `ISC_R_RANGE`, never a string fallback

`isc_parse_uint32` returns `ISC_R_BADNUMBER` only for a leading
non-alphanumeric or trailing junk — both unreachable from the number state,
which has already accumulated a pure digit run.  Overflow therefore reaches
the `else` branch and `isc_lex_gettoken` returns `ISC_R_RANGE` ("out of
range"), aborting the caller's token loop; the digit run is *not* handed
back as a string.  `4294967295` is `NUMBER 4294967295`, `4294967296` is an
error.  Court: ISC-LEX-0001.

## DNS-LORE-0005 — a NUL inside a quoted string is data, and the probe's `printf` truncates the capture

The specials table (NUL, `(`, `)`, `"`) only applies outside quoted
strings: the qstring state sets `no_comments` and never consults
`lex->specials`, so `"a\0b"` is one three-byte QSTRING.  Outside quotes, NUL
is a SPECIAL and terminates the preceding token.  The oracle prints token
text with `printf("%.*s")`, which stops at the first NUL byte — so a
QSTRING containing NUL appears truncated in the capture even though the
token is intact; the Rust probe reproduces the truncation, not the token
length.  Court: ISC-LEX-0001.

## DNS-LORE-0006 — quoted-string escapes are unconditional; `\"` overwrites the backslash

The qstring state tracks the escape flag without consulting the
`ISC_LEXOPT_ESCAPE` option (unlike the string state): `\` always escapes
the next character, and a closing `"` preceded by an odd backslash run is
*not* a terminator — BIND overwrites the preceding backslash with the quote
(the `prev` pointer dance), yielding `"` inside the QSTRING bytes.  A
newline inside a quoted string is `ISC_R_UNBALANCEDQUOTES` (the newline is
pushed back) unless `ISC_LEXOPT_QSTRINGMULTILINE`, which the courts never
set.  Court: ISC-LEX-0001.

## DNS-LORE-0007 — `getmastertoken` has no NUMBER or QSTRING options, so digits and quotes are just strings or errors

`isc_lex_getmastertoken(expect=STRING, eol=true)` runs `isc_lex_gettoken`
with only `EOL|EOF|DNSMULTILINE|ESCAPE`.  Digit runs are therefore STRING
tokens with their raw bytes — this is why `\# 01020304` in the rdata layer
must keep the leading zero, and why the masterfile view has no NUMBER
token.  A `"` is a SPECIAL, which fails the type check and becomes
`ISC_R_UNEXPECTEDTOKEN` ("unexpected token") after an `isc_lex_ungettoken`;
EOL and EOF tokens are accepted (eol=true), so `MASTER EOL` is a normal
result.  Court: ISC-LEX-0001.

## DNS-LORE-0008 — RESERVED11..15 are TOTEXTONLY rcode table entries

`dns_rcode_totext` maps rcodes 11..15 to RESERVED11..RESERVED15, but the
fromtext table has no entries for them — `dns_rcode_fromtext("RESERVED12")`
fails while `totext(12)` succeeds, and `maybe_numeric` (the strtoul fallback
for unrecognized text) still accepts `"12"`.  The dig CLI therefore prints
`RESERVED12` for raw rcode 12 — the numeric `?12` prefix is reserved for
rcodes *outside* the table entirely.  Court: TABLES-0001.

## DNS-LORE-0009 — type 0 and type 65533 have name asymmetries in the tables

`dns_rdatatype_totext(0)` returns `TYPE0` (0 has no mnemonic), while
`dns_rdatatype_totext(65533)` returns `KEYDATA` (it gained a mnemonic in
the DNSSEC-key era); the fromtext side accepts `KEYDATA` but `type-fromtext`
for unknown numerics goes through the strtoul path with the TYPE/CLASS
prefix rules.  The ismeta/issingleton predicates come from
`RDATATYPE_ATTRIBUTE_SW`, not the name table.  Court: TABLES-0001.

## DNS-LORE-0010 — message ext-rcode merges with the header rcode at the OPT

`dns_message_parse` folds the OPT's extended rcode into the message rcode
after the header: BADVERS is header rcode 0 + ext 1, BADCOOKIE is header 7
+ ext 1, and ext 0x12 yields 0x120 — the rcode and OPT TTL are the two
places the 12-bit extended rcode lives, and render must re-split it when
writing the OPT back out.  Court: WIRE-MESSAGE-0001.

## DNS-LORE-0011 — best-effort parse recovers per record, merging rrsets and minimizing TTL

In best-effort mode a malformed record aborts only that record
(DNS_R_RECOVERABLE at the end); the rrsets merge by (name, type, covers)
with the *minimum* TTL across the set — BIND's rdata_merge.  Duplicate
question entries are appended as separate question rrsets, and a
question-only type in the answer section is a recoverable error rather than
a hard FORMERR.  Court: WIRE-MESSAGE-0001.

## DNS-LORE-0012 — TSIG must be the last record and SIG(0) has its own placement rule

A TSIG in the additional section is only accepted as the final record (the
ar count must include it, and a record after the TSIG is `DNS_R_BADTSIG`);
a root-name TSIG with a zero-length name is the canonical form.  SIG(0)
records are likewise placement-checked (`DNS_R_BADSIG0`).  RRSIG records
carry `covers` — the covered type from the RDATA — which participates in
rrset identity and render ordering.  Court: WIRE-MESSAGE-0001.

## DNS-LORE-0013 — NSEC3 owner names must be base32hex, and the check is a hard error

An NSEC3 record whose owner's first label is not valid base32hex (the
test's lowercase form) fails with `DNS_R_BADOWNERNAME` even under
best-effort — the owner-name check is not part of the per-record recovery,
and the typemap window/length fields are validated independently
(FORMERR on a truncated salt or typemap).  Court: WIRE-MESSAGE-0001.

## DNS-LORE-0014 — dynamic-update class rules are meta, not data

In update messages the class is the opcode's payload: `NONE` classes in the
update section are parsed as-is (a `NONE A` update is valid), class-agnostic
rdata like DS is gated by type rather than class, and a *query* opcode with
a NONE-class question is a recoverable class mismatch — the parser
distinguishes update semantics by opcode before the section class rules
apply.  Court: WIRE-MESSAGE-0001.

## DNS-LORE-0015 — the compressor table is shared across a render and survives in odd states

`dns_compress_name` writes every rendered name's suffixes into the table so
later names with the same suffix reuse the earliest offset — but the table
is only consulted for names whose traversal reaches a registered suffix;
with compression disabled or not permitted (RFC 3597) the full name is
written while the table is still populated for later names, and with
DNS_COMPRESS_CASE the suffix match is case-sensitive while the default
match is case-insensitive.  The LARGE flag selects the 1024-slot table
(AXFR/update semantics) instead of the 64-slot one.  Courts:
RENDER-COMPRESS-0001..0005.

## DNS-LORE-0016 — the rdata framework's `\#` generic form skips hex reads for a declared zero length

`unknown_fromtext` reads hex tokens only when the declared length is
nonzero (`if (token.value.as_ulong != 0U)`); after `\# 0` a following token
is left in the stream for the EXTRATOKEN check.  Overflow of the declared
length is ISC_R_RANGE, odd hex digits are DNS_R_BADHEX, a full byte beyond
the declaration hits the exactly-sized allocation (DNS_R_NOSPACE), and too
few octets is ISC_R_UNEXPECTEDEND.  The text form renders uppercase hex
(isc_hex_totext's alphabet) with no trailing space for empty data.  Court:
WIRE-RDATA-0001.

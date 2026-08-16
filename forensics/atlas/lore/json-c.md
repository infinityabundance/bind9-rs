# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## JSON-LORE-0001 — a parsed `null` is a NULL object pointer, not an object

json-c's tokener produces `null` by calling `json_object_new_null()`, which
returns NULL (json_object.c: `return NULL;`).  `json_tokener_parse_ex`
therefore returns a NULL pointer *with* `json_tokener_success` for the input
`null`.  Applications distinguish "parse failed" from "parsed null" by
checking the tokener error, not the pointer.  The C probe renders this as
`NULL err=0 success`; the Rust `json_tokener_parse_verbose` returns
`Some(JsonValue::Null)` and the probe prints the same line.  Nested `null`
values inside arrays/objects are real entries and serialize as `null`.
Court: JSON-0001.

## JSON-LORE-0002 — COLOR flag: booleans and null are magenta, keys blue, strings green

`JSON_C_TO_STRING_COLOR` in json-c 0.19 wraps `true`/`false` and `null` in
`\e[0;35m` (magenta), object keys in `\e[0;34m` (blue), and string values in
`\e[0;32m` (green), all reset with `\e[0m`.  Numbers (int/uint/double) get
no color at all.  The serializer's color decisions are per-token inside the
array/object loops, so a nested boolean is colored exactly like a top-level
one.  The Rust serializer originally colored only strings, keys and nested
nulls; the court caught top-level booleans/nulls and nested booleans.
Court: JSON-0001 (residual JSON-0001-COLOR-* class, now 0).

## JSON-LORE-0003 — C hex escapes eat all hex digits; probe literals must match byte-for-byte

In C, `"\x01b"` is the single byte 0x1b (the escape consumes `01b`); in
Rust, `\x01` is exactly two digits and `b` stays a literal.  Writing the
same *source* in both languages therefore feeds different bytes to the two
libraries.  The probes must pass identical input: the C side splits the
literal (`"a\x01" "b\x1f" "c"` → a, 0x01, b, 0x1f, c) while the Rust side
writes `b"a\x01b\x1fc"` → the same five bytes.  Also: a trailing comma in a
C *function call* argument list is a syntax error ("expected expression
before ')'"), unlike trailing commas in initializers.  Court: JSON-0001.

## JSON-LORE-0004 — the tokener's EOF normalization happens at the NUL terminator

`json_tokener_parse_ex` with `len=-1` runs past the input into the trailing
NUL.  The `out:` block in json_tokener.c treats "stopped because the next
byte is 0" as end-of-data: any state that is not `Finish` (and not a
*successful* scalar) becomes `json_tokener_error_parse_eof`.  This is why
`nul` → err=3 (EOF) while `nuX` → err=5 (null expected): the former reaches
the NUL mid-token, the latter dies on the bad byte first.  The Rust port
appends a sentinel 0x00, `peek` returns 0 past the end, and the same rule
fires.  Court: JSON-0001.

## JSON-LORE-0005 — `%.17g` and the NOZERO trim scan the exponent digits too

`json_object_new_double` serializes with the glibc `%.17g` conversion:
`%e` for |x| < 1e-4 or ≥ 1e17, `%f` otherwise, then a `.0` is appended when
the result has no `.`/`e`.  `JSON_C_TO_STRING_NOZERO` then trims trailing
zeros from the *whole* buffer including the exponent: `1e300` → `%.17g`
gives `1.0000000000000001e+300`; NOZERO turns it into
`1.0000000000000001e+3`.  (Exponent zeros are significant to the value, so
the trimming is a quirk, not a fix.)  The Rust `format_double` implements
the same %e/%f selection, `.0` append, and whole-buffer NOZERO trim.
Court: JSON-0001.

## JSON-LORE-0006 — JSON_C_VERSION_NUM for 0.19 is 4864 (0x001300)

`json_c_version_num` (0.19) = 0x001300 = 4864: the version macro encodes
0xMMmmpp where mm is the *minor* in the two-digit scheme (0.19 → 0x13), so
the number prints as `4864`, not `19`.  The oracle prints
`0.19 4864`; the Rust module returns the same constants.  Court: JSON-0001.

## JSON-LORE-0007 — embedded NULs survive in string values, keys truncate at NUL

Parsed string values keep their byte length (embedded 0x00 bytes survive),
because the tokener tracks an explicit length.  Object keys go through
`strdup`, so a key containing 0x00 is truncated at the first NUL.  The
serializer escapes control bytes as `\u00XX` (lowercase hex).  Both
behaviors are conserved by the Rust value model (`String(Vec<u8>)` for
values, `Vec<u8>` keys truncated on parse).  Court: JSON-0001 (strings with
`\u0000`, control-char programmatic object).

## JSON-LORE-0008 — json-c objects share one printbuf: serialize-then-print, one at a time

`json_object_to_json_string*` writes into a single cached `printbuf` inside
the object, so two serializations in one `printf` corrupt each other.  The
probes therefore print each flag's serialization immediately and never
nest two `to_string` calls in one format line.  This is an application-visible
lifetime quirk of the C API (the Rust mirror has no shared buffer, but the
probes keep the same print discipline so the *output* is identical).
Court: JSON-0001.

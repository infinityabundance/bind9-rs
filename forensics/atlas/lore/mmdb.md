# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## MMDB-LORE-0001 — libmaxminddb mmaps the file; the Rust module reads it

The C `MMDB_open` maps the whole database with `mmap(PROT_READ, MAP_SHARED)`
and looks up through the mapping.  `compat/maxminddb` reads the whole file
into a `Vec` at open.  The observable lookup/error contract is identical;
the differences (RSS for huge files, SIGBUS on mid-life truncation) are not
part of the library's API contract and are deliberately not conserved.
Court: MMDB-0001.

## MMDB-LORE-0002 — `data_size` for numeric entry data is uninitialized memory in C

`maxminddb.c` `lookup_path_in_map`/`lookup_path_in_array` use plain
uninitialized stack locals (`MMDB_entry_data_s key, value;`).  `decode_one`
sets `data_size` only for strings, bytes, map/array headers, booleans and
pointers (the header says it is "only valid for strings, utf8_strings or
binary data").  For uint16/32/64/128, int32, float and double the reported
`data_size` is therefore stack residue: in the MMDB-0001 oracle run it
happened to be 4 (a leftover pointer payload size), but it is not a defined
surface.  The probes render `-` for those types; the Rust module returns 0.

## MMDB-LORE-0003 — glibc `AI_NUMERICHOST` accepts IPv4 shorthand but requires full consumption

`getaddrinfo(AI_NUMERICHOST)` tries strict `inet_pton` for v4, then v6
(zone-aware), then falls back to `inet_aton`-style shorthand (octal/hex
prefixes, 1-3 part forms).  Unlike raw `inet_aton`, the getaddrinfo path
rejects trailing whitespace/garbage (`inet_aton("1.2.3.4 ")` succeeds;
`getaddrinfo("1.2.3.4 ")` returns EAI_NONAME) and rejects signs, leading
whitespace and octal digits 8/9 ("09").  Pinned empirically against glibc
2.36 (Debian 12) in court MMDB-0001; the Rust `parse_inet_aton_exact`
implements the observed contract.

## MMDB-LORE-0004 — IPv6 zone validation in glibc numeric lookups

For `addr%zone`, glibc accepts a fully-decimal zone (any value that parses
with strtoul without ERANGE, including 0), and any other zone must name an
existing interface (`if_nametoindex`); an empty zone is rejected.  The Rust
module mirrors this with `/sys/class/net/<name>/ifindex`.  The zone never
affects the address bytes (scoped lookups still use the numeric part).

## MMDB-LORE-0005 — `mmdblookup` metadata dump formats the build epoch with gmtime

`dump_meta` renders `Build epoch: <epoch> (<%F %T UTC>)` via
`gmtime`/`strftime`.  The Rust mirror uses the civil-from-days conversion
(Howard Hinnant's algorithm), which is bit-identical to glibc's gmtime for
the representable range; "out of range" mirrors `tm == NULL`.

## MMDB-LORE-0006 — the dump formatter's indentation quirks are conserved

`MMDB_dump_entry_data_list`: map keys print at `indent + 2` and values at
`indent + 4` (the C bumps `indent` before the key loop); array elements
print at `indent + 2` relative to the bracket line; the map key line ends
with `": "` (trailing space); array elements are *not* aligned with their
keys.  `print_indentation` clamps to [0, 1023] spaces.  All of this is
observable output and is reproduced byte-for-byte.

## MMDB-LORE-0007 — an empty file opens with MMDB_IO_ERROR, not INVALID_METADATA

`mmap(NULL, 0, ...)` fails with EINVAL on Linux, which `map_file` reports
as MMDB_IO_ERROR (errno is not ENOMEM).  A zero-length file therefore
surfaces as IO_ERROR before the metadata search ever runs.  The Rust module
reproduces this.

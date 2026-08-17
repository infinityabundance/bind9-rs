# Lore Archive (addendum §10)

Knowledge conventional documentation loses, kept with the code that depends
on it.  Each entry records *why* an observed behavior exists.

## PBC-LORE-0001 — int32 negatives are 10-byte two's-complement varints

`int32_pack` encodes a negative `int32` as the full 64-bit two's-complement
value: bytes `0..4` carry the sign-extended low bits, byte 4 is `(v>>28)|0xf0`,
bytes 5..8 are `0xff` and byte 9 is `0x01` — 10 bytes, exactly the encoding of
`-1` as `uint64`.  `int32_size(v)` returns 10 for every negative value, and
the `int32` field type (and `enum`, which packs through `int32_pack`) never
uses the 5-byte form for negative values.  Getting this wrong shifts every
field's size and every length prefix.  Court: PBC-0001.

## PBC-LORE-0002 — a NULL string/message packs as a single 0x00 byte

`string_pack(NULL)` writes just `0x00` (a zero length prefix, no payload),
and `prefixed_message_pack(NULL)` does the same for messages — so a *required*
string or message member with a NULL pointer serializes as `tag 0x00`, an
empty-but-present field.  This is why "missing required" must be detected by
the required-field bitmap on unpack, not by the absence of a field on the
wire: a NULL required field *is* on the wire.  Court: PBC-0001.

## PBC-LORE-0003 — the packed-repeated length is a two-pass memmove

Packing a `[packed=true]` repeated field writes the payload at the length
position and *then* fixes up the length varint: the C computes
`length_size_min = uint32_size(get_type_min_size(type) * count)` and reserves
that many bytes, then `memmove`s the payload one byte right when the actual
payload length needs a longer varint (the 1→2 byte transition at 128).  The
observable result is just tag + exact length + payload, but the PBC-0001
corpus deliberately crosses the 128-byte boundary so both implementations
exercise the path.  The same two-pass trick appears in
`prefixed_message_pack` (the sub-message length prefix).  Court: PBC-0001.

## PBC-LORE-0004 — merge_messages: concat, last-wins, zero-copy, and the required blind spot

When an optional message field appears twice, the second instance is merged
into the first and *the second instance is kept*: repeated fields
concatenate, singular scalars from the earlier instance fill slots the later
instance left unset (zero-copied, and the earlier slot is zeroed so freeing
the earlier message can't free shared data), embedded messages merge
recursively — and REQUIRED fields are not merged at all, so the later
instance's value simply wins.  Top-level scalar fields (non-message) never
merge; they are last-wins by plain overwrite.  Court: PBC-0001.

## PBC-LORE-0005 — unknown fields round-trip byte-exactly

Unknown tags are captured with their exact tag, wire type and payload and
re-emitted verbatim on pack — the forward-compatibility contract.  The
payload of an unknown length-prefixed field is `do_alloc(len)`, which for an
*empty* unknown field is `malloc(0)`; on glibc that succeeds (non-NULL), so
the unpack succeeds and the empty field round-trips.  Court: PBC-0001.

## PBC-LORE-0006 — a required field with a default is not required

The unpack required-check is `default_value == NULL && !bitmap_set` — a
proto2 `required` field that declares a default is *exempt* from the
presence check (it is always considered present via its default).  This is
why `DefaultRequiredValues` unpacks successfully from an empty wire with all
defaults applied, while `TestMessRequiredString` (no default) fails.  Court:
PBC-0001.

## PBC-LORE-0007 — presence is a pointer comparison, not a value comparison

Optional strings and messages have no `has` flag; presence is "member pointer
!= NULL && != default_value", and the C compares *pointers*.  Optional
*bytes* do carry a `has` quantifier (the generated `has_*_bytes` fields), and
their pack is gated on `has` alone — a bytes field whose data happens to
equal its default is still packed when `has` is set.  The PBC-0001 corpus
never sets a field to its default content, so the Rust's value comparison is
observationally identical to the C's pointer comparison there.  Court:
PBC-0001.

## PBC-LORE-0008 — proto3 unlabeled fields skip zeroish values; enum defaults are the first enumerator

Unlabeled (proto3) fields pack only when non-zeroish: `0` numbers, empty
strings, `len==0` bytes (the zeroish check reads the *length* word of the
bytes member — so a zero-length bytes with a non-NULL data pointer is still
zeroish), NULL messages.  In proto2, an enum field with no declared default
defaults to the *first enumerator* (the generated INIT embeds it), which the
descriptor's `default_value` does NOT carry — only the generated init
function does.  Court: PBC-0001.

## PBC-LORE-0009 — the scanned-member slabs and the observable allocation sizes

Unpack first scans the whole wire into `ScannedMember` records: 16 fit on the
stack, then heap slabs of `sizeof(ScannedMember) << (slab + 4)` — 32 bytes
each on x86-64, so the 17th member triggers a 1024-byte allocation.  A
counting allocator observes every `do_alloc`/`do_free` of the C, and the
PBC-0001 corpus checks the exact sequence and sizes: the message struct
(232), the slab (1024), strings (len+1), bytes, nested message structs,
repeated arrays, the heap required-bitmap (17 bytes for 129 fields), and the
unknown-field array.  Court: PBC-0001.

## PBC-LORE-0010 — descriptor lookups are binary searches over compressed ranges

`get_field`/`get_field_by_name`/`get_value`/`get_value_by_name`/
`get_method_by_name` all binary-search: message fields by tag over
`number_ranges` (compressed consecutive runs with a trailing dummy element
whose `orig_index` is the field count), by name over the name-sorted index
array, enum values by number over `value_ranges` (same compression, with
negative start values), by name over the name-sorted `values_by_name` (which
keeps aliases), and service methods by name.  The `int_range_lookup` span is
`start_value + (next.orig_index - cur.orig_index)`, and a tag just past the
last run's end resolves to the dummy and returns -1.  Court: PBC-0001.

## PBC-LORE-0011 — enum aliases dedupe by number, but not by name

The generated `values_by_number` array keeps only the FIRST alias of each
numeric value (VALUE_A=42 wins over VALUE_B/VALUE_C), while
`values_by_name` keeps every name (aliases resolve to the same first value).
`get_value(42)` therefore returns VALUE_A and `get_value_by_name("VALUE_B")`
also returns VALUE_A.  Court: PBC-0001.

## PBC-LORE-0012 — an empty wire is a valid message

`unpack(desc, len=0, data=NULL)` succeeds: the scan loop is skipped, the init
(defaults) runs, and the message is valid — unless a required field without a
default is missing, which the bitmap check rejects.  `EmptyMess` unpacks
from nothing; `free_unpacked(NULL)` is a no-op.  Court: PBC-0001.

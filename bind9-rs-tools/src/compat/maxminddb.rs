//! `compat::maxminddb` — libmaxminddb 1.13.3 conservation (§33).
//!
//! A native-Rust custodian implementation of the MaxMind DB format
//! interpretation: metadata, search tree, data pointer traversal, the full
//! data-type decoder, path lookup (with `strtol` array-index semantics), the
//! entry-data-list machinery, the byte-exact dump formatter, and the exact
//! error taxonomy of `maxminddb.c` 1.13.3.
//!
//! Every function maps to the pinned C source:
//! `bind9-rs-tools/forensics/sources/libmaxminddb-1.13.3/`
//! (`src/maxminddb.c`, `src/data-pool.c`, `src/maxminddb-compat-util.h`).
//! Courts: MMDB-* (four-corner: C libmaxminddb ↔ this module, same pinned
//! test databases, byte-exact stdout).
//!
//! The implementation is safe Rust; file access goes through the platform
//! boundary.  The C mmaps the file; we read the whole file (the lookup and
//! error semantics are identical; memory mapping is an internal detail of
//! the C that has no observable API consequence other than RSS and
//! SIGBUS-on-truncation, which are not part of the library contract — see
//! lore entry MMDB-LORE-0001).

use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Constants (maxminddb.h, MMDB-*)
// ---------------------------------------------------------------------------

pub const MMDB_DATA_TYPE_EXTENDED: u32 = 0;
pub const MMDB_DATA_TYPE_POINTER: u32 = 1;
pub const MMDB_DATA_TYPE_UTF8_STRING: u32 = 2;
pub const MMDB_DATA_TYPE_DOUBLE: u32 = 3;
pub const MMDB_DATA_TYPE_BYTES: u32 = 4;
pub const MMDB_DATA_TYPE_UINT16: u32 = 5;
pub const MMDB_DATA_TYPE_UINT32: u32 = 6;
pub const MMDB_DATA_TYPE_MAP: u32 = 7;
pub const MMDB_DATA_TYPE_INT32: u32 = 8;
pub const MMDB_DATA_TYPE_UINT64: u32 = 9;
pub const MMDB_DATA_TYPE_UINT128: u32 = 10;
pub const MMDB_DATA_TYPE_ARRAY: u32 = 11;
pub const MMDB_DATA_TYPE_CONTAINER: u32 = 12;
pub const MMDB_DATA_TYPE_END_MARKER: u32 = 13;
pub const MMDB_DATA_TYPE_BOOLEAN: u32 = 14;
pub const MMDB_DATA_TYPE_FLOAT: u32 = 15;

pub const MMDB_RECORD_TYPE_SEARCH_NODE: u8 = 0;
pub const MMDB_RECORD_TYPE_EMPTY: u8 = 1;
pub const MMDB_RECORD_TYPE_DATA: u8 = 2;
pub const MMDB_RECORD_TYPE_INVALID: u8 = 3;

pub const MMDB_MODE_MMAP: u32 = 1;
pub const MMDB_MODE_MASK: u32 = 7;

/// maxminddb.c `MMDB_DATA_SECTION_SEPARATOR` — the 16-byte gap between the
/// search tree and the data section.
pub const MMDB_DATA_SECTION_SEPARATOR: u32 = 16;

/// maxminddb.c `MAXIMUM_DATA_STRUCTURE_DEPTH` (512).
pub const MAXIMUM_DATA_STRUCTURE_DEPTH: u32 = 512;

/// maxminddb.c `METADATA_BLOCK_MAX_SIZE` — 128kb; the metadata marker is
/// searched only within the final block of this size.
pub const METADATA_BLOCK_MAX_SIZE: usize = 131_072;

/// maxminddb.c `METADATA_MARKER`.
pub const METADATA_MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";

pub const MMDB_SUCCESS: i32 = 0;
pub const MMDB_FILE_OPEN_ERROR: i32 = 1;
pub const MMDB_CORRUPT_SEARCH_TREE_ERROR: i32 = 2;
pub const MMDB_INVALID_METADATA_ERROR: i32 = 3;
pub const MMDB_IO_ERROR: i32 = 4;
pub const MMDB_OUT_OF_MEMORY_ERROR: i32 = 5;
pub const MMDB_UNKNOWN_DATABASE_FORMAT_ERROR: i32 = 6;
pub const MMDB_INVALID_DATA_ERROR: i32 = 7;
pub const MMDB_INVALID_LOOKUP_PATH_ERROR: i32 = 8;
pub const MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR: i32 = 9;
pub const MMDB_INVALID_NODE_NUMBER_ERROR: i32 = 10;
pub const MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR: i32 = 11;

/// `MMDB_strerror(error_code)` — the exact C strings (maxminddb.c).
#[must_use]
pub fn mmdb_strerror(error_code: i32) -> &'static str {
    match error_code {
        MMDB_SUCCESS => "Success (not an error)",
        MMDB_FILE_OPEN_ERROR => "Error opening the specified MaxMind DB file",
        MMDB_CORRUPT_SEARCH_TREE_ERROR => "The MaxMind DB file's search tree is corrupt",
        MMDB_INVALID_METADATA_ERROR => "The MaxMind DB file contains invalid metadata",
        MMDB_IO_ERROR => "An attempt to read data from the MaxMind DB file failed",
        MMDB_OUT_OF_MEMORY_ERROR => "A memory allocation call failed",
        MMDB_UNKNOWN_DATABASE_FORMAT_ERROR => {
            "The MaxMind DB file is in a format this library can't handle \
             (unknown record size or binary format version)"
        }
        MMDB_INVALID_DATA_ERROR => {
            "The MaxMind DB file's data section contains bad data \
             (unknown data type or corrupt data)"
        }
        MMDB_INVALID_LOOKUP_PATH_ERROR => {
            "The lookup path contained an invalid value (like a negative \
             integer for an array index)"
        }
        MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR => {
            "The lookup path does not match the data (key that doesn't exist, \
             array index bigger than the array, expected array or map where \
             none exists)"
        }
        MMDB_INVALID_NODE_NUMBER_ERROR => {
            "The MMDB_read_node function was called with a node number that \
             does not exist in the search tree"
        }
        MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR => {
            "You attempted to look up an IPv6 address in an IPv4-only database"
        }
        _ => "Unknown error code",
    }
}

/// `MMDB_lib_version()` — PACKAGE_VERSION of the pinned release.
#[must_use]
pub const fn mmdb_lib_version() -> &'static str {
    "1.13.3"
}

// ---------------------------------------------------------------------------
// Entry data (maxminddb.h MMDB_entry_data_s)
// ---------------------------------------------------------------------------

/// The union payload of `MMDB_entry_data_s`.  Strings and bytes are owned
/// copies of the referenced section bytes (the C pointers into the mapped
/// file; the observable bytes are identical).
#[derive(Clone, Debug, PartialEq)]
pub enum EntryValue {
    Pointer(u32),
    Utf8String(Vec<u8>),
    Double(f64),
    Bytes(Vec<u8>),
    Uint16(u16),
    Uint32(u32),
    Int32(i32),
    Uint64(u64),
    Uint128(u128),
    Boolean(bool),
    Float(f32),
    /// map/array header (value carried by `data_size`/`offset_to_next`)
    Container,
}

/// `MMDB_entry_data_s`.
#[derive(Clone, Debug)]
pub struct EntryData {
    pub has_data: bool,
    /// this entry's offset (the C sets `offset` then `has_data = true`)
    pub offset: u32,
    pub offset_to_next: u32,
    pub data_size: u32,
    pub type_id: u32,
    pub value: EntryValue,
}

impl Default for EntryData {
    fn default() -> Self {
        EntryData {
            has_data: false,
            offset: 0,
            offset_to_next: 0,
            data_size: 0,
            type_id: 0,
            value: EntryValue::Container,
        }
    }
}

/// One node of the entry-data list (`MMDB_entry_data_list_s`).  The C links
/// nodes through a doubling data pool; the observable contract is the ORDER
/// of nodes, which a `Vec` preserves exactly (data-pool.c ordering).
pub type EntryDataList = Vec<EntryData>;

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct Description {
    pub language: String,
    pub description: String,
}

/// `MMDB_metadata_s` — the parsed fields (database_type/languages/
/// descriptions are strndup'd copies in the C, so they are owned Strings
/// here; strndup stops at the first NUL, reproduced by `strndup`).
#[derive(Debug, Clone)]
pub struct Metadata {
    pub node_count: u32,
    pub record_size: u16,
    pub ip_version: u16,
    pub database_type: String,
    pub languages: Vec<String>,
    pub binary_format_major_version: u16,
    pub binary_format_minor_version: u16,
    pub build_epoch: u64,
    pub descriptions: Vec<Description>,
}

// ---------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------

/// `MMDB_s`.  `data_section` and `metadata_section` are byte offsets into
/// `file_content` (the C keeps pointers; offsets are equivalent and make the
/// borrow structure safe).
#[derive(Debug)]
pub struct Mmdb {
    pub flags: u32,
    pub filename: String,
    pub file_size: usize,
    pub file_content: Vec<u8>,
    pub data_section: usize,
    pub data_section_size: u32,
    pub metadata_section: usize,
    pub metadata_section_size: u32,
    pub full_record_byte_size: u16,
    pub depth: u16,
    /// (node_value, netmask) — `MMDB_ipv4_start_node_s`
    pub ipv4_start_node: (u32, u16),
    pub metadata: Metadata,
}

impl Mmdb {
    fn data(&self) -> &[u8] {
        &self.file_content[self.data_section..self.data_section + self.data_section_size as usize]
    }

    fn metadata_data(&self) -> &[u8] {
        &self.file_content
            [self.metadata_section..self.metadata_section + self.metadata_section_size as usize]
    }
}

// ---------------------------------------------------------------------------
// Small integer readers (maxminddb.c get_uint32/24/16/X, get_sintX)
// ---------------------------------------------------------------------------

/// `get_uint32(p)` = p[0]*16777216 + p[1]*65536 + p[2]*256 + p[3] (big-endian).
fn get_uint32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn get_uint24(p: &[u8]) -> u32 {
    (p[0] as u32) * 65536 + (p[1] as u32) * 256 + p[2] as u32
}

fn get_uint16(p: &[u8]) -> u32 {
    (p[0] as u32) * 256 + p[1] as u32
}

fn get_uintx(p: &[u8], length: usize) -> u64 {
    let mut value: u64 = 0;
    for i in 0..length {
        value <<= 8;
        value += p[i] as u64;
    }
    value
}

fn get_sintx(p: &[u8], length: usize) -> i32 {
    get_uintx(p, length) as i32
}

/// `get_ieee754_float(p)`: bytes are big-endian on disk; the C byte-swaps on
/// little-endian hosts.  `f32::from_be_bytes` is the exact equivalent.
fn get_ieee754_float(p: &[u8]) -> f32 {
    f32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

fn get_ieee754_double(p: &[u8]) -> f64 {
    f64::from_be_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
}

// ---------------------------------------------------------------------------
// Metadata discovery (maxminddb.c find_metadata, read_metadata, *)
// ---------------------------------------------------------------------------

/// `find_metadata`: the LAST occurrence of the marker within the final
/// METADATA_BLOCK_MAX_SIZE bytes wins; the metadata section is everything
/// after that marker.  Returns (metadata_offset, metadata_size) or None.
fn find_metadata(file_content: &[u8], file_size: usize) -> Option<(usize, u32)> {
    const MARKER: &[u8] = b"\xab\xcd\xefMaxMind.com";
    let marker_len = MARKER.len();
    let max_size = file_size.min(METADATA_BLOCK_MAX_SIZE);
    let start = file_size - max_size;
    let mut search_area = start;
    let mut size = max_size;
    loop {
        let found = find_bytes(&file_content[search_area..search_area + size], MARKER);
        match found {
            Some(pos) => {
                size -= pos;
                search_area += pos;
                size -= marker_len;
                search_area += marker_len;
            }
            None => break,
        }
    }
    if search_area == start {
        return None;
    }
    Some((search_area, size as u32))
}

/// minimal memmem (FreeBSD-derived, maxminddb-compat-util.h)
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.is_empty() || needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    if needle.len() == 1 {
        return haystack.iter().position(|&b| b == needle[0]);
    }
    let last = haystack.len() - needle.len();
    for cur in 0..=last {
        if haystack[cur] == needle[0] && &haystack[cur..cur + needle.len()] == needle {
            return Some(cur);
        }
    }
    None
}

/// `mmdb_strnlen` + strndup semantics: copy up to `n` bytes, stop at the
/// first NUL.
fn strndup(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn can_multiply(max: u64, m: u64, n: u64) -> bool {
    if m == 0 {
        return false;
    }
    n <= max / m
}

/// `read_metadata` — decode the metadata map through the same decoder used
/// for the data section (the "fake metadata db" trick).
fn read_metadata(mmdb: &mut Mmdb) -> i32 {
    // fake metadata db: data_section = metadata bytes
    let meta = mmdb.metadata_data().to_vec();
    let meta_size = meta.len() as u32;
    let fake = FakeDb {
        data: meta,
        data_size: meta_size,
    };

    // node_count
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["node_count"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT32 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.node_count = match entry.value {
        EntryValue::Uint32(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };
    if mmdb.metadata.node_count == 0 {
        return MMDB_INVALID_METADATA_ERROR;
    }

    // record_size
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["record_size"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT16 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.record_size = match entry.value {
        EntryValue::Uint16(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };
    if mmdb.metadata.record_size == 0 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    if mmdb.metadata.record_size != 24
        && mmdb.metadata.record_size != 28
        && mmdb.metadata.record_size != 32
    {
        return MMDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    }

    // ip_version
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["ip_version"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT16 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.ip_version = match entry.value {
        EntryValue::Uint16(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };
    if mmdb.metadata.ip_version == 0 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    if mmdb.metadata.ip_version != 4 && mmdb.metadata.ip_version != 6 {
        return MMDB_INVALID_METADATA_ERROR;
    }

    // database_type
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["database_type"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UTF8_STRING {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.database_type = match &entry.value {
        EntryValue::Utf8String(b) => strndup(b),
        _ => return MMDB_INVALID_METADATA_ERROR,
    };

    // languages (array of utf8 strings)
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["languages"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_ARRAY {
        return MMDB_INVALID_METADATA_ERROR;
    }
    let mut list = Vec::new();
    let status = get_entry_data_list(&fake, entry.offset, &mut list, 0);
    if status != MMDB_SUCCESS {
        return status;
    }
    let array_size = list[0].data_size as usize;
    let mut names = Vec::with_capacity(array_size);
    let mut idx = 0usize;
    for _ in 0..array_size {
        idx += 1; // member = member->next
        if idx >= list.len() || list[idx].type_id != MMDB_DATA_TYPE_UTF8_STRING {
            return MMDB_INVALID_METADATA_ERROR;
        }
        names.push(strndup(match &list[idx].value {
            EntryValue::Utf8String(b) => b,
            _ => return MMDB_INVALID_METADATA_ERROR,
        }));
    }
    mmdb.metadata.languages = names;

    // binary_format_major_version
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["binary_format_major_version"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT16 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.binary_format_major_version = match entry.value {
        EntryValue::Uint16(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };
    if mmdb.metadata.binary_format_major_version == 0 {
        return MMDB_INVALID_METADATA_ERROR;
    }

    // binary_format_minor_version
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["binary_format_minor_version"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT16 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.binary_format_minor_version = match entry.value {
        EntryValue::Uint16(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };

    // build_epoch
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["build_epoch"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_UINT64 {
        return MMDB_INVALID_METADATA_ERROR;
    }
    mmdb.metadata.build_epoch = match entry.value {
        EntryValue::Uint64(v) => v,
        _ => return MMDB_INVALID_METADATA_ERROR,
    };
    if mmdb.metadata.build_epoch == 0 {
        return MMDB_INVALID_METADATA_ERROR;
    }

    // description (map of language -> description)
    let mut entry = EntryData::default();
    let status = mmdb_aget_value_raw(&fake, 0, &["description"], &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id != MMDB_DATA_TYPE_MAP {
        return MMDB_INVALID_METADATA_ERROR;
    }
    let mut list = Vec::new();
    let status = get_entry_data_list(&fake, entry.offset, &mut list, 0);
    if status != MMDB_SUCCESS {
        return status;
    }
    let map_size = list[0].data_size as usize;
    let mut descriptions = Vec::new();
    let mut idx = 0usize;
    for _ in 0..map_size {
        idx += 1; // key
        if idx >= list.len() || list[idx].type_id != MMDB_DATA_TYPE_UTF8_STRING {
            return MMDB_INVALID_METADATA_ERROR;
        }
        let language = strndup(match &list[idx].value {
            EntryValue::Utf8String(b) => b,
            _ => return MMDB_INVALID_METADATA_ERROR,
        });
        idx += 1; // value
        if idx >= list.len() || list[idx].type_id != MMDB_DATA_TYPE_UTF8_STRING {
            return MMDB_INVALID_METADATA_ERROR;
        }
        let description = strndup(match &list[idx].value {
            EntryValue::Utf8String(b) => b,
            _ => return MMDB_INVALID_METADATA_ERROR,
        });
        descriptions.push(Description {
            language,
            description,
        });
    }
    mmdb.metadata.descriptions = descriptions;

    mmdb.full_record_byte_size = mmdb.metadata.record_size * 2 / 8;
    mmdb.depth = if mmdb.metadata.ip_version == 4 {
        32
    } else {
        128
    };

    MMDB_SUCCESS
}

/// A borrowable stand-in for the fake metadata db: the decoder operates on
/// (data slice, size) pairs; the real Mmdb and the fake metadata db both
/// provide those.
trait Decodable {
    fn data(&self) -> &[u8];
    fn data_size(&self) -> u32;
}

struct FakeDb {
    data: Vec<u8>,
    data_size: u32,
}

impl Decodable for FakeDb {
    fn data(&self) -> &[u8] {
        &self.data
    }
    fn data_size(&self) -> u32 {
        self.data_size
    }
}

impl Decodable for Mmdb {
    fn data(&self) -> &[u8] {
        self.data()
    }
    fn data_size(&self) -> u32 {
        self.data_section_size
    }
}

// ---------------------------------------------------------------------------
// The data decoder (maxminddb.c decode_one, decode_one_follow, get_*)
// ---------------------------------------------------------------------------

/// `get_ext_type(raw)` = 7 + raw.
fn get_ext_type(raw_ext_type: u8) -> u32 {
    7 + raw_ext_type as u32
}

/// `get_ptr_from(ctrl, ptr, ptr_size)`.
fn get_ptr_from(ctrl: u8, ptr: &[u8], ptr_size: usize) -> u32 {
    match ptr_size {
        1 => ((ctrl & 7) as u32) << 8 | ptr[0] as u32,
        2 => 2048 + (((ctrl & 7) as u32) << 16) + ((ptr[0] as u32) << 8) + ptr[1] as u32,
        3 => 2048 + 524288 + (((ctrl & 7) as u32) << 24) + get_uint24(ptr),
        _ => get_uint32(ptr),
    }
}

/// `decode_one` — decode the entry at `offset` without following pointers.
fn decode_one<D: Decodable>(db: &D, offset: u32, entry: &mut EntryData) -> i32 {
    let mem = db.data();
    let size = db.data_size();

    // We subtract rather than add as it possible that offset + 1 could
    // overflow for a corrupt database while an underflow from
    // data_section_size - 1 should not be possible.
    if offset > size.wrapping_sub(1) {
        return MMDB_INVALID_DATA_ERROR;
    }

    entry.offset = offset;
    entry.has_data = true;

    let mut offset = offset;
    let ctrl = mem[offset as usize];
    offset += 1;

    let mut type_id = ((ctrl >> 5) & 7) as u32;
    if type_id == MMDB_DATA_TYPE_EXTENDED {
        if offset > size.wrapping_sub(1) {
            return MMDB_INVALID_DATA_ERROR;
        }
        type_id = get_ext_type(mem[offset as usize]);
        offset += 1;
    }
    entry.type_id = type_id;

    if type_id == MMDB_DATA_TYPE_POINTER {
        let psize = (((ctrl >> 3) & 3) + 1) as usize;
        // offset past the end, or the subtraction of psize underflowed
        // (the C compares in unsigned arithmetic, hence wrapping_sub)
        if offset > size.wrapping_sub(psize as u32) || size < psize as u32 {
            return MMDB_INVALID_DATA_ERROR;
        }
        entry.value = EntryValue::Pointer(get_ptr_from(ctrl, &mem[offset as usize..], psize));
        entry.data_size = psize as u32;
        entry.offset_to_next = offset + psize as u32;
        return MMDB_SUCCESS;
    }

    let mut entry_size: u32 = (ctrl & 31) as u32;
    match entry_size {
        29 => {
            if offset > size.wrapping_sub(1) {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry_size = 29 + mem[offset as usize] as u32;
            offset += 1;
        }
        30 => {
            if offset > size.wrapping_sub(2) {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry_size = 285 + get_uint16(&mem[offset as usize..]);
            offset += 2;
        }
        31 => {
            if offset > size.wrapping_sub(3) {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry_size = 65821 + get_uint24(&mem[offset as usize..]);
            offset += 3;
        }
        _ => {}
    }

    if type_id == MMDB_DATA_TYPE_MAP || type_id == MMDB_DATA_TYPE_ARRAY {
        entry.data_size = entry_size;
        entry.offset_to_next = offset;
        entry.value = EntryValue::Container;
        return MMDB_SUCCESS;
    }

    if type_id == MMDB_DATA_TYPE_BOOLEAN {
        entry.value = EntryValue::Boolean(entry_size != 0);
        entry.data_size = 0;
        entry.offset_to_next = offset;
        return MMDB_SUCCESS;
    }

    // Check that the data doesn't extend past the end of the memory buffer
    // and that the calculation in doing this did not underflow.
    if offset > size.wrapping_sub(entry_size) || size < entry_size {
        return MMDB_INVALID_DATA_ERROR;
    }

    let payload = &mem[offset as usize..offset as usize + entry_size as usize];
    match type_id {
        MMDB_DATA_TYPE_UINT16 => {
            if entry_size > 2 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Uint16(get_uintx(payload, entry_size as usize) as u16);
        }
        MMDB_DATA_TYPE_UINT32 => {
            if entry_size > 4 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Uint32(get_uintx(payload, entry_size as usize) as u32);
        }
        MMDB_DATA_TYPE_INT32 => {
            if entry_size > 4 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Int32(get_sintx(payload, entry_size as usize));
        }
        MMDB_DATA_TYPE_UINT64 => {
            if entry_size > 8 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Uint64(get_uintx(payload, entry_size as usize));
        }
        MMDB_DATA_TYPE_UINT128 => {
            if entry_size > 16 {
                return MMDB_INVALID_DATA_ERROR;
            }
            // C (non-byte-array mode): get_uint128 shifts up to 16 bytes
            let mut value: u128 = 0;
            for i in 0..entry_size as usize {
                value <<= 8;
                value += payload[i] as u128;
            }
            entry.value = EntryValue::Uint128(value);
        }
        MMDB_DATA_TYPE_FLOAT => {
            if entry_size != 4 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Float(get_ieee754_float(payload));
        }
        MMDB_DATA_TYPE_DOUBLE => {
            if entry_size != 8 {
                return MMDB_INVALID_DATA_ERROR;
            }
            entry.value = EntryValue::Double(get_ieee754_double(payload));
        }
        MMDB_DATA_TYPE_UTF8_STRING => {
            entry.value = EntryValue::Utf8String(payload.to_vec());
            entry.data_size = entry_size;
        }
        MMDB_DATA_TYPE_BYTES => {
            entry.value = EntryValue::Bytes(payload.to_vec());
            entry.data_size = entry_size;
        }
        _ => {}
    }

    entry.offset_to_next = offset + entry_size;
    MMDB_SUCCESS
}

/// `decode_one_follow` — decode and follow one pointer level; pointers to
/// pointers are illegal.
fn decode_one_follow<D: Decodable>(db: &D, offset: u32, entry: &mut EntryData) -> i32 {
    let status = decode_one(db, offset, entry);
    if status != MMDB_SUCCESS {
        return status;
    }
    if entry.type_id == MMDB_DATA_TYPE_POINTER {
        let next = entry.offset_to_next;
        let pointer = match entry.value {
            EntryValue::Pointer(p) => p,
            _ => return MMDB_INVALID_DATA_ERROR,
        };
        let status = decode_one(db, pointer, entry);
        if status != MMDB_SUCCESS {
            return status;
        }
        if entry.type_id == MMDB_DATA_TYPE_POINTER {
            return MMDB_INVALID_DATA_ERROR;
        }
        // For a compound value the next one is the one after the pointer
        // result; for a simple value it is the one after the pointer.
        if entry.type_id != MMDB_DATA_TYPE_MAP && entry.type_id != MMDB_DATA_TYPE_ARRAY {
            entry.offset_to_next = next;
        }
    }
    MMDB_SUCCESS
}

/// `skip_map_or_array` — advance over compound values without following
/// pointers; depth is capped at MAXIMUM_DATA_STRUCTURE_DEPTH.
fn skip_map_or_array<D: Decodable>(db: &D, entry: &mut EntryData, depth: i32) -> i32 {
    if depth >= MAXIMUM_DATA_STRUCTURE_DEPTH as i32 {
        return MMDB_INVALID_DATA_ERROR;
    }
    if entry.type_id == MMDB_DATA_TYPE_MAP {
        let mut size = entry.data_size;
        while size > 0 {
            size -= 1;
            let status = decode_one(db, entry.offset_to_next, entry);
            if status != MMDB_SUCCESS {
                return status;
            }
            let status = decode_one(db, entry.offset_to_next, entry);
            if status != MMDB_SUCCESS {
                return status;
            }
            let status = skip_map_or_array(db, entry, depth + 1);
            if status != MMDB_SUCCESS {
                return status;
            }
        }
    } else if entry.type_id == MMDB_DATA_TYPE_ARRAY {
        let mut size = entry.data_size;
        while size > 0 {
            size -= 1;
            let status = decode_one(db, entry.offset_to_next, entry);
            if status != MMDB_SUCCESS {
                return status;
            }
            let status = skip_map_or_array(db, entry, depth + 1);
            if status != MMDB_SUCCESS {
                return status;
            }
        }
    }
    MMDB_SUCCESS
}

// ---------------------------------------------------------------------------
// Path lookup (maxminddb.c MMDB_aget_value, lookup_path_in_array/map)
// ---------------------------------------------------------------------------

/// `strtol` (base 10, glibc): skip leading whitespace, optional sign, parse
/// decimal digits; ERANGE on overflow; returns (value, first_invalid).
/// Mirrors the observable subset the C relies on for array indexes.
fn strtol10(s: &str) -> Result<(i64, usize), ()> {
    let bytes = s.as_bytes();
    let mut i = 0;
    // isspace (glibc: space, \t, \n, \v, \f, \r)
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut negative = false;
    if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
        negative = bytes[i] == b'-';
        i += 1;
    }
    let digits_start = i;
    let mut any = false;
    let mut overflow = false;
    // accumulate with checked arithmetic (the C clamps and sets ERANGE; we
    // only need the ERANGE verdict)
    let mut value: i64 = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        any = true;
        let d = (bytes[i] - b'0') as i64;
        let next = if negative {
            value.checked_mul(10).and_then(|v| v.checked_sub(d))
        } else {
            value.checked_mul(10).and_then(|v| v.checked_add(d))
        };
        match next {
            Some(v) => value = v,
            None => {
                overflow = true;
            }
        }
        i += 1;
    }
    if !any {
        // no digits: first_invalid points at the first character; value 0
        return Ok((0, digits_start));
    }
    if overflow {
        return Err(()); // ERANGE
    }
    let first_invalid = i;
    Ok((if negative { value } else { value }, first_invalid))
}

/// `lookup_path_in_array` — the C uses strtol on the path element.
fn lookup_path_in_array<D: Decodable>(db: &D, path_elem: &str, entry: &mut EntryData) -> i32 {
    let size = entry.data_size;

    let (array_index, first_invalid) = match strtol10(path_elem) {
        Ok(v) => v,
        Err(()) => return MMDB_INVALID_LOOKUP_PATH_ERROR,
    };

    let mut array_index = array_index;
    if array_index < 0 {
        array_index += size as i64;
        if array_index < 0 {
            return MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
        }
    }

    if first_invalid != path_elem.len() || array_index as u64 >= size as u64 {
        return MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
    }

    for _ in 0..array_index {
        let status = decode_one(db, entry.offset_to_next, entry);
        if status != MMDB_SUCCESS {
            return status;
        }
        let status = skip_map_or_array(db, entry, 0);
        if status != MMDB_SUCCESS {
            return status;
        }
    }

    let mut value = EntryData::default();
    let status = decode_one_follow(db, entry.offset_to_next, &mut value);
    if status != MMDB_SUCCESS {
        return status;
    }
    *entry = value;
    MMDB_SUCCESS
}

/// `lookup_path_in_map` — byte-compare keys; keys must be utf8 strings.
fn lookup_path_in_map<D: Decodable>(db: &D, path_elem: &str, entry: &mut EntryData) -> i32 {
    let mut size = entry.data_size;
    let mut offset = entry.offset_to_next;
    let path_elem_len = path_elem.len();

    while size > 0 {
        size -= 1;
        let mut key = EntryData::default();
        let status = decode_one_follow(db, offset, &mut key);
        if status != MMDB_SUCCESS {
            return status;
        }
        let offset_to_value = key.offset_to_next;

        if key.type_id != MMDB_DATA_TYPE_UTF8_STRING {
            return MMDB_INVALID_DATA_ERROR;
        }

        let matches = match &key.value {
            EntryValue::Utf8String(b) => {
                b.len() == path_elem_len && b.as_slice() == path_elem.as_bytes()
            }
            _ => false,
        };

        if matches {
            let mut value = EntryData::default();
            let status = decode_one_follow(db, offset_to_value, &mut value);
            if status != MMDB_SUCCESS {
                return status;
            }
            *entry = value;
            return MMDB_SUCCESS;
        } else {
            let mut value = EntryData::default();
            let status = decode_one(db, offset_to_value, &mut value);
            if status != MMDB_SUCCESS {
                return status;
            }
            let status = skip_map_or_array(db, &mut value, 0);
            if status != MMDB_SUCCESS {
                return status;
            }
            offset = value.offset_to_next;
        }
    }

    *entry = EntryData::default();
    MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR
}

/// `MMDB_aget_value` — walk the path.  Returns the error code; on failure
/// the entry data is zeroed exactly like the C (`memset` in the caller).
fn aget_value_inner<D: Decodable>(
    db: &D,
    start_offset: u32,
    path: &[&str],
    entry_data: &mut EntryData,
) -> i32 {
    *entry_data = EntryData::default();
    let mut offset = start_offset;

    let status = decode_one_follow(db, offset, entry_data);
    if status != MMDB_SUCCESS {
        return status;
    }

    if !entry_data.has_data {
        return MMDB_INVALID_LOOKUP_PATH_ERROR;
    }

    for path_elem in path {
        if entry_data.type_id == MMDB_DATA_TYPE_ARRAY {
            let status = lookup_path_in_array(db, path_elem, entry_data);
            if status != MMDB_SUCCESS {
                *entry_data = EntryData::default();
                return status;
            }
        } else if entry_data.type_id == MMDB_DATA_TYPE_MAP {
            let status = lookup_path_in_map(db, path_elem, entry_data);
            if status != MMDB_SUCCESS {
                *entry_data = EntryData::default();
                return status;
            }
        } else {
            *entry_data = EntryData::default();
            return MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR;
        }
    }

    MMDB_SUCCESS
}

/// wrapper used by read_metadata
fn mmdb_aget_value_raw<D: Decodable>(
    db: &D,
    start: u32,
    path: &[&str],
    out: &mut EntryData,
) -> i32 {
    aget_value_inner(db, start, path, out)
}

/// `MMDB_aget_value(start, path)` — public entry from an open database.
pub fn mmdb_aget_value(mmdb: &Mmdb, start_offset: u32, path: &[&str], out: &mut EntryData) -> i32 {
    aget_value_inner(mmdb, start_offset, path, out)
}

// ---------------------------------------------------------------------------
// Entry data list (maxminddb.c get_entry_data_list + data-pool.c ordering)
// ---------------------------------------------------------------------------

/// `get_entry_data_list` — build the list in the exact order the C's data
/// pool allocates nodes (preorder; map = key,value pairs; pointers to
/// compounds expand in place).
fn get_entry_data_list<D: Decodable>(
    db: &D,
    offset: u32,
    list: &mut Vec<EntryData>,
    depth: i32,
) -> i32 {
    if depth >= MAXIMUM_DATA_STRUCTURE_DEPTH as i32 {
        return MMDB_INVALID_DATA_ERROR;
    }
    let depth = depth + 1;

    let mut entry = EntryData::default();
    let status = decode_one(db, offset, &mut entry);
    if status != MMDB_SUCCESS {
        return status;
    }

    match entry.type_id {
        MMDB_DATA_TYPE_POINTER => {
            let next_offset = entry.offset_to_next;
            let pointer = match entry.value {
                EntryValue::Pointer(p) => p,
                _ => return MMDB_INVALID_DATA_ERROR,
            };
            let status = decode_one(db, pointer, &mut entry);
            if status != MMDB_SUCCESS {
                return status;
            }
            if entry.type_id == MMDB_DATA_TYPE_POINTER {
                return MMDB_INVALID_DATA_ERROR;
            }
            if entry.type_id == MMDB_DATA_TYPE_ARRAY || entry.type_id == MMDB_DATA_TYPE_MAP {
                let status = get_entry_data_list(db, pointer, list, depth);
                if status != MMDB_SUCCESS {
                    return status;
                }
            } else {
                // scalar pointed to: the node IS the resolved scalar
                list.push(entry);
            }
            if let Some(last) = list.last_mut() {
                last.offset_to_next = next_offset;
            }
            MMDB_SUCCESS
        }
        MMDB_DATA_TYPE_ARRAY => {
            let array_size = entry.data_size;
            let mut array_offset = entry.offset_to_next;
            // Each array element needs at least 1 byte.
            let ds = db.data_size();
            if array_offset > ds || array_size > ds - array_offset {
                return MMDB_INVALID_DATA_ERROR;
            }
            list.push(entry);
            let mut n = array_size;
            while n > 0 {
                n -= 1;
                let status = get_entry_data_list(db, array_offset, list, depth);
                if status != MMDB_SUCCESS {
                    return status;
                }
                array_offset = list
                    .last()
                    .map(|e| e.offset_to_next)
                    .unwrap_or(array_offset);
            }
            if let Some(last) = list.last_mut() {
                last.offset_to_next = array_offset;
            }
            MMDB_SUCCESS
        }
        MMDB_DATA_TYPE_MAP => {
            let map_size = entry.data_size;
            let mut offset = entry.offset_to_next;
            let ds = db.data_size();
            // Each map entry needs at least a key and a value (1 byte each).
            if offset > ds || map_size > (ds - offset) / 2 {
                return MMDB_INVALID_DATA_ERROR;
            }
            list.push(entry);
            let mut n = map_size;
            while n > 0 {
                n -= 1;
                let status = get_entry_data_list(db, offset, list, depth);
                if status != MMDB_SUCCESS {
                    return status;
                }
                offset = list.last().map(|e| e.offset_to_next).unwrap_or(offset);
                let status = get_entry_data_list(db, offset, list, depth);
                if status != MMDB_SUCCESS {
                    return status;
                }
                offset = list.last().map(|e| e.offset_to_next).unwrap_or(offset);
            }
            if let Some(last) = list.last_mut() {
                last.offset_to_next = offset;
            }
            MMDB_SUCCESS
        }
        _ => {
            list.push(entry);
            MMDB_SUCCESS
        }
    }
}

/// `MMDB_get_entry_data_list(start, &list)`.
pub fn mmdb_get_entry_data_list(db: &Mmdb, start_offset: u32, list: &mut Vec<EntryData>) -> i32 {
    let status = get_entry_data_list(db, start_offset, list, 0);
    if status != MMDB_SUCCESS {
        return status;
    }
    MMDB_SUCCESS
}

/// `MMDB_get_metadata_as_entry_data_list` — the metadata section decoded as
/// entry data.
pub fn mmdb_get_metadata_as_entry_data_list(db: &Mmdb, list: &mut Vec<EntryData>) -> i32 {
    let fake = FakeDb {
        data: db.metadata_data().to_vec(),
        data_size: db.metadata_section_size,
    };
    let status = get_entry_data_list(&fake, 0, list, 0);
    if status != MMDB_SUCCESS {
        return status;
    }
    MMDB_SUCCESS
}

// ---------------------------------------------------------------------------
// Search tree (maxminddb.c record_info_for_database, find_address_in_search_tree,
// find_ipv4_start_node, record_type, MMDB_read_node)
// ---------------------------------------------------------------------------

struct RecordInfo {
    record_length: usize,
    right_record_offset: usize,
    /// 6=24bit, 7=28bit, 8=32bit
    kind: u8,
}

fn record_info_for_database(mmdb: &Mmdb) -> Option<RecordInfo> {
    let record_length = mmdb.full_record_byte_size as usize;
    match record_length {
        6 => Some(RecordInfo {
            record_length,
            right_record_offset: 3,
            kind: 6,
        }),
        7 => Some(RecordInfo {
            record_length,
            right_record_offset: 3,
            kind: 7,
        }),
        8 => Some(RecordInfo {
            record_length,
            right_record_offset: 4,
            kind: 8,
        }),
        _ => None,
    }
}

fn get_left_record(ri: &RecordInfo, p: &[u8]) -> u64 {
    match ri.kind {
        6 => get_uint24(p) as u64,
        7 => {
            // get_left_28_bit_record
            (p[0] as u64) * 65536
                + (p[1] as u64) * 256
                + p[2] as u64
                + (((p[3] & 0xf0) as u64) << 20)
        }
        _ => get_uint32(p) as u64,
    }
}

fn get_right_record(ri: &RecordInfo, p: &[u8]) -> u64 {
    match ri.kind {
        6 => get_uint24(p) as u64,
        7 => (get_uint32(p) & 0xfffffff) as u64,
        _ => get_uint32(p) as u64,
    }
}

/// `data_section_offset_for_record(record)` = record - node_count - 16.
/// The C computes this in unsigned 64-bit arithmetic (wrapping) and casts to
/// u32; for non-DATA record types the result is an "invalid" wrapped offset
/// that MMDB_read_node still reports (probe parity).
fn data_section_offset_for_record(mmdb: &Mmdb, record: u64) -> u32 {
    record
        .wrapping_sub(mmdb.metadata.node_count as u64)
        .wrapping_sub(MMDB_DATA_SECTION_SEPARATOR as u64) as u32
}

/// `record_type(record)`.
fn record_type(mmdb: &Mmdb, record: u64) -> u8 {
    let node_count = mmdb.metadata.node_count as u64;
    if record == 0 {
        return MMDB_RECORD_TYPE_INVALID;
    }
    if record < node_count {
        return MMDB_RECORD_TYPE_SEARCH_NODE;
    }
    if record == node_count {
        return MMDB_RECORD_TYPE_EMPTY;
    }
    if record - node_count < mmdb.data_section_size as u64 {
        return MMDB_RECORD_TYPE_DATA;
    }
    MMDB_RECORD_TYPE_INVALID
}

/// `find_ipv4_start_node` — walk the all-zero path for up to 96 bits.
fn find_ipv4_start_node(mmdb: &mut Mmdb) -> i32 {
    if mmdb.ipv4_start_node.0 != 0 {
        return MMDB_SUCCESS;
    }
    let Some(ri) = record_info_for_database(mmdb) else {
        return MMDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    };
    let search_tree_size = mmdb.metadata.node_count as usize * ri.record_length;
    let node_count = mmdb.metadata.node_count as u64;
    let mut node_value: u64 = 0;
    let mut netmask: u16 = 0;
    while netmask < 96 && node_value < node_count {
        let off = node_value as usize * ri.record_length;
        if off + ri.record_length > search_tree_size + MMDB_DATA_SECTION_SEPARATOR as usize {
            return MMDB_CORRUPT_SEARCH_TREE_ERROR;
        }
        node_value = get_left_record(&ri, &mmdb.file_content[off..off + ri.record_length]);
        netmask += 1;
    }
    mmdb.ipv4_start_node = (node_value as u32, netmask);
    MMDB_SUCCESS
}

/// `find_address_in_search_tree`.
fn find_address_in_search_tree(
    mmdb: &Mmdb,
    address: &[u8],
    is_ipv6: bool,
    result: &mut LookupResult,
) -> i32 {
    let Some(ri) = record_info_for_database(mmdb) else {
        return MMDB_UNKNOWN_DATABASE_FORMAT_ERROR;
    };
    let search_tree_size = mmdb.metadata.node_count as usize * ri.record_length;

    let mut value: u64;
    let mut current_bit: u16;
    if mmdb.metadata.ip_version == 6 && !is_ipv6 {
        value = mmdb.ipv4_start_node.0 as u64;
        current_bit = mmdb.ipv4_start_node.1;
    } else {
        value = 0;
        current_bit = 0;
    }

    let node_count = mmdb.metadata.node_count as u64;
    while (current_bit as u32) < mmdb.depth as u32 && value < node_count {
        let bit = 1u8 & (address[(current_bit >> 3) as usize] >> (7 - (current_bit % 8)));
        let off = value as usize * ri.record_length;
        if off + ri.record_length > search_tree_size + MMDB_DATA_SECTION_SEPARATOR as usize {
            return MMDB_CORRUPT_SEARCH_TREE_ERROR;
        }
        let record = &mmdb.file_content[off..off + ri.record_length];
        if bit != 0 {
            value = get_right_record(&ri, &record[ri.right_record_offset..]);
        } else {
            value = get_left_record(&ri, record);
        }
        current_bit += 1;
    }

    result.netmask = current_bit;

    if value >= node_count + mmdb.data_section_size as u64 {
        // The pointer points off the end of the database.
        return MMDB_CORRUPT_SEARCH_TREE_ERROR;
    }
    if value == node_count {
        // record is empty
        result.found_entry = false;
        return MMDB_SUCCESS;
    }
    result.found_entry = true;
    result.entry_offset = data_section_offset_for_record(mmdb, value);
    MMDB_SUCCESS
}

// ---------------------------------------------------------------------------
// Public lookup API
// ---------------------------------------------------------------------------

/// `MMDB_lookup_result_s`.
#[derive(Debug, Clone, Default)]
pub struct LookupResult {
    pub found_entry: bool,
    pub entry_offset: u32,
    pub netmask: u16,
}

/// glibc EAI_* codes (the C returns the raw getaddrinfo status).
pub const EAI_NONAME: i32 = -2;

/// `resolve_any_address` — getaddrinfo(AF_UNSPEC, AI_NUMERICHOST,
/// SOCK_STREAM).  Numeric-only; returns 0 on success and the glibc EAI code
/// on failure.  glibc's AI_NUMERICHOST validation is inet_pton semantics
/// (strict: no leading-zero octets in IPv4, RFC 4291 IPv6) plus the
/// inet_aton shorthand fallback; we reproduce that exactly.
fn resolve_any_address(ipstr: &str) -> (i32, Option<IpAddr>) {
    match parse_inet_pton(ipstr) {
        Some(addr) => (0, Some(addr)),
        None => (EAI_NONAME, None),
    }
}

/// Probe accessor (MMDB-GAI-0001): the getaddrinfo-equivalent resolution,
/// used by the probe court to print the resolved address bytes.
pub fn mmdb_resolve(ipstr: &str) -> (i32, Option<IpAddr>) {
    resolve_any_address(ipstr)
}

/// Strict inet_pton (glibc) numeric parsing: returns the address bytes.
/// IPv4: exactly four decimal octets, no leading zeros unless the octet is
/// exactly "0".  IPv6: RFC 4291 with at most one "::", 1-4 hex digits per
/// group, optional trailing embedded IPv4 (which must itself be strict),
/// and getaddrinfo zone handling (a non-empty zone after '%'; numeric zones
/// accepted as-is, named zones must resolve via if_nametoindex).
fn parse_inet_pton(s: &str) -> Option<IpAddr> {
    if s.is_empty() {
        return None;
    }
    if let Some(addr) = parse_inet_pton4(s) {
        return Some(IpAddr::V4(addr));
    }
    if let Some(addr) = parse_inet_pton6_ga(s) {
        return Some(IpAddr::V6(addr));
    }
    // glibc AI_NUMERICHOST fallback: inet_aton-style shorthand (octal, hex,
    // 1-3 part forms) with an exact-consumption rule (MMDB-GAI-0001).
    if let Some(addr) = parse_inet_aton_exact(s) {
        return Some(IpAddr::V4(std::net::Ipv4Addr::new(
            addr[0], addr[1], addr[2], addr[3],
        )));
    }
    None
}

/// getaddrinfo zone handling: strip at '%'; the zone must be non-empty;
/// a fully-decimal zone is accepted as a numeric interface index (glibc's
/// strtol path accepts any value including 0); any other zone must name an
/// existing interface (glibc if_nametoindex; we read /sys/class/net/NAME/
/// ifindex, the same kernel state).
fn parse_inet_pton6_ga(s: &str) -> Option<std::net::Ipv6Addr> {
    match s.find('%') {
        Some(idx) => {
            let zone = &s[idx + 1..];
            if zone.is_empty() {
                return None;
            }
            let zone_ok = if zone.bytes().all(|b| b.is_ascii_digit()) {
                // glibc parses the numeric zone with strtoul; on ERANGE it
                // falls back to if_nametoindex (which fails for the huge
                // digit string) and rejects (MMDB-GAI-0002)
                zone.parse::<u64>().is_ok()
            } else {
                std::fs::read_to_string(format!("/sys/class/net/{zone}/ifindex")).is_ok()
            };
            if !zone_ok {
                return None;
            }
            parse_inet_pton6(&s[..idx])
        }
        None => parse_inet_pton6(s),
    }
}

/// glibc `__inet_aton` as used by getaddrinfo(AI_NUMERICHOST) — the
/// observed contract (pinned by the MMDB-0001 oracle corpus):
///
/// - 1 to 4 dot-separated parts; a part is decimal, octal (leading '0'), or
///   hexadecimal ("0x"/"0X"); signs are rejected; the whole string must be
///   consumed (no trailing whitespace/garbage, no leading whitespace);
/// - an octal part whose digit is 8/9 stops at that digit and the address
///   is rejected (the "09" case); a "0x" prefix requires at least one hex
///   digit;
/// - ranges: 1 part <= 0xFFFFFFFF, 2 parts: first <= 0xFF, second <=
///   0xFFFF, 3 parts: first two <= 0xFF, third <= 0xFFFFFF, 4 parts: each
///   <= 0xFF;
/// - layout: a.b.c.d -> b0..b3; a.b.c -> a, b, c>>8, c&0xff; a.b -> a,
///   b>>16, (b>>8)&0xff, b&0xff; a -> the 32-bit value big-endian.
fn parse_inet_aton_exact(s: &str) -> Option<[u8; 4]> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes[0] == b'.' {
        return None;
    }
    let mut parts = [0u64; 4];
    let mut n = 0usize;
    let mut i = 0usize;
    loop {
        if i >= bytes.len() {
            return None; // empty part
        }
        let mut base = 10u32;
        let mut j = i;
        if bytes[j] == b'0' {
            if j + 1 < bytes.len() && (bytes[j + 1] == b'x' || bytes[j + 1] == b'X') {
                base = 16;
                j += 2;
            } else {
                // octal: the '0' itself is a digit (do not consume it)
                base = 8;
            }
        }
        let start = j;
        let mut val: u64 = 0;
        while j < bytes.len() {
            let c = bytes[j];
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' if base == 16 => (c - b'a' + 10) as u32,
                b'A'..=b'F' if base == 16 => (c - b'A' + 10) as u32,
                _ => break,
            };
            if base == 8 && d >= 8 {
                break; // invalid octal digit: not consumed -> reject later
            }
            val = val.wrapping_mul(base as u64).wrapping_add(d as u64);
            j += 1;
        }
        if j == start {
            // no digits consumed (includes the bare "0x" prefix)
            return None;
        }
        if n >= 4 {
            return None; // 5+ parts
        }
        parts[n] = val;
        n += 1;
        if j < bytes.len() && bytes[j] == b'.' {
            i = j + 1;
            continue;
        }
        if j != bytes.len() {
            return None; // trailing garbage (includes octal 8/9)
        }
        break;
    }
    // range checks per part count
    let limit: u64 = match n {
        1 => 0xFFFF_FFFF,
        2 => 0xFFFF,
        3 => 0xFF_FFFF,
        _ => 0xFF,
    };
    if parts[n - 1] > limit {
        return None;
    }
    for p in &parts[..n - 1] {
        if *p > 0xFF {
            return None;
        }
    }
    let mut out = [0u8; 4];
    match n {
        1 => out.copy_from_slice(&(parts[0] as u32).to_be_bytes()),
        2 => {
            out[0] = parts[0] as u8;
            out[1] = (parts[1] >> 16) as u8;
            out[2] = (parts[1] >> 8) as u8;
            out[3] = parts[1] as u8;
        }
        3 => {
            out[0] = parts[0] as u8;
            out[1] = parts[1] as u8;
            out[2] = (parts[2] >> 8) as u8;
            out[3] = parts[2] as u8;
        }
        _ => {
            out[0] = parts[0] as u8;
            out[1] = parts[1] as u8;
            out[2] = parts[2] as u8;
            out[3] = parts[3] as u8;
        }
    }
    Some(out)
}

fn parse_inet_pton4(s: &str) -> Option<std::net::Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        // musl/glibc inet_pton4: no leading zeros (a digit after a 0 makes
        // the value 10x and rejects), each octet <= 255, at least one digit
        if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        let v: u32 = part.parse().ok()?;
        if v > 255 {
            return None;
        }
        octets[i] = v as u8;
    }
    Some(std::net::Ipv4Addr::new(
        octets[0], octets[1], octets[2], octets[3],
    ))
}

/// glibc inet_pton6 (port of the Vixie-derived algorithm in glibc/
/// inet_pton.c).
fn parse_inet_pton6(s: &str) -> Option<std::net::Ipv6Addr> {
    let bytes = s.as_bytes();
    let mut tmp = [0u8; 16];
    let mut tp: usize = 0; // write position
    let mut colonp: Option<usize> = None; // position of "::"
    let mut curtok: usize = 0;
    let mut i = 0usize;

    // Leading "::" requires some special handling: the C checks the first
    // two characters and then lets the main loop process the second colon,
    // which is what records the compression point (colonp).  We therefore
    // start the loop AT the second colon, not past it.
    if bytes[0] == b':' {
        if bytes.get(1) != Some(&b':') {
            return None;
        }
        i = 1;
    }

    let mut saw_xdigit = false;
    let mut val: u32 = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        let digit = match ch {
            b'0'..=b'9' => Some((ch - b'0') as u32),
            b'a'..=b'f' => Some((ch - b'a' + 10) as u32),
            b'A'..=b'F' => Some((ch - b'A' + 10) as u32),
            _ => None,
        };
        if let Some(d) = digit {
            val <<= 4;
            val |= d;
            if val > 0xffff {
                return None;
            }
            saw_xdigit = true;
            i += 1;
            continue;
        }
        if ch == b':' {
            curtok = i + 1;
            if !saw_xdigit {
                if colonp.is_some() {
                    return None;
                }
                colonp = Some(tp);
                i += 1;
                continue;
            } else if i + 1 == bytes.len() {
                return None;
            }
            if tp + 2 > 16 {
                return None;
            }
            tmp[tp] = ((val >> 8) & 0xff) as u8;
            tmp[tp + 1] = (val & 0xff) as u8;
            tp += 2;
            saw_xdigit = false;
            val = 0;
            i += 1;
            continue;
        }
        if ch == b'.' && tp + 4 <= 16 {
            // embedded IPv4: inet_pton4 scans from curtok to the end of the
            // string (it consumed through the NUL, so we finish here)
            let v4part = &s[curtok..];
            if let Some(v4) = parse_inet_pton4(v4part) {
                let o = v4.octets();
                tmp[tp..tp + 4].copy_from_slice(&o);
                tp += 4;
                return finish_inet_pton6(&mut tmp, tp, colonp);
            }
            return None;
        }
        return None;
    }

    if saw_xdigit {
        if tp + 2 > 16 {
            return None;
        }
        tmp[tp] = ((val >> 8) & 0xff) as u8;
        tmp[tp + 1] = (val & 0xff) as u8;
        tp += 2;
    }
    finish_inet_pton6(&mut tmp, tp, colonp)
}

/// glibc's "shift the tail by hand" — n = tp - colonp; endp[-i] =
/// colonp[n-i] for i in 1..=n; tp becomes endp.  (The C zeroes the old
/// positions too; the destination bytes are identical either way.)
fn finish_inet_pton6(
    tmp: &mut [u8; 16],
    mut tp: usize,
    colonp: Option<usize>,
) -> Option<std::net::Ipv6Addr> {
    if let Some(cp) = colonp {
        let n = tp - cp;
        if tp == 16 {
            return None;
        }
        for k in 1..=n {
            tmp[16 - k] = tmp[cp + n - k];
            // the C zeroes the vacated region (colonp[n-i] = 0); without it
            // the compressed tail would remain duplicated at the front
            tmp[cp + n - k] = 0;
        }
        tp = 16;
    }
    if tp != 16 {
        return None;
    }
    Some(std::net::Ipv6Addr::from(*tmp))
}

/// `MMDB_lookup_sockaddr` — `is_ipv6` distinguishes the sockaddr family.
pub fn mmdb_lookup_sockaddr(mmdb: &Mmdb, addr: IpAddr, mmdb_error: &mut i32) -> LookupResult {
    let mut result = LookupResult::default();
    let is_ipv6 = addr.is_ipv6();
    let bytes = match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let address: Vec<u8>;
    if mmdb.metadata.ip_version == 4 {
        if is_ipv6 {
            *mmdb_error = MMDB_IPV6_LOOKUP_IN_IPV4_DATABASE_ERROR;
            return result;
        }
        address = bytes;
    } else {
        if is_ipv6 {
            address = bytes;
        } else {
            // mapped: 12 zero bytes + the 4 v4 bytes
            let mut mapped = vec![0u8; 16];
            mapped[12..].copy_from_slice(&bytes);
            address = mapped;
        }
    }

    *mmdb_error = find_address_in_search_tree(mmdb, &address, is_ipv6, &mut result);
    result
}

/// `MMDB_lookup_string` — returns (result, gai_error, mmdb_error).
pub fn mmdb_lookup_string(mmdb: &Mmdb, ipstr: &str) -> (LookupResult, i32, i32) {
    let (gai_error, addr) = resolve_any_address(ipstr);
    let mut result = LookupResult::default();
    let mut mmdb_error;
    if gai_error == 0 {
        let addr = addr.unwrap();
        let mut e = MMDB_SUCCESS;
        result = mmdb_lookup_sockaddr(mmdb, addr, &mut e);
        mmdb_error = e;
    } else {
        // No MMDB error occurred; the GAI failure is reported via gai_error.
        mmdb_error = MMDB_SUCCESS;
    }
    (result, gai_error, mmdb_error)
}

/// `MMDB_read_node` — returns (node, status); the node carries left/right
/// records, their types and data entries.
#[derive(Debug, Clone, Default)]
pub struct SearchNode {
    pub left_record: u64,
    pub right_record: u64,
    pub left_record_type: u8,
    pub right_record_type: u8,
    pub left_record_offset: u32,
    pub right_record_offset: u32,
}

pub fn mmdb_read_node(mmdb: &Mmdb, node_number: u32) -> Result<SearchNode, i32> {
    let Some(ri) = record_info_for_database(mmdb) else {
        return Err(MMDB_UNKNOWN_DATABASE_FORMAT_ERROR);
    };
    if node_number >= mmdb.metadata.node_count {
        return Err(MMDB_INVALID_NODE_NUMBER_ERROR);
    }
    let search_tree_size = mmdb.metadata.node_count as usize * ri.record_length;
    let off = node_number as usize * ri.record_length;
    if off + ri.record_length > search_tree_size + MMDB_DATA_SECTION_SEPARATOR as usize {
        return Err(MMDB_CORRUPT_SEARCH_TREE_ERROR);
    }
    let rec = &mmdb.file_content[off..off + ri.record_length];
    let left_record = get_left_record(&ri, rec);
    let right_record = get_right_record(&ri, &rec[ri.right_record_offset..]);

    let node = SearchNode {
        left_record,
        right_record,
        left_record_type: record_type(mmdb, left_record),
        right_record_type: record_type(mmdb, right_record),
        left_record_offset: data_section_offset_for_record(mmdb, left_record),
        right_record_offset: data_section_offset_for_record(mmdb, right_record),
    };
    Ok(node)
}

// ---------------------------------------------------------------------------
// MMDB_open
// ---------------------------------------------------------------------------

/// `MMDB_open(filename, flags)` — error codes follow maxminddb.c map_file +
// find_metadata + read_metadata + the section-size checks.
pub fn mmdb_open(filename: &str, flags: u32) -> Result<Mmdb, i32> {
    let content = match std::fs::read(filename) {
        Ok(c) => c,
        Err(_) => return Err(MMDB_FILE_OPEN_ERROR),
    };
    let file_size = content.len();
    // map_file parity: the C mmaps the file; mmap(0 bytes) fails with EINVAL
    // on Linux, which the C reports as MMDB_IO_ERROR (not ENOMEM).  An empty
    // file therefore opens with IO_ERROR, not INVALID_METADATA (MMDB-0001).
    if file_size == 0 {
        return Err(MMDB_IO_ERROR);
    }
    if file_size > i64::MAX as usize {
        // C: size > SSIZE_MAX -> MMDB_OUT_OF_MEMORY_ERROR (map_file)
        return Err(MMDB_OUT_OF_MEMORY_ERROR);
    }

    let mut mmdb = Mmdb {
        flags: if flags & MMDB_MODE_MASK == 0 {
            flags | MMDB_MODE_MMAP
        } else {
            flags
        },
        filename: filename.to_string(),
        file_size,
        file_content: content,
        data_section: 0,
        data_section_size: 0,
        metadata_section: 0,
        metadata_section_size: 0,
        full_record_byte_size: 0,
        depth: 0,
        ipv4_start_node: (0, 0),
        metadata: Metadata {
            node_count: 0,
            record_size: 0,
            ip_version: 0,
            database_type: String::new(),
            languages: Vec::new(),
            binary_format_major_version: 0,
            binary_format_minor_version: 0,
            build_epoch: 0,
            descriptions: Vec::new(),
        },
    };

    let (meta_off, meta_size) = match find_metadata(&mmdb.file_content, file_size) {
        Some(v) => v,
        None => return Err(MMDB_INVALID_METADATA_ERROR),
    };
    mmdb.metadata_section = meta_off;
    mmdb.metadata_section_size = meta_size;

    let status = read_metadata(&mut mmdb);
    if status != MMDB_SUCCESS {
        return Err(status);
    }

    if mmdb.metadata.binary_format_major_version != 2 {
        return Err(MMDB_UNKNOWN_DATABASE_FORMAT_ERROR);
    }

    if !can_multiply(
        i64::MAX as u64,
        mmdb.metadata.node_count as u64,
        mmdb.full_record_byte_size as u64,
    ) {
        return Err(MMDB_INVALID_METADATA_ERROR);
    }
    let search_tree_size = mmdb.metadata.node_count as usize * mmdb.full_record_byte_size as usize;

    mmdb.data_section = search_tree_size + MMDB_DATA_SECTION_SEPARATOR as usize;
    if file_size < MMDB_DATA_SECTION_SEPARATOR as usize
        || search_tree_size > file_size - MMDB_DATA_SECTION_SEPARATOR as usize
    {
        return Err(MMDB_INVALID_METADATA_ERROR);
    }
    let data_section_size = file_size - search_tree_size - MMDB_DATA_SECTION_SEPARATOR as usize;
    if data_section_size > u32::MAX as usize || data_section_size == 0 {
        return Err(MMDB_INVALID_METADATA_ERROR);
    }
    mmdb.data_section_size = data_section_size as u32;

    // Although it is likely not possible to construct a database with valid
    // metadata and a data_section_size less than 3, we do this check as later
    // we assume it is at least three when doing bound checks.
    if mmdb.data_section_size < 3 {
        return Err(MMDB_INVALID_DATA_ERROR);
    }

    if mmdb.metadata.ip_version == 6 {
        let status = find_ipv4_start_node(&mut mmdb);
        if status != MMDB_SUCCESS {
            return Err(status);
        }
    }

    Ok(mmdb)
}

// ---------------------------------------------------------------------------
// Dump (maxminddb.c dump_entry_data_list, print_indentation, bytes_to_hex)
// ---------------------------------------------------------------------------

/// `MMDB_dump_entry_data_list` — byte-exact output into a String.  The C
/// writes to a FILE*; the caller decides the stream.
pub fn mmdb_dump_entry_data_list(out: &mut String, list: &[EntryData], indent: i32) -> i32 {
    let mut status = MMDB_SUCCESS;
    let mut idx = 0usize;
    dump_list(out, list, &mut idx, indent, &mut status);
    status
}

fn dump_list(out: &mut String, list: &[EntryData], idx: &mut usize, indent: i32, status: &mut i32) {
    if *idx >= list.len() {
        *status = MMDB_INVALID_DATA_ERROR;
        return;
    }
    let entry = &list[*idx];
    match entry.type_id {
        MMDB_DATA_TYPE_MAP => {
            let mut size = entry.data_size;
            print_indentation(out, indent);
            out.push_str("{\n");
            // the C does indent += 2 before the key loop, so keys are
            // printed at indent+2 and values at indent+4
            let mut i = *idx + 1;
            while size > 0 && i < list.len() {
                size -= 1;
                if list[i].type_id != MMDB_DATA_TYPE_UTF8_STRING {
                    *status = MMDB_INVALID_DATA_ERROR;
                    return;
                }
                let key = match &list[i].value {
                    EntryValue::Utf8String(b) => String::from_utf8_lossy(b).into_owned(),
                    _ => {
                        *status = MMDB_INVALID_DATA_ERROR;
                        return;
                    }
                };
                print_indentation(out, indent + 2);
                out.push('"');
                out.push_str(&key);
                out.push_str("\": \n");
                i += 1;
                // value at indent + 4
                let mut v = i;
                dump_list(out, list, &mut v, indent + 4, status);
                if *status != MMDB_SUCCESS {
                    return;
                }
                i = v;
            }
            print_indentation(out, indent);
            out.push_str("}\n");
            // the C advances via next pointers; our index must move past
            // every consumed node or the caller re-reads the header as a key
            *idx = i;
        }
        MMDB_DATA_TYPE_ARRAY => {
            let mut size = entry.data_size;
            print_indentation(out, indent);
            out.push_str("[\n");
            // the C bumps indent by 2 for the elements and restores it for
            // the closing bracket
            let mut i = *idx + 1;
            while size > 0 && i < list.len() {
                size -= 1;
                let mut v = i;
                dump_list(out, list, &mut v, indent + 2, status);
                if *status != MMDB_SUCCESS {
                    return;
                }
                i = v;
            }
            print_indentation(out, indent);
            out.push_str("]\n");
            *idx = i;
        }
        MMDB_DATA_TYPE_UTF8_STRING => {
            let s = match &entry.value {
                EntryValue::Utf8String(b) => String::from_utf8_lossy(b).into_owned(),
                _ => String::new(),
            };
            print_indentation(out, indent);
            out.push('"');
            out.push_str(&s);
            out.push_str("\" <utf8_string>\n");
            *idx += 1;
        }
        MMDB_DATA_TYPE_BYTES => {
            let hex = match &entry.value {
                EntryValue::Bytes(b) => bytes_to_hex(b),
                _ => String::new(),
            };
            print_indentation(out, indent);
            out.push_str(&hex);
            out.push_str(" <bytes>\n");
            *idx += 1;
        }
        MMDB_DATA_TYPE_DOUBLE => {
            print_indentation(out, indent);
            out.push_str(&format_printf_f64(match entry.value {
                EntryValue::Double(v) => v,
                _ => 0.0,
            }));
            out.push_str(" <double>\n");
            *idx += 1;
        }
        MMDB_DATA_TYPE_FLOAT => {
            print_indentation(out, indent);
            out.push_str(&format_printf_f64(match entry.value {
                EntryValue::Float(v) => v as f64,
                _ => 0.0,
            }));
            out.push_str(" <float>\n");
            *idx += 1;
        }
        MMDB_DATA_TYPE_UINT16 => {
            print_indentation(out, indent);
            let v = match entry.value {
                EntryValue::Uint16(v) => v,
                _ => 0,
            };
            out.push_str(&format!("{} <uint16>\n", v));
            *idx += 1;
        }
        MMDB_DATA_TYPE_UINT32 => {
            print_indentation(out, indent);
            let v = match entry.value {
                EntryValue::Uint32(v) => v,
                _ => 0,
            };
            out.push_str(&format!("{} <uint32>\n", v));
            *idx += 1;
        }
        MMDB_DATA_TYPE_BOOLEAN => {
            print_indentation(out, indent);
            let v = match entry.value {
                EntryValue::Boolean(v) => v,
                _ => false,
            };
            out.push_str(if v {
                "true <boolean>\n"
            } else {
                "false <boolean>\n"
            });
            *idx += 1;
        }
        MMDB_DATA_TYPE_UINT64 => {
            print_indentation(out, indent);
            let v = match entry.value {
                EntryValue::Uint64(v) => v,
                _ => 0,
            };
            out.push_str(&format!("{} <uint64>\n", v));
            *idx += 1;
        }
        MMDB_DATA_TYPE_UINT128 => {
            print_indentation(out, indent);
            // 0x%016PRIX64%016PRIX64 (uppercase)
            let v = match entry.value {
                EntryValue::Uint128(v) => v,
                _ => 0,
            };
            let high = (v >> 64) as u64;
            let low = v as u64;
            out.push_str(&format!("0x{:016X}{:016X} <uint128>\n", high, low));
            *idx += 1;
        }
        MMDB_DATA_TYPE_INT32 => {
            print_indentation(out, indent);
            let v = match entry.value {
                EntryValue::Int32(v) => v,
                _ => 0,
            };
            out.push_str(&format!("{} <int32>\n", v));
            *idx += 1;
        }
        _ => {
            *status = MMDB_INVALID_DATA_ERROR;
        }
    }
}

/// `print_indentation` — clamp to [0, 1023] spaces.
fn print_indentation(out: &mut String, i: i32) {
    let n = if i < 0 {
        0
    } else if i >= 1024 {
        1023
    } else {
        i as usize
    };
    for _ in 0..n {
        out.push(' ');
    }
}

/// `bytes_to_hex` — uppercase %02X per byte.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02X}"));
    }
    s
}

/// C `%f` rendering (6 decimals).  glibc prints NaN as "nan" and infinity as
/// "inf"/"-inf"; Rust's default differs for NaN, so match glibc exactly.
pub fn format_printf_f64(v: f64) -> String {
    if v.is_nan() {
        return "nan".to_string();
    }
    format!("{v:.6}")
}

/// Probe-side `render_value` (probe-maxminddb.c): the exact C rendering,
/// including the uint128 -> unsigned long long truncation of the C cast.
pub fn render_value(out: &mut String, d: &EntryData) {
    match d.type_id {
        MMDB_DATA_TYPE_UTF8_STRING => {
            if let EntryValue::Utf8String(b) = &d.value {
                out.push('"');
                out.push_str(&String::from_utf8_lossy(b));
                out.push('"');
            }
        }
        MMDB_DATA_TYPE_DOUBLE => {
            if let EntryValue::Double(v) = d.value {
                out.push_str(&format_printf_f64(v));
            }
        }
        MMDB_DATA_TYPE_BYTES => {
            if let EntryValue::Bytes(b) = &d.value {
                out.push_str(&bytes_to_hex(b));
            }
        }
        MMDB_DATA_TYPE_UINT16 => {
            if let EntryValue::Uint16(v) = d.value {
                out.push_str(&format!("{v}"));
            }
        }
        MMDB_DATA_TYPE_UINT32 => {
            if let EntryValue::Uint32(v) = d.value {
                out.push_str(&format!("{v}"));
            }
        }
        MMDB_DATA_TYPE_INT32 => {
            if let EntryValue::Int32(v) = d.value {
                out.push_str(&format!("{v}"));
            }
        }
        MMDB_DATA_TYPE_UINT64 => {
            if let EntryValue::Uint64(v) = d.value {
                out.push_str(&format!("{v}"));
            }
        }
        MMDB_DATA_TYPE_UINT128 => {
            if let EntryValue::Uint128(v) = d.value {
                out.push_str(&format!("{}", v as u64));
            }
        }
        MMDB_DATA_TYPE_BOOLEAN => {
            if let EntryValue::Boolean(v) = d.value {
                out.push_str(if v { "true" } else { "false" });
            }
        }
        MMDB_DATA_TYPE_FLOAT => {
            if let EntryValue::Float(v) = d.value {
                out.push_str(&format_printf_f64(v as f64));
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strerror_strings_match_c() {
        assert_eq!(mmdb_strerror(MMDB_SUCCESS), "Success (not an error)");
        assert_eq!(
            mmdb_strerror(MMDB_FILE_OPEN_ERROR),
            "Error opening the specified MaxMind DB file"
        );
        assert_eq!(
            mmdb_strerror(MMDB_CORRUPT_SEARCH_TREE_ERROR),
            "The MaxMind DB file's search tree is corrupt"
        );
        assert_eq!(
            mmdb_strerror(MMDB_INVALID_METADATA_ERROR),
            "The MaxMind DB file contains invalid metadata"
        );
        assert_eq!(
            mmdb_strerror(MMDB_UNKNOWN_DATABASE_FORMAT_ERROR),
            "The MaxMind DB file is in a format this library can't handle \
             (unknown record size or binary format version)"
        );
        assert_eq!(mmdb_strerror(999), "Unknown error code");
        assert_eq!(mmdb_lib_version(), "1.13.3");
    }

    #[test]
    fn integer_readers() {
        let p = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(get_uint32(&p), 0x1234_5678);
        assert_eq!(get_uint24(&p), 0x1234_56);
        assert_eq!(get_uint16(&p), 0x1234);
        assert_eq!(get_uintx(&p, 4), 0x1234_5678);
        assert_eq!(get_sintx(&[0xff, 0xff, 0xff, 0xfe], 4), -2);
    }

    #[test]
    fn ieee754_readers() {
        // 1.0 as big-endian f64/f32
        assert_eq!(get_ieee754_double(&[0x3f, 0xf0, 0, 0, 0, 0, 0, 0]), 1.0);
        assert_eq!(get_ieee754_float(&[0x3f, 0x80, 0, 0]), 1.0f32);
    }

    #[test]
    fn metadata_marker_search() {
        // marker in the last 128k; last occurrence wins
        let mut f = vec![0u8; 1000];
        let marker = b"\xab\xcd\xefMaxMind.com";
        let pos1 = 100usize;
        let pos2 = 200usize;
        f[pos1..pos1 + 14].copy_from_slice(marker);
        f[pos2..pos2 + 14].copy_from_slice(marker);
        f[pos2 + 14] = 0x99;
        f[pos2 + 15] = 0x88;
        let (off, size) = find_metadata(&f, f.len()).unwrap();
        assert_eq!(off, pos2 + 14);
        assert_eq!(size as usize, f.len() - off);
        // no marker
        assert!(find_metadata(&vec![0u8; 100], 100).is_none());
    }

    #[test]
    fn strtol10_semantics() {
        assert_eq!(strtol10("0").unwrap(), (0, 1));
        assert_eq!(strtol10("1").unwrap(), (1, 1));
        assert_eq!(strtol10("12x").unwrap(), (12, 2));
        assert_eq!(strtol10("-1").unwrap(), (-1, 2));
        assert_eq!(strtol10("+3").unwrap(), (3, 2));
        assert_eq!(strtol10(" 4").unwrap(), (4, 2));
        // overflow -> ERANGE
        assert!(strtol10("999999999999999999999999").is_err());
        // no digits: first_invalid at the start
        assert_eq!(strtol10("x").unwrap(), (0, 0));
        assert_eq!(strtol10("").unwrap(), (0, 0));
    }

    #[test]
    fn strict_ipv4() {
        assert_eq!(parse_inet_pton4("1.2.3.4").unwrap().to_string(), "1.2.3.4");
        assert_eq!(parse_inet_pton4("0.0.0.0").unwrap().to_string(), "0.0.0.0");
        assert_eq!(
            parse_inet_pton4("255.255.255.255").unwrap().to_string(),
            "255.255.255.255"
        );
        // leading zeros rejected (inet_pton)
        assert!(parse_inet_pton4("01.2.3.4").is_none());
        assert!(parse_inet_pton4("1.2.3.4.5").is_none());
        assert!(parse_inet_pton4("1.2.3").is_none());
        assert!(parse_inet_pton4("256.1.1.1").is_none());
        assert!(parse_inet_pton4("1.2.3.x").is_none());
        assert!(parse_inet_pton4("").is_none());
    }

    #[test]
    fn strict_ipv6() {
        assert_eq!(parse_inet_pton("::").unwrap().to_string(), "::");
        assert_eq!(parse_inet_pton("::1").unwrap().to_string(), "::1");
        assert_eq!(
            parse_inet_pton("2001:db8::1").unwrap().to_string(),
            "2001:db8::1"
        );
        assert_eq!(
            parse_inet_pton("::ffff:1.2.3.4").unwrap().to_string(),
            "::ffff:1.2.3.4"
        );
        assert_eq!(
            parse_inet_pton("1:2:3:4:5:6:7:8").unwrap().to_string(),
            "1:2:3:4:5:6:7:8"
        );
        assert_eq!(
            parse_inet_pton("fe80::1%lo").unwrap().to_string(),
            "fe80::1"
        );
        // empty and unknown zones rejected (glibc zone handling)
        assert!(parse_inet_pton("fe80::1%").is_none());
        assert!(parse_inet_pton("fe80::1%nonexistentzz").is_none());
        // double :: rejected
        assert!(parse_inet_pton("1::2::3").is_none());
        // too many groups
        assert!(parse_inet_pton("1:2:3:4:5:6:7:8:9").is_none());
        // leading single colon
        assert!(parse_inet_pton(":1").is_none());
        // trailing single colon without ::
        assert!(parse_inet_pton("1:2:3:4:5:6:7:").is_none());
        // bad hex
        assert!(parse_inet_pton("1:2:3:4:5:6:7:g").is_none());
        // overflow group
        assert!(parse_inet_pton("10000::1").is_none());
        // embedded v4 must be strict
        assert!(parse_inet_pton("::ffff:1.2.3.256").is_none());
    }

    #[test]
    fn inet_aton_fallback_vectors() {
        // pinned against glibc 2.36 getaddrinfo AI_NUMERICHOST (MMDB-0001)
        let ok = [
            ("1.2.3", [1, 2, 0, 3]),
            ("01.2.3.4", [1, 2, 3, 4]),
            ("0x7f.1", [127, 0, 0, 1]),
            ("010.0.0.1", [8, 0, 0, 1]),
            ("0x7f.0.0.1", [127, 0, 0, 1]),
            ("4294967295", [255, 255, 255, 255]),
            ("0xffffffff", [255, 255, 255, 255]),
            ("0x1f.0x1", [31, 0, 0, 1]),
            ("0377.0.0.1", [255, 0, 0, 1]),
            ("0", [0, 0, 0, 0]),
            ("0x0", [0, 0, 0, 0]),
            ("1.2.3.4", [1, 2, 3, 4]),
        ];
        for (s, want) in ok {
            let got = parse_inet_aton_exact(s).unwrap();
            assert_eq!(got, want, "{s}");
        }
        let bad = [
            "not an ip",
            "",
            "1.2.3.4.5",
            "256.1.1.1",
            "1.2.3.x",
            "1.2.3.4.5.6",
            "1.2.3.4 ",
            "1.2.3.4. ",
            "09.0.0.1",
            "0x.1",
            "1..2",
            ".1.2.3",
            "1.2.3.",
            "4294967296",
            "1.2.3.256",
            "0x100000000",
            "1.2.3.4 xyz",
            "1.2.3.4\t",
            " 1.2.3.4",
            "+1.2.3.4",
            "1.2.3.4garbage",
        ];
        for s in bad {
            assert!(parse_inet_aton_exact(s).is_none(), "{s}");
        }
    }

    #[test]
    fn format_printf() {
        assert_eq!(format_printf_f64(1.5), "1.500000");
        assert_eq!(format_printf_f64(0.1), "0.100000");
        assert_eq!(format_printf_f64(-0.0), "-0.000000");
        assert_eq!(format_printf_f64(f64::NAN), "nan");
        assert_eq!(format_printf_f64(f64::INFINITY), "inf");
    }

    #[test]
    fn dump_format_quirks() {
        // Map keys sit at the map's indent+2 and values at indent+4; the key
        // line ends with ": " (trailing space).  These quirks are conserved
        // from maxminddb.c dump_entry_data_list.
        let mut out = String::new();
        let list = vec![
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 1,
                type_id: MMDB_DATA_TYPE_MAP,
                value: EntryValue::Container,
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 2,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"en".to_vec()),
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 2,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"UK".to_vec()),
            },
        ];
        let status = mmdb_dump_entry_data_list(&mut out, &list, 0);
        assert_eq!(status, MMDB_SUCCESS);
        assert_eq!(out, "{\n  \"en\": \n    \"UK\" <utf8_string>\n}\n");
    }

    #[test]
    fn dump_array_indent_and_index_advance() {
        // Regression (MMDB-0001): array elements are indented indent+2 (the
        // C bumps indent inside the array case), and the caller index must
        // advance past every consumed node — the earlier port left it at the
        // container header, so the outer map re-read it as a key and dumped
        // INVALID_DATA right after the first compound value.
        let mut out = String::new();
        let list = vec![
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 2,
                type_id: MMDB_DATA_TYPE_MAP,
                value: EntryValue::Container,
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 3,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"arr".to_vec()),
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 2,
                type_id: MMDB_DATA_TYPE_ARRAY,
                value: EntryValue::Container,
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 1,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"a".to_vec()),
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 1,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"b".to_vec()),
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 2,
                type_id: MMDB_DATA_TYPE_UTF8_STRING,
                value: EntryValue::Utf8String(b"after".to_vec()),
            },
            EntryData {
                has_data: true,
                offset: 0,
                offset_to_next: 0,
                data_size: 1,
                type_id: MMDB_DATA_TYPE_UINT16,
                value: EntryValue::Uint16(7),
            },
        ];
        let status = mmdb_dump_entry_data_list(&mut out, &list, 0);
        assert_eq!(status, MMDB_SUCCESS);
        assert_eq!(
            out,
            "{\n  \"arr\": \n    [\n      \"a\" <utf8_string>\n      \"b\" <utf8_string>\n    ]\n  \"after\": \n    7 <uint16>\n}\n"
        );
    }
}

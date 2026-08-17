//! `protobuf-c-probe` — Rust mirror of `forensics/oracle/probes/probe-protobuf-c.c`
//! for the PBC-0001 court (§26, §38).
//!
//! Drives the same descriptor corpus as the C oracle probe: the checked-in
//! protoc-gen-c 1.5.2 fixtures (`protobuf_c_gen.rs`, generated from the
//! pinned tarball's t/test-full.proto + t/test-proto3.proto).  Every section
//! of the C probe is mirrored; stdout must be byte-identical.
//!
//! Runs inside the same oracle-protobuf-c-1.5.2 container as the C probe.

mod protobuf_c_gen;

use std::mem::size_of;

use bind9_rs_tools::compat::protobuf_c as pbc;
use bind9_rs_tools::compat::protobuf_c::{
    message_check, message_get_packed_size, message_init, message_pack, message_pack_to_buffer,
    message_unpack, service_destroy, service_generated_init, BufferSimple, Closure,
    CountingAllocator, Field, IntRange, Message, MessageDescriptor, NullAllocator, Service, Value,
    FALSE, LABEL_OPTIONAL, TRUE, TYPE_BOOL, TYPE_BYTES, TYPE_INT32, TYPE_INT64, TYPE_MESSAGE,
    TYPE_STRING,
};
use protobuf_c_gen::all;

// ---------------------------------------------------------------------------
// deterministic printers
// ---------------------------------------------------------------------------

fn section(name: &str) {
    println!("--- {name} ---");
}

fn hexout(d: &[u8]) {
    print!("hex:");
    for b in d {
        print!(" {b:02x}");
    }
    println!();
}

fn strout(s: Option<&str>) {
    print!("str:");
    match s {
        None => {
            println!(" (null)");
            return;
        }
        Some(s) => {
            for &b in s.as_bytes() {
                match b {
                    b'\n' => print!("\\n"),
                    b'\t' => print!("\\t"),
                    b'\r' => print!("\\r"),
                    b'\\' => print!("\\\\"),
                    b'"' => print!("\\\""),
                    0x20..=0x7e => print!("{}", b as char),
                    _ => print!("\\x{b:02x}"),
                }
            }
            println!(" (len={})", s.len());
        }
    }
}

fn repack_check(m: &Message, size: usize, packed: &[u8]) {
    let size2 = message_get_packed_size(m);
    let out = message_pack(m);
    println!(
        "repack size={size2} wrote={} match={}",
        out.len(),
        if out.len() == size && out == packed {
            "yes"
        } else {
            "NO"
        }
    );
}

fn roundtrip(m: &Message) {
    let size = message_get_packed_size(m);
    let packed = message_pack(m);
    println!("size={size} wrote={}", packed.len());
    hexout(&packed);
    repack_check(m, size, &packed);
}

// ---------------------------------------------------------------------------
// field setters
// ---------------------------------------------------------------------------

fn s_i32(m: &mut Message, i: usize, has: bool, v: i32) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::I32(v),
    };
}
fn s_u32(m: &mut Message, i: usize, has: bool, v: u32) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::U32(v),
    };
}
fn s_i64(m: &mut Message, i: usize, has: bool, v: i64) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::I64(v),
    };
}
fn s_u64(m: &mut Message, i: usize, has: bool, v: u64) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::U64(v),
    };
}
fn s_f32(m: &mut Message, i: usize, has: bool, bits: u32) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::F32(bits),
    };
}
fn s_f64(m: &mut Message, i: usize, has: bool, bits: u64) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::F64(bits),
    };
}
fn s_bool(m: &mut Message, i: usize, has: bool, v: i32) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::Bool(v),
    };
}
fn s_enum(m: &mut Message, i: usize, has: bool, v: i32) {
    m.fields[i] = Field::Scalar {
        has: if has { TRUE } else { FALSE },
        value: Value::Enum(v),
    };
}
fn p_str(m: &mut Message, i: usize, v: &str) {
    m.fields[i] = Field::Pointer {
        has: FALSE,
        value: Some(Value::Str(v.to_string())),
    };
}
fn p_bin(m: &mut Message, i: usize, has: bool, v: Vec<u8>) {
    m.fields[i] = Field::Pointer {
        has: if has { TRUE } else { FALSE },
        value: Some(Value::Bin(pbc::BinValue {
            len: v.len(),
            data: Some(v),
        })),
    };
}
fn p_msg(m: &mut Message, i: usize, v: Message) {
    m.fields[i] = Field::Pointer {
        has: FALSE,
        value: Some(Value::Msg(Box::new(v))),
    };
}
fn rp(m: &mut Message, i: usize, v: Vec<Value>) {
    m.fields[i] = Field::Repeated(v);
}
/// Set a oneof member, clearing the other members of the same oneof first
/// (the C stores all members in one union with a single case field).
fn o_set(m: &mut Message, i: usize, case: u32, v: Value) {
    for j in 0..18 {
        m.fields[j] = Field::Oneof {
            case: 0,
            value: None,
        };
    }
    m.fields[i] = Field::Oneof {
        case,
        value: Some(v),
    };
}

// ---------------------------------------------------------------------------
// fixed corpora (identical constants in the C probe)
// ---------------------------------------------------------------------------

const PACK_I32: [i32; 24] = [
    0,
    -1,
    1,
    127,
    128,
    16383,
    16384,
    2097151,
    2097152,
    -2147483647,
    2147483647,
    -123456789,
    42,
    -42,
    300,
    -300,
    70000,
    -70000,
    5,
    -5,
    6,
    7,
    8,
    -8,
];
const PACK_SI32: [i32; 24] = [
    0,
    -1,
    1,
    127,
    128,
    16383,
    16384,
    2097151,
    2097152,
    -2147483648,
    2147483647,
    -123456789,
    42,
    -42,
    300,
    -300,
    70000,
    -70000,
    5,
    -5,
    6,
    7,
    8,
    -8,
];
const PACK_SF32: [i32; 24] = [
    -1,
    0,
    1,
    127,
    128,
    16383,
    16384,
    2097151,
    2097152,
    -2147483648,
    2147483647,
    -123456789,
    42,
    -42,
    300,
    -300,
    70000,
    -70000,
    5,
    -5,
    6,
    7,
    8,
    -8,
];
const PACK_I64: [i64; 24] = [
    0,
    -1,
    1,
    127,
    128,
    16383,
    16384,
    2097151,
    2097152,
    268435455,
    268435456,
    4294967295,
    4294967296,
    1099511627775,
    1099511627776,
    281474976710655,
    281474976710656,
    72057594037927935,
    72057594037927936,
    -9223372036854775807,
    9223372036854775807,
    -1234567890123,
    42,
    -8,
];
const PACK_SI64: [i64; 24] = PACK_I64;
const PACK_SF64: [i64; 24] = PACK_I64;
const PACK_U32: [u32; 24] = [
    0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 4294967295, 300, 70000,
    42, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
];
const PACK_FX32: [u32; 24] = PACK_U32;
const PACK_U64: [u64; 24] = [
    0,
    1,
    127,
    128,
    16383,
    16384,
    2097151,
    2097152,
    268435455,
    268435456,
    4294967295,
    4294967296,
    1099511627775,
    1099511627776,
    281474976710655,
    281474976710656,
    72057594037927935,
    72057594037927936,
    18446744073709551615,
    300,
    42,
    5,
    6,
    7,
];
const PACK_FX64: [u64; 24] = PACK_U64;
const PACK_FL: [u32; 24] = [
    0x00000000, 0x3f800000, 0x40490fdb, 0x7f800000, 0xff800000, 0x3fc00000, 0xbf800000, 0x00000001,
    0x3eaaaaab, 0x3f000000, 0x40000000, 0x40490fdb, 0x41200000, 0x42c80000, 0x477fff00, 0x3f000000,
    0x3f800000, 0x3dcccccd, 0x3d8f5c29, 0x3ba3d70a, 0x00000000, 0x00000000, 0x80000000, 0x3f000000,
];
const PACK_DB: [u64; 24] = [
    0x0000000000000000,
    0x3ff0000000000000,
    0x400921fb54442d18,
    0x7ff0000000000000,
    0xfff0000000000000,
    0x3ff8000000000000,
    0xbff0000000000000,
    0x0000000000000001,
    0x3fd5555555555555,
    0x3fe0000000000000,
    0x4000000000000000,
    0x400921fb54442d18,
    0x4024000000000000,
    0x4059000000000000,
    0x40efffe000000000,
    0x3fe0000000000000,
    0x3ff0000000000000,
    0x3fb999999999999a,
    0x3fb1eb851eb851ec,
    0x3f747ae147ae147b,
    0x0000000000000000,
    0x0000000000000000,
    0x8000000000000000,
    0x3fe0000000000000,
];
const PACK_BOOL: [i32; 24] = [
    1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1,
];
const PACK_ESM: [i32; 24] = [
    -1, 0, 1, 0, 1, -1, 1, 0, 1, 0, -1, 1, 0, 1, 0, -1, 1, 0, 1, -1, 0, 1, 0, 1,
];
const PACK_EN: [i32; 24] = [
    -123456, -1, 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 0, 1, 127,
    128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, -1, -123456,
];

fn pack_i32s() -> Vec<Value> {
    PACK_I32.iter().map(|&v| Value::I32(v)).collect()
}
fn pack_si32s() -> Vec<Value> {
    PACK_SI32.iter().map(|&v| Value::I32(v)).collect()
}
fn pack_sf32s() -> Vec<Value> {
    PACK_SF32.iter().map(|&v| Value::I32(v)).collect()
}
fn pack_i64s() -> Vec<Value> {
    PACK_I64.iter().map(|&v| Value::I64(v)).collect()
}
fn pack_si64s() -> Vec<Value> {
    PACK_SI64.iter().map(|&v| Value::I64(v)).collect()
}
fn pack_sf64s() -> Vec<Value> {
    PACK_SF64.iter().map(|&v| Value::I64(v)).collect()
}
fn pack_u32s() -> Vec<Value> {
    PACK_U32.iter().map(|&v| Value::U32(v)).collect()
}
fn pack_fx32s() -> Vec<Value> {
    PACK_FX32.iter().map(|&v| Value::U32(v)).collect()
}
fn pack_u64s() -> Vec<Value> {
    PACK_U64.iter().map(|&v| Value::U64(v)).collect()
}
fn pack_fx64s() -> Vec<Value> {
    PACK_FX64.iter().map(|&v| Value::U64(v)).collect()
}
fn pack_fls() -> Vec<Value> {
    PACK_FL.iter().map(|&v| Value::F32(v)).collect()
}
fn pack_dbs() -> Vec<Value> {
    PACK_DB.iter().map(|&v| Value::F64(v)).collect()
}
fn pack_bools() -> Vec<Value> {
    PACK_BOOL.iter().map(|&v| Value::Bool(v)).collect()
}
fn pack_esms() -> Vec<Value> {
    PACK_ESM.iter().map(|&v| Value::Enum(v)).collect()
}
fn pack_ens() -> Vec<Value> {
    PACK_EN.iter().map(|&v| Value::Enum(v)).collect()
}

fn fill_packed(m: &mut Message) {
    rp(m, 0, pack_i32s());
    rp(m, 1, pack_si32s());
    rp(m, 2, pack_sf32s());
    rp(m, 3, pack_i64s());
    rp(m, 4, pack_si64s());
    rp(m, 5, pack_sf64s());
    rp(m, 6, pack_u32s());
    rp(m, 7, pack_fx32s());
    rp(m, 8, pack_u64s());
    rp(m, 9, pack_fx64s());
    rp(m, 10, pack_fls());
    rp(m, 11, pack_dbs());
    rp(m, 12, pack_bools());
    rp(m, 13, pack_esms());
    rp(m, 14, pack_ens());
}

fn print_i32_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        match v {
            Value::I32(x) => print!("{x}"),
            // sfixed32/float storage read back as the bit pattern
            Value::U32(x) | Value::F32(x) => print!("{}", *x as i32),
            Value::Enum(x) => print!("{x}"),
            Value::Bool(x) => print!("{x}"),
            _ => {}
        }
    }
    println!("]");
}

fn print_i64_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        match v {
            Value::I64(x) => print!("{x}"),
            // sfixed64/double storage read back as the bit pattern
            Value::U64(x) | Value::F64(x) => print!("{}", *x as i64),
            _ => {}
        }
    }
    println!("]");
}

fn print_u32_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        if let Value::U32(x) = v {
            print!("{x}");
        }
    }
    println!("]");
}

fn print_u64_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        match v {
            Value::U64(x) => print!("{x}"),
            // int64 storage read back as the bit pattern
            Value::I64(x) => print!("{}", *x as u64),
            _ => {}
        }
    }
    println!("]");
}

fn print_f32_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        match v {
            Value::F32(x) => print!("0x{x:08x}"),
            Value::U32(x) => print!("0x{x:08x}"),
            _ => {}
        }
    }
    println!("]");
}

fn print_f64_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        match v {
            Value::F64(x) => print!("0x{x:016x}"),
            Value::U64(x) => print!("0x{x:016x}"),
            _ => {}
        }
    }
    println!("]");
}

fn print_bool_list(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        if let Value::Bool(x) = v {
            print!("{x}");
        }
    }
    println!("]");
}

fn print_i32_plain(values: &[Value]) {
    print!("[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            print!(", ");
        }
        if let Value::I32(x) | Value::Enum(x) = v {
            print!("{x}");
        }
    }
    println!("]");
}

// ---------------------------------------------------------------------------
// sections
// ---------------------------------------------------------------------------

fn test_version() {
    section("version");
    println!("version: {}", pbc::version());
    println!("version_number: {}", pbc::version_number());
}

fn test_sizes() {
    section("sizes");
    let mut sizes = std::collections::HashMap::new();
    for (k, v) in protobuf_c_gen::SIZES {
        sizes.insert(*k, *v);
    }
    let s = |k: &str| sizes[k];
    println!("TestMessPacked={}", s("TestMessPacked"));
    println!("TestMess={}", s("TestMess"));
    println!("TestMessOptional={}", s("TestMessOptional"));
    println!("TestMessOneof={}", s("TestMessOneof"));
    println!("SubMess={}", s("SubMess"));
    println!("SubSubMess={}", s("SubMess__SubSubMess"));
    println!("TestMessageCheck={}", s("TestMessageCheck"));
    println!("CheckSub={}", s("TestMessageCheck__SubMessage"));
    println!("DefaultRequiredValues={}", s("DefaultRequiredValues"));
    println!("DefaultOptionalValues={}", s("DefaultOptionalValues"));
    println!("TestRequiredFieldsBitmap={}", s("TestRequiredFieldsBitmap"));
    println!("TestMessSubMess={}", s("TestMessSubMess"));
    println!("EmptyMess={}", s("EmptyMess"));
    println!("proto3 Person={}", s("Person"));
    println!("proto3 PhoneNumber={}", s("Person__PhoneNumber"));
    println!("proto3 Comment={}", s("Person__PhoneNumber__Comment"));
    println!("proto3 Name={}", s("Name"));
    println!("proto3 LookupResult={}", s("LookupResult"));
    let a = all();
    println!(
        "desc TestMessPacked sizeof_message={}",
        a.test_mess_packed.sizeof_message
    );
    println!(
        "desc TestMessOneof sizeof_message={}",
        a.test_mess_oneof.sizeof_message
    );
    println!(
        "desc proto3 Person sizeof_message={}",
        a.p3_person.sizeof_message
    );
}

fn test_packed_battery() {
    section("packed");
    let a = all();
    let mut m = message_init(a.test_mess_packed);
    fill_packed(&mut m);

    let size = message_get_packed_size(&m);
    let packed = message_pack(&m);
    println!("size={size} wrote={}", packed.len());
    hexout(&packed);

    let mut alloc = NullAllocator;
    let u = message_unpack(a.test_mess_packed, &mut alloc, packed.len(), &packed);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    if let Some(u) = u {
        let f = |i: usize| -> &Vec<Value> {
            if let Field::Repeated(v) = &u.fields[i] {
                v
            } else {
                unreachable!()
            }
        };
        print!("int32 n={} ", f(0).len());
        print_i32_list(f(0));
        print!("sint32 n={} ", f(1).len());
        print_i32_list(f(1));
        print!("sfixed32 n={} ", f(2).len());
        print_i32_list(f(2));
        print!("int64 n={} ", f(3).len());
        print_i64_list(f(3));
        print!("sint64 n={} ", f(4).len());
        print_i64_list(f(4));
        print!("sfixed64 n={} ", f(5).len());
        print_i64_list(f(5));
        print!("uint32 n={} ", f(6).len());
        print_u32_list(f(6));
        print!("fixed32 n={} ", f(7).len());
        print_u32_list(f(7));
        print!("uint64 n={} ", f(8).len());
        print_u64_list(f(8));
        print!("fixed64 n={} ", f(9).len());
        print_u64_list(f(9));
        print!("float n={} ", f(10).len());
        print_f32_list(f(10));
        print!("double n={} ", f(11).len());
        print_f64_list(f(11));
        print!("bool n={} ", f(12).len());
        print_bool_list(f(12));
        print!("enum_small n={} ", f(13).len());
        print_i32_plain(f(13));
        print!("enum n={} ", f(14).len());
        print_i32_plain(f(14));

        let r2 = message_get_packed_size(&u);
        let rp = message_pack(&u);
        println!(
            "repack size={r2} match={}",
            if rp.len() == packed.len() && rp == packed {
                "yes"
            } else {
                "NO"
            }
        );
    }
}

fn test_repeated_battery() {
    section("repeated");
    let a = all();
    let mut sub1 = message_init(a.sub_mess);
    s_i32(&mut sub1, 0, false, 5);
    let mut sub2 = message_init(a.sub_mess);
    s_i32(&mut sub2, 0, false, -9);
    s_i32(&mut sub2, 1, true, 77);

    let mut m = message_init(a.test_mess);
    rp(
        &mut m,
        0,
        vec![Value::I32(1), Value::I32(-1), Value::I32(300)],
    );
    rp(
        &mut m,
        1,
        vec![Value::I32(1), Value::I32(-1), Value::I32(300)],
    );
    rp(
        &mut m,
        2,
        vec![Value::I32(1), Value::I32(-1), Value::I32(300)],
    );
    rp(
        &mut m,
        3,
        vec![Value::I64(1), Value::I64(-1), Value::I64(4294967296)],
    );
    rp(
        &mut m,
        4,
        vec![Value::I64(1), Value::I64(-1), Value::I64(4294967296)],
    );
    rp(
        &mut m,
        5,
        vec![Value::I64(1), Value::I64(-1), Value::I64(4294967296)],
    );
    rp(
        &mut m,
        6,
        vec![Value::U32(1), Value::U32(300), Value::U32(4294967295)],
    );
    rp(
        &mut m,
        7,
        vec![Value::U32(1), Value::U32(300), Value::U32(4294967295)],
    );
    rp(
        &mut m,
        8,
        vec![
            Value::U64(1),
            Value::U64(300),
            Value::U64(18446744073709551615),
        ],
    );
    rp(
        &mut m,
        9,
        vec![
            Value::U64(1),
            Value::U64(300),
            Value::U64(18446744073709551615),
        ],
    );
    rp(
        &mut m,
        10,
        vec![
            Value::F32(0x3f800000),
            Value::F32(0x40000000),
            Value::F32(0x40490fdb),
        ],
    );
    rp(
        &mut m,
        11,
        vec![
            Value::F64(0x3ff0000000000000),
            Value::F64(0x4000000000000000),
            Value::F64(0x400921fb54442d18),
        ],
    );
    rp(
        &mut m,
        12,
        vec![Value::Bool(1), Value::Bool(0), Value::Bool(1)],
    );
    rp(
        &mut m,
        13,
        vec![Value::Enum(-1), Value::Enum(0), Value::Enum(1)],
    );
    rp(
        &mut m,
        14,
        vec![Value::Enum(-123456), Value::Enum(0), Value::Enum(268435456)],
    );
    rp(
        &mut m,
        15,
        vec![
            Value::Str("abc".into()),
            Value::Str(String::new()),
            Value::Str("hello world".into()),
        ],
    );
    rp(
        &mut m,
        16,
        vec![
            Value::Bin(pbc::BinValue::new(b"abc".to_vec())),
            Value::Bin(pbc::BinValue::empty()),
            Value::Bin(pbc::BinValue::new(b"hello".to_vec())),
        ],
    );
    rp(
        &mut m,
        17,
        vec![Value::Msg(Box::new(sub1)), Value::Msg(Box::new(sub2))],
    );

    let size = message_get_packed_size(&m);
    let packed = message_pack(&m);
    println!("size={size} wrote={}", packed.len());
    hexout(&packed);

    let mut alloc = NullAllocator;
    let u = message_unpack(a.test_mess, &mut alloc, packed.len(), &packed);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    if let Some(u) = u {
        let f = |i: usize| -> &Vec<Value> {
            if let Field::Repeated(v) = &u.fields[i] {
                v
            } else {
                unreachable!()
            }
        };
        print!("int32 ");
        print_i32_list(f(0));
        print!("sint32 ");
        print_i32_list(f(1));
        print!("sfixed32 ");
        print_i32_list(f(2));
        print!("int64 ");
        print_i64_list(f(3));
        print!("sint64 ");
        print_i64_list(f(4));
        print!("sfixed64 ");
        print_i64_list(f(5));
        print!("uint32 ");
        print_u32_list(f(6));
        print!("fixed32 ");
        print_u32_list(f(7));
        print!("uint64 ");
        print_u64_list(f(8));
        print!("fixed64 ");
        print_u64_list(f(9));
        print!("float ");
        print_f32_list(f(10));
        print!("double ");
        print_f64_list(f(11));
        print!("bool ");
        print_bool_list(f(12));
        print!("enum_small ");
        print_i32_plain(f(13));
        print!("enum ");
        print_i32_plain(f(14));
        println!("string n={}", f(15).len());
        for (i, v) in f(15).iter().enumerate() {
            print!("  [{i}] ");
            if let Value::Str(s) = v {
                strout(Some(s));
            }
        }
        println!("bytes n={}", f(16).len());
        for (i, v) in f(16).iter().enumerate() {
            if let Value::Bin(b) = v {
                print!("  [{i}] len={} ", b.len);
                hexout(b.data.as_deref().unwrap_or(&[]));
            }
        }
        println!("message n={}", f(17).len());
        for (i, v) in f(17).iter().enumerate() {
            if let Value::Msg(sm) = v {
                let test = if let Field::Scalar {
                    value: Value::I32(t),
                    ..
                } = &sm.fields[0]
                {
                    *t
                } else {
                    0
                };
                let has_val1 = if let Field::Scalar { has, .. } = &sm.fields[1] {
                    *has
                } else {
                    0
                };
                let val1 = if let Field::Scalar {
                    value: Value::I32(vv),
                    ..
                } = &sm.fields[1]
                {
                    *vv
                } else {
                    0
                };
                println!("  [{i}] test={test} has_val1={has_val1} val1={val1}");
            }
        }
    }
}

fn test_optional_battery() {
    section("optional");
    let a = all();
    let mut sub = message_init(a.sub_mess);
    s_i32(&mut sub, 0, false, 42);
    s_i32(&mut sub, 1, true, 9);

    let mut m = message_init(a.test_mess_optional);
    s_i32(&mut m, 0, true, -5);
    s_i32(&mut m, 1, true, -5);
    s_i32(&mut m, 2, true, -5);
    s_i64(&mut m, 3, true, -1234567890123);
    s_i64(&mut m, 4, true, -1234567890123);
    s_i64(&mut m, 5, true, -1234567890123);
    s_u32(&mut m, 6, true, 4294967295);
    s_u32(&mut m, 7, true, 4294967295);
    s_u64(&mut m, 8, true, 18446744073709551615);
    s_u64(&mut m, 9, true, 18446744073709551615);
    s_f32(&mut m, 10, true, PACK_FL[2]);
    s_f64(&mut m, 11, true, PACK_DB[2]);
    s_bool(&mut m, 12, true, 1);
    s_enum(&mut m, 13, true, -1);
    s_enum(&mut m, 14, true, 268435456);
    p_str(&mut m, 15, "optional str");
    p_bin(&mut m, 16, true, b"opts!".to_vec());
    p_msg(&mut m, 17, sub);

    roundtrip(&m);

    let mut alloc = NullAllocator;
    let size = message_get_packed_size(&m);
    let packed = message_pack(&m);
    let u = message_unpack(a.test_mess_optional, &mut alloc, size, &packed);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    if let Some(u) = u {
        let sc = |i: usize| -> (i32, Value) {
            if let Field::Scalar { has, value } = &u.fields[i] {
                (*has, value.clone())
            } else {
                unreachable!()
            }
        };
        for (i, name) in [
            "int32", "sint32", "sfixed32", "int64", "sint64", "sfixed64", "uint32", "fixed32",
            "uint64", "fixed64",
        ]
        .iter()
        .enumerate()
        {
            let (has, v) = sc(i);
            match &v {
                Value::I32(x) => println!("{name} has={has} val={x}"),
                Value::U32(x) => {
                    // sfixed32 storage reads back as int32 (the C's %d)
                    if i == 2 {
                        println!("{name} has={has} val={}", *x as i32);
                    } else {
                        println!("{name} has={has} val={x}");
                    }
                }
                Value::I64(x) => {
                    // uint64 storage reads back unsigned (the C's PRIu64)
                    if i == 8 {
                        println!("{name} has={has} val={}", *x as u64);
                    } else {
                        println!("{name} has={has} val={x}");
                    }
                }
                Value::U64(x) => {
                    // sfixed64 storage reads back signed (the C's PRId64)
                    if i == 5 {
                        println!("{name} has={has} val={}", *x as i64);
                    } else {
                        println!("{name} has={has} val={x}");
                    }
                }
                _ => unreachable!(),
            }
        }
        {
            let (has, v) = sc(10);
            match v {
                Value::F32(x) => println!("float has={has} val=0x{x:08x}"),
                Value::U32(x) => println!("float has={has} val=0x{x:08x}"),
                _ => unreachable!(),
            }
        }
        {
            let (has, v) = sc(11);
            match v {
                Value::F64(x) => println!("double has={has} val=0x{x:016x}"),
                Value::U64(x) => println!("double has={has} val=0x{x:016x}"),
                _ => unreachable!(),
            }
        }
        {
            let (has, v) = sc(12);
            if let Value::Bool(x) = v {
                println!("bool has={has} val={x}");
            }
        }
        {
            let (has, v) = sc(13);
            match v {
                Value::Enum(x) => println!("enum_small has={has} val={x}"),
                Value::I32(x) => println!("enum_small has={has} val={x}"),
                _ => unreachable!(),
            }
        }
        {
            let (has, v) = sc(14);
            match v {
                Value::Enum(x) => println!("enum has={has} val={x}"),
                Value::I32(x) => println!("enum has={has} val={x}"),
                _ => unreachable!(),
            }
        }
        if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &u.fields[15]
        {
            print!("string ");
            strout(Some(s));
        }
        if let Field::Pointer {
            has,
            value: Some(Value::Bin(b)),
            ..
        } = &u.fields[16]
        {
            print!("bytes has={has} len={} ", b.len);
            hexout(b.data.as_deref().unwrap_or(&[]));
        }
        if let Field::Pointer {
            value: Some(Value::Msg(sm)),
            ..
        } = &u.fields[17]
        {
            let test = if let Field::Scalar {
                value: Value::I32(t),
                ..
            } = &sm.fields[0]
            {
                *t
            } else {
                -999
            };
            let has_val1 = if let Field::Scalar { has, .. } = &sm.fields[1] {
                *has
            } else {
                -1
            };
            let val1 = if let Field::Scalar {
                value: Value::I32(vv),
                ..
            } = &sm.fields[1]
            {
                *vv
            } else {
                -999
            };
            println!("message test={test} has_val1={has_val1} val1={val1}");
        }
    }

    let fresh = message_init(a.test_mess_optional);
    println!("unset size={}", message_get_packed_size(&fresh));
    let e = message_pack(&fresh);
    println!("unset pack={}", e.len());
}

fn test_oneof_battery() {
    section("oneof");
    let a = all();
    let mut sub = message_init(a.sub_mess);
    s_i32(&mut sub, 0, false, 3);

    let mut m = message_init(a.test_mess_oneof);
    println!("none size={}", message_get_packed_size(&m));

    o_set(&mut m, 0, 1, Value::I32(42));
    roundtrip(&m);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&m);
        let packed = message_pack(&m);
        let u = message_unpack(a.test_mess_oneof, &mut alloc, size, &packed).unwrap();
        let (case, int32) = if let Field::Oneof {
            case,
            value: Some(Value::I32(x)),
        } = &u.fields[0]
        {
            (*case, *x)
        } else {
            unreachable!()
        };
        println!("case={case} int32={int32}");
    }

    o_set(&mut m, 15, 16, Value::Str("oneof string".into()));
    roundtrip(&m);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&m);
        let packed = message_pack(&m);
        let u = message_unpack(a.test_mess_oneof, &mut alloc, size, &packed).unwrap();
        let (case, s) = if let Field::Oneof {
            case,
            value: Some(Value::Str(s)),
        } = &u.fields[15]
        {
            (*case, s.clone())
        } else {
            unreachable!()
        };
        print!("case={case} string=");
        strout(Some(&s));
    }

    o_set(
        &mut m,
        16,
        17,
        Value::Bin(pbc::BinValue::new(b"bytes".to_vec())),
    );
    roundtrip(&m);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&m);
        let packed = message_pack(&m);
        let u = message_unpack(a.test_mess_oneof, &mut alloc, size, &packed).unwrap();
        let (case, b) = if let Field::Oneof {
            case,
            value: Some(Value::Bin(b)),
        } = &u.fields[16]
        {
            (*case, b.clone())
        } else {
            unreachable!()
        };
        print!("case={case} bytes len={} ", b.len);
        hexout(b.data.as_deref().unwrap_or(&[]));
    }

    o_set(&mut m, 17, 18, Value::Msg(Box::new(sub)));
    roundtrip(&m);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&m);
        let packed = message_pack(&m);
        let u = message_unpack(a.test_mess_oneof, &mut alloc, size, &packed).unwrap();
        let (case, test) = if let Field::Oneof {
            case,
            value: Some(Value::Msg(sm)),
        } = &u.fields[17]
        {
            let test = if let Field::Scalar {
                value: Value::I32(t),
                ..
            } = &sm.fields[0]
            {
                *t
            } else {
                -1
            };
            (*case, test)
        } else {
            unreachable!()
        };
        println!("case={case} message test={test}");
    }

    o_set(&mut m, 11, 12, Value::F64(PACK_DB[4]));
    roundtrip(&m);

    // both members present on the wire: last wins
    {
        let mut alloc = NullAllocator;
        let wire = [0x08, 0x2a, 0x82, 0x01, 0x03, b'a', b'b', b'c'];
        let u = message_unpack(a.test_mess_oneof, &mut alloc, wire.len(), &wire).unwrap();
        let (case, s) = if let Field::Oneof {
            case,
            value: Some(Value::Str(s)),
        } = &u.fields[15]
        {
            (*case, s.clone())
        } else {
            unreachable!()
        };
        print!("both case={case} string=");
        strout(Some(&s));
    }
}

fn test_defaults_battery() {
    section("defaults");
    let a = all();
    let dr = message_init(a.default_required_values);
    roundtrip(&dr);
    {
        let mut alloc = NullAllocator;
        let u = message_unpack(a.default_required_values, &mut alloc, 0, &[]).unwrap();
        let v_i32 = if let Field::Scalar {
            value: Value::I32(x),
            ..
        } = &u.fields[0]
        {
            *x
        } else {
            0
        };
        let v_u32 = if let Field::Scalar {
            value: Value::U32(x),
            ..
        } = &u.fields[1]
        {
            *x
        } else {
            0
        };
        let v_i64 = if let Field::Scalar {
            value: Value::I32(x),
            ..
        } = &u.fields[2]
        {
            *x
        } else {
            0
        };
        let v_u64 = if let Field::Scalar {
            value: Value::U32(x),
            ..
        } = &u.fields[3]
        {
            *x
        } else {
            0
        };
        println!("empty-unpack=ok");
        println!("v_int32={v_i32} v_uint32={v_u32} v_int64={v_i64} v_uint64={v_u64}");
        if let Field::Scalar {
            value: Value::F32(x),
            ..
        } = &u.fields[4]
        {
            println!("v_float=0x{x:08x}");
        }
        if let Field::Scalar {
            value: Value::F64(x),
            ..
        } = &u.fields[5]
        {
            println!("v_double=0x{x:016x}");
        }
        if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &u.fields[6]
        {
            print!("v_string ");
            strout(Some(s));
        }
        if let Field::Pointer {
            value: Some(Value::Bin(b)),
            ..
        } = &u.fields[7]
        {
            print!("v_bytes len={} ", b.len);
            hexout(b.data.as_deref().unwrap_or(&[]));
        }
    }

    let mut dob = message_init(a.default_optional_values);
    println!("optional-fresh size={}", message_get_packed_size(&dob));
    let e = message_pack(&dob);
    println!("optional-fresh pack={}", e.len());
    s_i32(&mut dob, 0, true, 7);
    s_f64(&mut dob, 5, true, PACK_DB[2]);
    roundtrip(&dob);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&dob);
        let packed = message_pack(&dob);
        let u = message_unpack(a.default_optional_values, &mut alloc, size, &packed).unwrap();
        let (h1, v1) = if let Field::Scalar {
            has,
            value: Value::I32(x),
        } = &u.fields[0]
        {
            (*has, *x)
        } else {
            unreachable!()
        };
        let (h2, v2) = if let Field::Scalar {
            has,
            value: Value::U32(x),
        } = &u.fields[1]
        {
            (*has, *x)
        } else {
            unreachable!()
        };
        let (h5, v5) = match &u.fields[5] {
            Field::Scalar {
                has,
                value: Value::F64(x),
            } => (*has, *x),
            Field::Scalar {
                has,
                value: Value::U64(x),
            } => (*has, *x),
            _ => unreachable!(),
        };
        println!("unpack v_int32 has={h1} val={v1}");
        println!("unpack v_uint32 has={h2} val={v2}");
        println!("unpack v_double has={h5} val=0x{v5:016x}");
    }

    let mut ssm = message_init(a.sub_sub_mess);
    println!("subsub-fresh size={}", message_get_packed_size(&ssm));
    if let Field::Scalar {
        has,
        value: Value::I32(x),
    } = &ssm.fields[0]
    {
        println!("subsub val1={x} has={has}");
    }
    if let Field::Pointer {
        value: Some(Value::Bin(b)),
        ..
    } = &ssm.fields[1]
    {
        print!("subsub bytes1 len={} ", b.len);
        hexout(b.data.as_deref().unwrap_or(&[]));
    }
    if let Field::Pointer {
        value: Some(Value::Str(s)),
        ..
    } = &ssm.fields[2]
    {
        print!("subsub str1 ");
        strout(Some(s));
    }
    if let Field::Pointer {
        value: Some(Value::Bin(b)),
        ..
    } = &ssm.fields[4]
    {
        print!("subsub str2 len={} ", b.len);
        hexout(b.data.as_deref().unwrap_or(&[]));
    }

    s_i32(&mut ssm, 0, true, 5);
    p_bin(&mut ssm, 1, false, b"abc".to_vec());
    p_str(&mut ssm, 2, "custom str");
    p_bin(&mut ssm, 4, true, b"abcde".to_vec());
    roundtrip(&ssm);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&ssm);
        let packed = message_pack(&ssm);
        let u = message_unpack(a.sub_sub_mess, &mut alloc, size, &packed).unwrap();
        let (v1, h1) = if let Field::Scalar {
            has,
            value: Value::I32(x),
        } = &u.fields[0]
        {
            (*x, *has)
        } else {
            unreachable!()
        };
        let b1 = if let Field::Pointer {
            value: Some(Value::Bin(b)),
            ..
        } = &u.fields[1]
        {
            b.clone()
        } else {
            unreachable!()
        };
        let s1 = if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &u.fields[2]
        {
            s.clone()
        } else {
            unreachable!()
        };
        let b2 = if let Field::Pointer {
            value: Some(Value::Bin(b)),
            ..
        } = &u.fields[4]
        {
            b.clone()
        } else {
            unreachable!()
        };
        print!("readback val1={v1} has={h1} bytes1 len={} str1 ", b1.len);
        strout(Some(&s1));
        print!("readback str2 len={} ", b2.len);
        hexout(b2.data.as_deref().unwrap_or(&[]));
    }

    // SubMess with sub1/sub2 set
    let mut s1 = message_init(a.sub_sub_mess);
    s_i32(&mut s1, 0, true, 11);
    let mut s2 = message_init(a.sub_sub_mess);
    s_i32(&mut s2, 0, true, 22);
    p_str(&mut s2, 2, "s2 str");
    let mut sm = message_init(a.sub_mess);
    s_i32(&mut sm, 0, false, 5);
    rp(
        &mut sm,
        3,
        vec![Value::I32(1), Value::I32(2), Value::I32(3)],
    );
    p_msg(&mut sm, 4, s1);
    p_msg(&mut sm, 5, s2);
    roundtrip(&sm);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&sm);
        let packed = message_pack(&sm);
        let u = message_unpack(a.sub_mess, &mut alloc, size, &packed).unwrap();
        let test = if let Field::Scalar {
            value: Value::I32(x),
            ..
        } = &u.fields[0]
        {
            *x
        } else {
            0
        };
        let rep = if let Field::Repeated(v) = &u.fields[3] {
            v.clone()
        } else {
            unreachable!()
        };
        let sub1 = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[4]
        {
            Some(m.clone())
        } else {
            None
        };
        let sub2 = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[5]
        {
            Some(m.clone())
        } else {
            None
        };
        print!("readback test={test} n_rep={} rep=[", rep.len());
        for (i, v) in rep.iter().enumerate() {
            if let Value::I32(x) = v {
                if i > 0 {
                    print!(", ");
                }
                print!("{x}");
            }
        }
        println!(
            "] sub1={} sub2={}",
            sub1.is_some() as i32,
            sub2.is_some() as i32
        );
        let v1 = if let Some(m) = &sub1 {
            if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &m.fields[0]
            {
                *x
            } else {
                -1
            }
        } else {
            -1
        };
        let (v2, s2str) = if let Some(m) = &sub2 {
            let v = if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &m.fields[0]
            {
                *x
            } else {
                -1
            };
            let s = if let Field::Pointer {
                value: Some(Value::Str(s)),
                ..
            } = &m.fields[2]
            {
                Some(s.clone())
            } else {
                None
            };
            (v, s)
        } else {
            (-1, None)
        };
        print!("sub1 val1={v1} sub2 val1={v2} sub2 str1 ");
        strout(s2str.as_deref());
    }
}

fn test_fieldno() {
    section("fieldno");
    let a = all();
    let mut f = message_init(a.test_field_no15);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("15 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no16);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("16 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no2047);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("2047 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no2048);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("2048 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no262143);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("262143 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no262144);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("262144 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no33554431);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("33554431 size={} pack={} ", b.len(), b.len());
    hexout(&b);
    let mut f = message_init(a.test_field_no33554432);
    p_str(&mut f, 0, "x");
    let b = message_pack(&f);
    print!("33554432 size={} pack={} ", b.len(), b.len());
    hexout(&b);
}

fn check_scalar(m: &Message, i: usize) -> (i32, Value) {
    if let Field::Scalar { has, value } = &m.fields[i] {
        (*has, value.clone())
    } else {
        unreachable!()
    }
}

fn test_check_battery() {
    section("check");
    let a = all();
    let mut sm = message_init(a.check_sub);
    p_str(&mut sm, 0, "req");

    let mut ok = message_init(a.test_message_check);
    p_msg(&mut ok, 0, sm.clone());
    p_str(&mut ok, 3, "reqstr");
    p_bin(&mut ok, 6, true, b"req".to_vec());
    println!("valid check={}", message_check(&ok));

    let mut m1 = message_init(a.test_message_check);
    p_msg(&mut m1, 0, sm.clone());
    println!("missing-req-string check={}", message_check(&m1));

    let mut m2 = message_init(a.test_message_check);
    p_str(&mut m2, 3, "reqstr");
    println!("missing-req-message check={}", message_check(&m2));

    let mut m3 = message_init(a.test_message_check);
    p_msg(&mut m3, 0, sm.clone());
    p_str(&mut m3, 3, "reqstr");
    m3.fields[6] = Field::Pointer {
        has: FALSE,
        value: Some(Value::Bin(pbc::BinValue { len: 3, data: None })),
    };
    println!("req-bytes-null-data check={}", message_check(&m3));

    let mut m4 = message_init(a.test_message_check);
    p_msg(&mut m4, 0, sm.clone());
    p_str(&mut m4, 3, "reqstr");
    m4.fields[1] = Field::RepeatedNull { n: 2 };
    println!("repeated-msg-null-array check={}", message_check(&m4));

    let mut m5 = message_init(a.test_message_check);
    p_msg(&mut m5, 0, sm.clone());
    p_str(&mut m5, 3, "reqstr");
    m5.fields[4] = Field::RepeatedNull { n: 2 };
    println!("repeated-string-null-array check={}", message_check(&m5));

    let mut m6 = message_init(a.test_message_check);
    p_msg(&mut m6, 0, sm.clone());
    p_str(&mut m6, 3, "reqstr");
    rp(
        &mut m6,
        7,
        vec![
            Value::Bin(pbc::BinValue { len: 3, data: None }),
            Value::Bin(pbc::BinValue::empty()),
        ],
    );
    println!("repeated-bytes-null-data check={}", message_check(&m6));

    let mut m7 = message_init(a.test_message_check);
    p_msg(&mut m7, 0, sm.clone());
    p_str(&mut m7, 3, "reqstr");
    p_msg(&mut m7, 2, sm.clone());
    p_str(&mut m7, 5, "opt");
    m7.fields[8] = Field::Pointer {
        has: TRUE,
        value: Some(Value::Bin(pbc::BinValue { len: 5, data: None })),
    };
    println!("opt-bytes-null-data check={}", message_check(&m7));

    let mut m8 = message_init(a.test_message_check);
    p_msg(&mut m8, 0, sm.clone());
    p_str(&mut m8, 3, "reqstr");
    p_msg(&mut m8, 2, sm.clone());
    p_str(&mut m8, 5, "opt");
    println!("opt-set-valid check={}", message_check(&m8));

    let o1 = message_init(a.test_mess_oneof);
    println!("oneof-unset check={}", message_check(&o1));
    let mut o2 = message_init(a.test_mess_oneof);
    o2.fields[2] = Field::Oneof {
        case: 16,
        value: None,
    };
    println!("oneof-string-null check={}", message_check(&o2));
    let mut o3 = message_init(a.test_mess_oneof);
    o_set(&mut o3, 15, 16, Value::Str("set".into()));
    println!("oneof-string-set check={}", message_check(&o3));

    let mut bad = message_init(a.check_sub);
    let mut m9 = message_init(a.test_message_check);
    p_msg(&mut m9, 0, sm.clone());
    p_str(&mut m9, 3, "reqstr");
    rp(&mut m9, 1, vec![Value::Msg(Box::new(bad))]);
    println!("nested-req-missing check={}", message_check(&m9));
}

fn test_enum_lookups() {
    section("enums");
    let a = all();
    let names = ["VALUE0", "VALUENEG123456", "VALUE268435456", "NOPE", ""];
    for name in names {
        match pbc::enum_descriptor_get_value_by_name(a.test_enum, name) {
            Some(v) => println!("by_name {name} -> {} {}", v.name, v.value),
            None => println!("by_name {name} -> NULL"),
        }
    }
    let vals = [
        -123456, -1, 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456, 2, -2,
        1000000000,
    ];
    for v in vals {
        match pbc::enum_descriptor_get_value(a.test_enum, v) {
            Some(ev) => println!("by_value {v} -> {} {}", ev.name, ev.value),
            None => println!("by_value {v} -> NULL"),
        }
    }
    let dn = [
        "VALUE_A", "VALUE_B", "VALUE_D", "VALUE_E", "VALUE_F", "VALUE_AA", "VALUE_BB", "VALUE_X",
    ];
    for name in dn {
        match pbc::enum_descriptor_get_value_by_name(a.test_enum_dup, name) {
            Some(v) => println!("dup by_name {name} -> {} {}", v.name, v.value),
            None => println!("dup by_name {name} -> NULL"),
        }
    }
    let dv = [42, 666, 1000, 1001, 41, 43, 667, 999, 1002];
    for v in dv {
        match pbc::enum_descriptor_get_value(a.test_enum_dup, v) {
            Some(ev) => println!("dup by_value {v} -> {} {}", ev.name, ev.value),
            None => println!("dup by_value {v} -> NULL"),
        }
    }
    let v = pbc::enum_descriptor_get_value_by_name(a.test_enum_small, "NEG_VALUE").unwrap();
    println!("small by_name NEG_VALUE -> {} {}", v.name, v.value);
    let v = pbc::enum_descriptor_get_value(a.test_enum_small, 1).unwrap();
    println!("small by_value 1 -> {} {}", v.name, v.value);
    match pbc::enum_descriptor_get_value(a.test_enum_small, 2) {
        Some(v) => println!("small by_value 2 -> {}", v.name),
        None => println!("small by_value 2 -> NULL"),
    }
}

fn test_descriptor_lookups() {
    section("descriptor-lookups");
    let a = all();
    let names = ["test_int32", "test_uint64", "test_boolean", "nope", ""];
    for name in names {
        match pbc::message_descriptor_get_field_by_name(a.test_mess_packed, name) {
            Some(f) => println!(
                "by_name {name} -> id={} type={} label={} flags={}",
                f.id, f.ty, f.label, f.flags
            ),
            None => println!("by_name {name} -> NULL"),
        }
    }
    let tags = [1u32, 7, 15, 0, 16, 1000000];
    for t in tags {
        match pbc::message_descriptor_get_field(a.test_mess_packed, t) {
            Some(f) => println!("by_tag {t} -> {} id={}", f.name, f.id),
            None => println!("by_tag {t} -> NULL"),
        }
    }
    let f = pbc::message_descriptor_get_field_by_name(a.test_mess_oneof, "test_int32").unwrap();
    println!("oneof test_int32 flags={}", f.flags);
    let f = pbc::message_descriptor_get_field_by_name(a.test_mess_oneof, "test_string").unwrap();
    println!("oneof test_string flags={}", f.flags);
}

fn test_services() {
    section("services");
    let a = all();
    let mut service: Service = Service {
        descriptor: a.dir_lookup,
        invoke: None,
        destroy: None,
        handlers: Vec::new(),
    };
    service_generated_init(&mut service, a.dir_lookup, Some(|_s| {}));

    let md = pbc::service_descriptor_get_method_by_name(a.dir_lookup, "ByName").unwrap();
    println!(
        "method ByName -> {} (in={} out={})",
        md.name, md.input.short_name, md.output.short_name
    );
    match pbc::service_descriptor_get_method_by_name(a.dir_lookup, "Nope") {
        Some(md) => println!("method Nope -> {}", md.name),
        None => println!("method Nope -> NULL"),
    }

    // the user-installed handler (C: service.by_name = dir_lookup_by_name_impl)
    service.handlers[0] = Some(Box::new(
        |_service: &mut Service, input: &Message, closure: &mut Closure, closure_data: usize| {
            let name = if let Field::Pointer {
                value: Some(Value::Str(s)),
                ..
            } = &input.fields[0]
            {
                Some(s.clone())
            } else {
                None
            };
            print!("  handler input name=");
            strout(name.as_deref());
            println!("  handler closure_data=0x{closure_data:x}");
            let result = message_init(protobuf_c_gen::all().p3_lookup_result);
            closure(&result, closure_data);
        },
    ));

    let mut name = message_init(a.p3_name);
    p_str(&mut name, 0, "alice");
    println!("invoke:");
    let mut closure: Closure = Box::new(|result: &Message, closure_data: usize| {
        let person = if let Field::Pointer {
            value: Some(Value::Msg(_)),
            ..
        } = &result.fields[0]
        {
            1
        } else {
            0
        };
        println!("  closure called closure_data=0x{closure_data:x} person={person}");
    });
    let invoke = service.invoke.unwrap();
    invoke(&mut service, 0, &name, &mut closure, 0x1234);
    let mut destroyed = 0;
    service.destroy = Some(|_s: &mut Service| {});
    println!("destroyed before destroy={destroyed}");
    service_destroy(&mut service);
    destroyed = 1;
    println!("destroyed after destroy={destroyed}");
}

fn test_proto3_battery() {
    section("proto3");
    let a = all();
    let p = message_init(a.p3_person);
    println!("fresh size={}", message_get_packed_size(&p));
    let e = message_pack(&p);
    println!("fresh pack={}", e.len());

    let mut comment = message_init(a.p3_comment);
    p_str(&mut comment, 0, "nice");
    let mut phone1 = message_init(a.p3_phone_number);
    p_str(&mut phone1, 0, "1234");
    s_enum(&mut phone1, 1, false, 2);
    p_msg(&mut phone1, 2, comment);
    let mut phone2 = message_init(a.p3_phone_number);
    p_str(&mut phone2, 0, "5678");
    s_enum(&mut phone2, 1, false, 0);

    let mut p = message_init(a.p3_person);
    p_str(&mut p, 0, "dave b");
    s_i32(&mut p, 1, false, 42);
    p_str(&mut p, 2, "dave@example.com");
    rp(
        &mut p,
        3,
        vec![Value::Msg(Box::new(phone1)), Value::Msg(Box::new(phone2))],
    );
    roundtrip(&p);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&p);
        let packed = message_pack(&p);
        let u = message_unpack(a.p3_person, &mut alloc, size, &packed).unwrap();
        let name = if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &u.fields[0]
        {
            s.clone()
        } else {
            unreachable!()
        };
        let id = if let Field::Scalar {
            value: Value::I32(x),
            ..
        } = &u.fields[1]
        {
            *x
        } else {
            unreachable!()
        };
        let email = if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &u.fields[2]
        {
            s.clone()
        } else {
            unreachable!()
        };
        let phones = if let Field::Repeated(v) = &u.fields[3] {
            v.clone()
        } else {
            unreachable!()
        };
        print!("readback name ");
        strout(Some(&name));
        println!("readback id={id}");
        print!("readback email ");
        strout(Some(&email));
        println!("readback n_phone={}", phones.len());
        for (i, v) in phones.iter().enumerate() {
            if let Value::Msg(pn) = v {
                let number = if let Field::Pointer {
                    value: Some(Value::Str(s)),
                    ..
                } = &pn.fields[0]
                {
                    s.clone()
                } else {
                    unreachable!()
                };
                let ty = match &pn.fields[1] {
                    Field::Scalar { value: Value::Enum(x), .. } => *x,
                    Field::Scalar { value: Value::I32(x), .. } => *x,
                    _ => unreachable!(),
                };
                let has_comment = if let Field::Pointer {
                    value: Some(Value::Msg(_)),
                    ..
                } = &pn.fields[2]
                {
                    1
                } else {
                    0
                };
                print!("  phone[{i}] number ");
                strout(Some(&number));
                println!("  phone[{i}] type={ty} comment={has_comment}");
                if let Field::Pointer {
                    value: Some(Value::Msg(cm)),
                    ..
                } = &pn.fields[2]
                {
                    let c = if let Field::Pointer {
                        value: Some(Value::Str(s)),
                        ..
                    } = &cm.fields[0]
                    {
                        s.clone()
                    } else {
                        unreachable!()
                    };
                    print!("  phone[{i}] comment ");
                    strout(Some(&c));
                }
            }
        }
    }

    let mut p2 = message_init(a.p3_person);
    p_str(&mut p2, 0, "zeroish");
    p_str(&mut p2, 2, "");
    roundtrip(&p2);
}

fn test_unknown_fields() {
    section("unknown-fields");
    let a = all();
    let wire: &[u8] = &[
        0x08, 0x07, 0x98, 0x06, 0x96, 0x01, 0xa5, 0x06, 0x01, 0x02, 0x03, 0x04, 0xa9, 0x06, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xb2, 0x06, 0x05, b'h', b'e', b'l', b'l', b'o',
        0xc2, 0x06, 0x00, 0xb8, 0x06, 0x01,
    ];
    let mut alloc = NullAllocator;
    let u = message_unpack(a.test_mess_optional, &mut alloc, wire.len(), wire);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    if let Some(u) = u {
        let (h, v) = check_scalar(&u, 0);
        let v = if let Value::I32(x) = v { x } else { 0 };
        println!("known int32 has={h} val={v}");
        println!("n_unknown={}", u.unknown_fields.len());
        for (i, uf) in u.unknown_fields.iter().enumerate() {
            print!(
                "  unknown[{i}] tag={} wire={} len={} ",
                uf.tag,
                uf.wire_type,
                uf.len()
            );
            hexout(&uf.data);
        }
        let size = message_get_packed_size(&u);
        let rp = message_pack(&u);
        println!(
            "repack size={size} match={}",
            if rp.len() == wire.len() && rp == wire {
                "yes"
            } else {
                "NO"
            }
        );
        print!("repack ");
        hexout(&rp);
    }
}

fn test_merge() {
    section("merge");
    let a = all();
    let wire: &[u8] = &[
        0x08, 0x05, 0x08, 0x06, 0x92, 0x01, 0x08, 0x20, 0x01, 0x30, 0x05, 0x40, 0x01, 0x40, 0x02,
        0x92, 0x01, 0x04, 0x20, 0x02, 0x40, 0x03,
    ];
    let mut alloc = NullAllocator;
    let u = message_unpack(a.test_mess_optional, &mut alloc, wire.len(), wire);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    if let Some(u) = u {
        let v = if let Field::Scalar {
            value: Value::I32(x),
            ..
        } = &u.fields[0]
        {
            *x
        } else {
            0
        };
        println!("int32={v} (last wins)");
        if let Field::Pointer {
            value: Some(Value::Msg(sm)),
            ..
        } = &u.fields[17]
        {
            let test = if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &sm.fields[0]
            {
                *x
            } else {
                0
            };
            let has_val1 = if let Field::Scalar { has, .. } = &sm.fields[1] {
                *has
            } else {
                0
            };
            let val1 = if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &sm.fields[1]
            {
                *x
            } else {
                0
            };
            let rep = if let Field::Repeated(v) = &sm.fields[3] {
                v.clone()
            } else {
                unreachable!()
            };
            print!(
                "sub test={test} has_val1={has_val1} val1={val1} n_rep={} rep=[",
                rep.len()
            );
            for (i, rv) in rep.iter().enumerate() {
                if let Value::I32(x) = rv {
                    if i > 0 {
                        print!(", ");
                    }
                    print!("{x}");
                }
            }
            println!("]");
        }
    }
}

fn unpack_err(name: &str, desc: &'static MessageDescriptor, data: &[u8]) {
    let mut alloc = NullAllocator;
    let m = message_unpack(desc, &mut alloc, data.len(), data);
    println!("{name}: {}", if m.is_some() { "NOT-NULL" } else { "NULL" });
}

fn test_errors() {
    section("errors");
    let a = all();
    unpack_err("bad-tag0", a.test_mess_optional, &[0x00]);
    unpack_err("truncated-varint", a.test_mess_optional, &[0x08, 0x80]);
    unpack_err("wiretype-3", a.test_mess_optional, &[0x0b]);
    unpack_err("wiretype-4", a.test_mess_optional, &[0x0c]);
    unpack_err("wiretype-6", a.test_mess_optional, &[0x0e]);
    unpack_err("wiretype-7", a.test_mess_optional, &[0x0f]);
    unpack_err("short-64bit", a.test_mess_optional, &[0x09, 0x01]);
    unpack_err("short-32bit", a.test_mess_optional, &[0x0d, 0x01]);
    unpack_err(
        "len-over-intmax",
        a.test_mess_optional,
        &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f],
    );
    unpack_err("len-too-long", a.test_mess_optional, &[0x0a, 0x64, b'x']);
    unpack_err("len-truncated", a.test_mess_optional, &[0x0a, 0x80]);
    unpack_err(
        "packed-fixed32-badlen",
        a.test_mess_packed,
        &[0x1a, 0x02, 0x01, 0x02],
    );
    unpack_err(
        "packed-varint-bad-tail",
        a.test_mess_packed,
        &[0x0a, 0x01, 0x80],
    );
    unpack_err(
        "wrong-wiretype",
        a.test_mess_optional,
        &[0x0d, 0x01, 0x00, 0x00, 0x00],
    );
    unpack_err("missing-required", a.test_mess_required_string, &[]);
    unpack_err("missing-required-int32", a.test_mess_required_int32, &[]);
    {
        let mut alloc = NullAllocator;
        let em = message_unpack(a.empty_mess, &mut alloc, 0, &[]);
        println!("empty-unpack: {}", if em.is_some() { "ok" } else { "NULL" });
    }
    {
        let mut alloc = NullAllocator;
        let boolwire = [0x68, 0x80, 0x01];
        let u =
            message_unpack(a.test_mess_optional, &mut alloc, boolwire.len(), &boolwire).unwrap();
        let (h, v) = check_scalar(&u, 12);
        let v = if let Value::Bool(x) = v { x } else { 0 };
        println!("bool-2byte-varint: has={h} val={v}");
    }
    {
        let mut alloc = NullAllocator;
        let u = message_unpack(a.default_required_values, &mut alloc, 0, &[]);
        let v = if let Some(u) = &u {
            if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &u.fields[0]
            {
                Some(*x)
            } else {
                None
            }
        } else {
            None
        };
        match (u.is_some(), v) {
            (true, Some(x)) => println!("required-with-default empty: ok v_int32={x}"),
            _ => println!("required-with-default empty: NULL v_int32=-999"),
        }
    }
}

fn test_allocator() {
    section("allocator");
    let a = all();
    let mut sub = message_init(a.sub_mess);
    s_i32(&mut sub, 0, false, 1);
    rp(
        &mut sub,
        3,
        vec![Value::I32(1), Value::I32(2), Value::I32(3)],
    );

    let mut m = message_init(a.test_mess_optional);
    s_i32(&mut m, 0, true, -5);
    s_i32(&mut m, 1, true, -5);
    s_i32(&mut m, 2, true, -5);
    s_i64(&mut m, 3, true, -1234567890123);
    s_i64(&mut m, 4, true, -1234567890123);
    s_i64(&mut m, 5, true, -1234567890123);
    s_u32(&mut m, 6, true, 4294967295);
    s_u32(&mut m, 7, true, 4294967295);
    s_u64(&mut m, 8, true, 18446744073709551615);
    s_u64(&mut m, 9, true, 18446744073709551615);
    s_f32(&mut m, 10, true, PACK_FL[2]);
    s_f64(&mut m, 11, true, PACK_DB[2]);
    s_bool(&mut m, 12, true, 1);
    s_enum(&mut m, 13, true, -1);
    s_enum(&mut m, 14, true, 268435456);
    p_str(&mut m, 15, "hello world");
    p_bin(&mut m, 16, true, b"bytes".to_vec());
    p_msg(&mut m, 17, sub);

    let mut alloc = CountingAllocator::new();
    let size = message_get_packed_size(&m);
    let packed = message_pack(&m);
    let u = message_unpack(a.test_mess_optional, &mut alloc, size, &packed);
    println!("unpack={}", if u.is_some() { "ok" } else { "NULL" });
    let mut u = u.unwrap();
    pbc::free_unpacked(Some(&mut u), &mut alloc);
    println!(
        "totals allocs={} frees={} bytes={}",
        alloc.n_alloc, alloc.n_free, alloc.total
    );

    let mut alloc = CountingAllocator::new();
    let mut rb = message_init(a.test_required_fields_bitmap);
    p_str(&mut rb, 0, "a");
    p_str(&mut rb, 128, "b");
    let rsize = message_get_packed_size(&rb);
    let rpacked = message_pack(&rb);
    println!("bitmap-message size={rsize}");
    let ru = message_unpack(a.test_required_fields_bitmap, &mut alloc, rsize, &rpacked);
    let ru = ru.unwrap();
    let f1 = if let Field::Pointer {
        value: Some(Value::Str(s)),
        ..
    } = &ru.fields[0]
    {
        s.clone()
    } else {
        unreachable!()
    };
    let f129 = if let Field::Pointer {
        value: Some(Value::Str(s)),
        ..
    } = &ru.fields[128]
    {
        s.clone()
    } else {
        unreachable!()
    };
    println!("bitmap unpack=ok field1={f1} field129={f129}");
    let mut ru = ru;
    pbc::free_unpacked(Some(&mut ru), &mut alloc);
    println!(
        "bitmap totals allocs={} frees={} bytes={}",
        alloc.n_alloc, alloc.n_free, alloc.total
    );

    let mut alloc = CountingAllocator::new();
    let wire129 = [0x0a, 0x01, b'a'];
    let ru2 = message_unpack(
        a.test_required_fields_bitmap,
        &mut alloc,
        wire129.len(),
        &wire129,
    );
    println!(
        "bitmap missing-129: {}",
        if ru2.is_some() { "NOT-NULL" } else { "NULL" }
    );
    if let Some(mut ru2) = ru2 {
        pbc::free_unpacked(Some(&mut ru2), &mut alloc);
    }
}

fn test_buffer_simple() {
    section("buffer-simple");
    let a = all();
    let mut m = message_init(a.test_mess_packed);
    fill_packed(&mut m);

    let size = message_get_packed_size(&m);
    let packed = message_pack(&m);

    let mut bs = BufferSimple::new(vec![0u8; 8]);
    let bsize = message_pack_to_buffer(&m, &mut bs);
    println!("pack_to_buffer size={bsize}");
    println!(
        "buffer alloced={} len={} must_free={}",
        bs.alloced, bs.len, bs.must_free_data as i32
    );
    println!(
        "buffer matches pack: {}",
        if bs.len == size && bs.data[..bs.len] == packed[..] {
            "yes"
        } else {
            "NO"
        }
    );
    bs.clear();

    let mut om = message_init(a.test_mess_optional);
    s_i32(&mut om, 0, true, 5);
    let mut bs2 = BufferSimple::new(vec![0u8; 4]);
    message_pack_to_buffer(&om, &mut bs2);
    println!(
        "small message: alloced={} len={} must_free={}",
        bs2.alloced, bs2.len, bs2.must_free_data as i32
    );
    bs2.clear();
}

/// the dynamic descriptor exercising `message_init_generic`
/// (message_init == NULL on the descriptor)
struct DynDesc {
    desc: &'static MessageDescriptor,
}

fn build_dyn_desc() -> DynDesc {
    // fields: f_i32(1,opt,int32,default -7), f_i64(2,opt,int64,default
    // 1234567890123), f_bool(3,opt,bool,default 1), f_str(4,opt,string,
    // default "dyn-default"), f_bytes(5,opt,bytes,default {3, 01 02 03})
    // The mirror struct layout (x86-64): base 24 + i32 4 + i64 8 + bool 4
    // + str 8 + bytes 16 + 4 has-bools = 88 bytes.
    #[repr(C)]
    struct Dyn {
        base: [u8; 24],
        f_i32: i32,
        f_i64: i64,
        f_bool: i32,
        f_str: *const u8,
        f_bytes: [u8; 16],
        has_f_i32: i32,
        has_f_i64: i32,
        has_f_bool: i32,
        has_f_bytes: i32,
    }
    let sizeof_message = size_of::<Dyn>();
    let off = |name: &str| -> usize {
        match name {
            "base" => 0,
            "f_i32" => std::mem::offset_of!(Dyn, f_i32),
            "f_i64" => std::mem::offset_of!(Dyn, f_i64),
            "f_bool" => std::mem::offset_of!(Dyn, f_bool),
            "f_str" => std::mem::offset_of!(Dyn, f_str),
            "f_bytes" => std::mem::offset_of!(Dyn, f_bytes),
            "has_f_i32" => std::mem::offset_of!(Dyn, has_f_i32),
            "has_f_i64" => std::mem::offset_of!(Dyn, has_f_i64),
            "has_f_bool" => std::mem::offset_of!(Dyn, has_f_bool),
            "has_f_bytes" => std::mem::offset_of!(Dyn, has_f_bytes),
            _ => unreachable!(),
        }
    };
    let fields: &'static [pbc::FieldDescriptor] = Box::leak(
        vec![
            pbc::FieldDescriptor {
                name: "f_i32",
                id: 1,
                label: LABEL_OPTIONAL,
                ty: TYPE_INT32,
                quantifier_offset: off("has_f_i32"),
                offset: off("f_i32"),
                descriptor: None,
                default_value: Some(pbc::DefaultValue::I32(-7)),
                flags: 0,
            },
            pbc::FieldDescriptor {
                name: "f_i64",
                id: 2,
                label: LABEL_OPTIONAL,
                ty: TYPE_INT64,
                quantifier_offset: off("has_f_i64"),
                offset: off("f_i64"),
                descriptor: None,
                default_value: Some(pbc::DefaultValue::I64(1234567890123)),
                flags: 0,
            },
            pbc::FieldDescriptor {
                name: "f_bool",
                id: 3,
                label: LABEL_OPTIONAL,
                ty: TYPE_BOOL,
                quantifier_offset: off("has_f_bool"),
                offset: off("f_bool"),
                descriptor: None,
                default_value: Some(pbc::DefaultValue::Bool(1)),
                flags: 0,
            },
            pbc::FieldDescriptor {
                name: "f_str",
                id: 4,
                label: LABEL_OPTIONAL,
                ty: TYPE_STRING,
                quantifier_offset: 0,
                offset: off("f_str"),
                descriptor: None,
                default_value: Some(pbc::DefaultValue::Str("dyn-default")),
                flags: 0,
            },
            pbc::FieldDescriptor {
                name: "f_bytes",
                id: 5,
                label: LABEL_OPTIONAL,
                ty: TYPE_BYTES,
                quantifier_offset: off("has_f_bytes"),
                offset: off("f_bytes"),
                descriptor: None,
                default_value: Some(pbc::DefaultValue::Bin(&[0x01, 0x02, 0x03])),
                flags: 0,
            },
        ]
        .into_boxed_slice(),
    );
    let indices: &'static [usize] = Box::leak(vec![2usize, 4, 0, 1, 3].into_boxed_slice());
    let ranges: &'static [IntRange] = Box::leak(
        vec![
            IntRange {
                start_value: 1,
                orig_index: 0,
            },
            IntRange {
                start_value: 0,
                orig_index: 5,
            },
        ]
        .into_boxed_slice(),
    );
    let desc: &'static MessageDescriptor = Box::leak(Box::new(MessageDescriptor {
        magic: pbc::MESSAGE_DESCRIPTOR_MAGIC,
        name: "dyn.DynMsg",
        short_name: "DynMsg",
        c_name: "DynMsg",
        package_name: "dyn",
        sizeof_message,
        fields,
        fields_sorted_by_name: Some(indices),
        field_ranges: ranges,
        n_field_ranges: 1,
        message_init: None, // exercises message_init_generic
    }));
    DynDesc { desc }
}

fn test_dynamic_descriptor() {
    section("dynamic");
    let dyn_desc = build_dyn_desc();
    let mut alloc = NullAllocator;
    let m = message_unpack(dyn_desc.desc, &mut alloc, 0, &[]);
    println!("unpack-empty={}", if m.is_some() { "ok" } else { "NULL" });
    if let Some(mut m) = m {
        let sc = |i: usize| check_scalar(&m, i);
        let (h0, v0) = sc(0);
        let v0 = if let Value::I32(x) = v0 { x } else { 0 };
        println!("f_i32={v0} has={h0}");
        let (h1, v1) = sc(1);
        let v1 = if let Value::I64(x) = v1 { x } else { 0 };
        println!("f_i64={v1} has={h1}");
        let (h2, v2) = sc(2);
        let v2 = if let Value::Bool(x) = v2 { x } else { 0 };
        println!("f_bool={v2} has={h2}");
        if let Field::Pointer {
            value: Some(Value::Str(s)),
            ..
        } = &m.fields[3]
        {
            print!("f_str ");
            strout(Some(s));
        }
        if let Field::Pointer {
            value: Some(Value::Bin(b)),
            ..
        } = &m.fields[4]
        {
            print!("f_bytes len={} ", b.len);
            hexout(b.data.as_deref().unwrap_or(&[]));
        }
        println!("fresh size={}", message_get_packed_size(&m));
        // set the has flags so the defaults serialize; replace the default
        // string so it is not skipped as the default
        s_i32(&mut m, 0, true, -7);
        s_i64(&mut m, 1, true, 1234567890123);
        s_bool(&mut m, 2, true, 1);
        p_str(&mut m, 3, "custom");
        m.fields[4] = Field::Pointer {
            has: TRUE,
            value: Some(Value::Bin(pbc::BinValue::new(vec![0x01, 0x02, 0x03]))),
        };
        let size = message_get_packed_size(&m);
        let packed = message_pack(&m);
        print!("size={size} wrote={} ", packed.len());
        hexout(&packed);
        pbc::free_unpacked(Some(&mut m), &mut alloc);
        println!("freed ok");
    }
    let f = pbc::message_descriptor_get_field_by_name(dyn_desc.desc, "f_i32").unwrap();
    println!("by_name f_i32 -> id={}", f.id);
    let f = pbc::message_descriptor_get_field(dyn_desc.desc, 5).unwrap();
    println!("by_tag 5 -> {}", f.name);
    match pbc::message_descriptor_get_field(dyn_desc.desc, 6) {
        Some(f) => println!("by_tag 6 -> {}", f.name),
        None => println!("by_tag 6 -> NULL"),
    }
}

fn test_empty() {
    section("empty");
    let a = all();
    let m = message_init(a.empty_mess);
    println!("size={}", message_get_packed_size(&m));
    let b = message_pack(&m);
    print!("pack={} ", b.len());
    hexout(&b);
    println!("check={}", message_check(&m));
    pbc::free_unpacked(None, &mut NullAllocator);
    println!("free-NULL ok");
    let mut rs = message_init(a.test_mess_required_string);
    let size = message_get_packed_size(&rs);
    println!("null-string size={size}");
    let b = message_pack(&rs);
    print!("null-string ");
    hexout(&b);
    let rm = message_init(a.test_mess_required_message);
    let size = message_get_packed_size(&rm);
    print!("null-message size={size} ");
    let b = message_pack(&rm);
    print!("null-message ");
    hexout(&b);
}

fn test_nested_battery() {
    section("nested");
    let a = all();
    let mut rep = message_init(a.test_mess);
    rp(&mut rep, 0, vec![Value::I32(1), Value::I32(2)]);
    rp(&mut rep, 1, vec![Value::I32(-3)]);
    rp(&mut rep, 6, vec![Value::U32(7)]);
    rp(&mut rep, 12, vec![Value::Bool(1), Value::Bool(0)]);
    rp(&mut rep, 15, vec![Value::Str("nested".into())]);
    rp(
        &mut rep,
        16,
        vec![Value::Bin(pbc::BinValue::new(vec![0xde, 0xad]))],
    );
    let mut n_sub = message_init(a.sub_mess);
    s_i32(&mut n_sub, 0, false, 1);
    rp(&mut rep, 17, vec![Value::Msg(Box::new(n_sub.clone()))]);

    let mut opt = message_init(a.test_mess_optional);
    s_i32(&mut opt, 0, true, 11);

    let mut oneof = message_init(a.test_mess_oneof);
    o_set(&mut oneof, 0, 1, Value::I32(22));

    let mut defs = message_init(a.default_optional_values);
    s_i32(&mut defs, 0, true, 33);

    let mut tm = message_init(a.test_mess_sub_mess);
    p_msg(&mut tm, 0, rep);
    p_msg(&mut tm, 1, opt);
    p_msg(&mut tm, 2, oneof);
    p_msg(&mut tm, 3, n_sub);
    p_msg(&mut tm, 4, defs);
    roundtrip(&tm);
    {
        let mut alloc = NullAllocator;
        let size = message_get_packed_size(&tm);
        let packed = message_pack(&tm);
        let u = message_unpack(a.test_mess_sub_mess, &mut alloc, size, &packed).unwrap();
        let rep = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[0]
        {
            m.clone()
        } else {
            unreachable!()
        };
        let opt = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[1]
        {
            m.clone()
        } else {
            unreachable!()
        };
        let oneof = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[2]
        {
            m.clone()
        } else {
            unreachable!()
        };
        let defs = if let Field::Pointer {
            value: Some(Value::Msg(m)),
            ..
        } = &u.fields[4]
        {
            m.clone()
        } else {
            unreachable!()
        };
        let ni32 = if let Field::Repeated(v) = &rep.fields[0] {
            v.len()
        } else {
            0
        };
        let nstr = if let Field::Repeated(v) = &rep.fields[15] {
            v.len()
        } else {
            0
        };
        let nbytes = if let Field::Repeated(v) = &rep.fields[16] {
            v.len()
        } else {
            0
        };
        let nmsg = if let Field::Repeated(v) = &rep.fields[17] {
            v.len()
        } else {
            0
        };
        println!(
            "readback rep.n_int32={ni32} rep.n_str={nstr} rep.n_bytes={nbytes} rep.n_msg={nmsg}"
        );
        let i0 = if let Value::I32(x) = &rep.fields_as_repeated(0)[0] {
            *x
        } else {
            0
        };
        let s0 = if let Value::I32(x) = &rep.fields_as_repeated(1)[0] {
            *x
        } else {
            0
        };
        let b0 = if let Value::Bool(x) = &rep.fields_as_repeated(12)[0] {
            *x
        } else {
            0
        };
        println!("readback rep.int32[0]={i0} rep.sint32[0]={s0} rep.bool[0]={b0}");
        if let Value::Str(s) = &rep.fields_as_repeated(15)[0] {
            print!("readback rep.str[0] ");
            strout(Some(s));
        }
        if let Value::Bin(b) = &rep.fields_as_repeated(16)[0] {
            print!("readback rep.bytes[0] len={} ", b.len);
            hexout(b.data.as_deref().unwrap_or(&[]));
        }
        if let Value::Msg(sm) = &rep.fields_as_repeated(17)[0] {
            let t = if let Field::Scalar {
                value: Value::I32(x),
                ..
            } = &sm.fields[0]
            {
                *x
            } else {
                0
            };
            println!("readback rep.msg[0] test={t}");
        }
        let (h, v) = check_scalar(&opt, 0);
        let v = if let Value::I32(x) = v { x } else { 0 };
        println!("readback opt.int32 has={h} val={v}");
        let (case, v) = if let Field::Oneof {
            case,
            value: Some(Value::I32(x)),
        } = &oneof.fields[0]
        {
            (*case, *x)
        } else {
            unreachable!()
        };
        println!("readback oneof case={case} int32={v}");
        let (h, v) = check_scalar(&defs, 0);
        let v = if let Value::I32(x) = v { x } else { 0 };
        println!("readback defs.v_int32 has={h} val={v}");
    }
}

trait RepHelper {
    fn fields_as_repeated(&self, i: usize) -> &Vec<Value>;
}

impl RepHelper for Message {
    fn fields_as_repeated(&self, i: usize) -> &Vec<Value> {
        if let Field::Repeated(v) = &self.fields[i] {
            v
        } else {
            unreachable!()
        }
    }
}

fn main() {
    println!("=== protobuf-c 1.5.2 probe ===");
    test_version();
    test_sizes();
    test_packed_battery();
    test_repeated_battery();
    test_optional_battery();
    test_oneof_battery();
    test_defaults_battery();
    test_fieldno();
    test_check_battery();
    test_enum_lookups();
    test_descriptor_lookups();
    test_services();
    test_proto3_battery();
    test_unknown_fields();
    test_merge();
    test_errors();
    test_allocator();
    test_buffer_simple();
    test_dynamic_descriptor();
    test_empty();
    test_nested_battery();
}

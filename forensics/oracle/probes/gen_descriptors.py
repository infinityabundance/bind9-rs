#!/usr/bin/env python3
"""Generate bind9-rs-tools/src/bin/protobuf_c_gen.rs from the checked-in
protoc-gen-c 1.5.2 fixture files (test-full.pb-c.{c,h}, test-proto3.pb-c.{c,h}).

The generated .pb-c files were produced by the pinned protoc-gen-c 1.5.2
from the pinned tarball's t/*.proto (see probe-protobuf-c.c header).  This
script transcribes the descriptor tables (field arrays, name-sorted index,
number ranges, enum tables, defaults, service) and computes the C struct
layout (x86-64 SysV: sizes + offsets) so the Rust probe's descriptors carry
the same sizeof_message/quantifier offsets as the C oracle's.

Run from the workspace root:
    python3 forensics/oracle/probes/gen_descriptors.py
"""
import re
import struct

H = "forensics/oracle/probes/protobuf-c-gen"
FULL_H = f"{H}/test-full.pb-c.h"
FULL_C = f"{H}/test-full.pb-c.c"
P3_H = f"{H}/test-proto3.pb-c.h"
P3_C = f"{H}/test-proto3.pb-c.c"

full_h = open(FULL_H).read()
full_c = open(FULL_C).read()
p3_h = open(P3_H).read()
p3_c = open(P3_C).read()

# ---------------------------------------------------------------------------
# C type sizes (x86-64 SysV)
# ---------------------------------------------------------------------------
ALIGN = {"i32": 4, "u32": 4, "i64": 8, "u64": 8, "f32": 4, "f64": 8, "usize": 8, "ptr": 8}
TYPE_SIZE = 16  # ProtobufCBinaryData = { size_t len; uint8_t *data; }


def align_up(n, a):
    return (n + a - 1) & ~(a - 1)


def split_top_level(s):
    """Split on commas at paren depth 0 (offsetof(..., x) must stay whole)."""
    parts = []
    depth = 0
    cur = ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def parse_c_string(s):
    """Decode a C string literal (with octal/hex/escape sequences)."""
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == "\\":
            nxt = s[i + 1]
            if nxt in "01234567":
                j = i + 1
                v = 0
                while j < len(s) and j < i + 4 and s[j] in "01234567":
                    v = v * 8 + int(s[j])
                    j += 1
                out.append(v & 0xFF)
                i = j
            elif nxt == "x":
                v = int(s[i + 2:i + 4], 16)
                out.append(v)
                i = i + 4
            elif nxt == "n":
                out.append(0x0A); i += 2
            elif nxt == "t":
                out.append(0x09); i += 2
            elif nxt == "r":
                out.append(0x0D); i += 2
            elif nxt == "0":
                out.append(0x00); i += 2
            elif nxt == "\\":
                out.append(0x5C); i += 2
            elif nxt == '"':
                out.append(0x22); i += 2
            else:
                out.append(ord(nxt)); i += 2
        else:
            out.append(ord(c))
            i += 1
    return bytes(out)


# ---------------------------------------------------------------------------
# parse enums + structs from the .h files
# ---------------------------------------------------------------------------
ENUM_SIZES = {}
enums = {}


def parse_enums(hdr):
    for m in re.finditer(r"typedef enum\s*_?(\w*)\s*\{([^}]*?)\}\s*(\w+);", hdr, re.S):
        name, body = m.group(1), m.group(2)
        vals = []
        for line in body.splitlines():
            line = line.split("/*")[0]
            vm = re.match(r"\s*(\w+)\s*=\s*(-?\d+)", line)
            if vm:
                vals.append((vm.group(1), int(vm.group(2))))
        # anonymous enums (oneof case enums) still have an int-sized type
        ENUM_SIZES[m.group(3)] = 4  # PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE
        if name:
            enums[name] = vals


parse_enums(full_h)
parse_enums(p3_h)

ENUM_INDEX_BY_NAME = {}


def camel_to_snake_upper(s):
    return "__".join(snake_part(p) for p in s.split("__"))


def snake_part(s):
    out = []
    for i, ch in enumerate(s):
        if ch.isupper():
            if i > 0:
                out.append("_")
            out.append(ch)
        else:
            out.append(ch)
    return "".join(out).upper()


for ename, vals in enums.items():
    # the generated .h value names are already fully qualified
    # (FOO__TEST_ENUM_SMALL__NEG_VALUE), which is exactly what the INIT
    # macros reference
    for vname, vval in vals:
        ENUM_INDEX_BY_NAME[vname] = vval

STRUCTS = {}


def c_type(decl):
    decl = decl.strip()
    if decl.endswith("*"):
        return (8, 8)
    if decl == "ProtobufCMessage":
        return (24, 8)
    if decl == "ProtobufCBinaryData":
        return (TYPE_SIZE, 8)
    if decl == "protobuf_c_boolean":
        return (4, 4)
    t = {
        "int32_t": (4, 4), "uint32_t": (4, 4), "int64_t": (8, 8),
        "uint64_t": (8, 8), "float": (4, 4), "double": (8, 8),
        "size_t": (8, 8), "char": (1, 1),
    }
    if decl in t:
        return t[decl]
    if decl in ENUM_SIZES:
        return (4, 4)
    if decl in STRUCTS:
        return (STRUCTS[decl][0], 8)
    raise ValueError(f"unknown type {decl!r}")


def parse_structs(hdr):
    for m in re.finditer(r"struct\s+(\w+)\s*\{(.*?)\};", hdr, re.S):
        name = m.group(1)
        if name.endswith("_Service"):
            continue  # service structs carry fn-pointer members, not data
        body = m.group(2)
        members = []
        lines = body.splitlines()
        li = 0
        while li < len(lines):
            line = lines[li].split("/*")[0].strip()
            if not line:
                li += 1
                continue
            if line.startswith("union"):
                umembers = []
                li += 1
                while li < len(lines):
                    ul = lines[li].split("/*")[0].strip()
                    if ul.startswith("};"):
                        break
                    fm = re.match(r"([\w\s]+?)\s*(\**)\s*(\w+)(?:\s+PROTOBUF_C__DEPRECATED)?;", ul)
                    if fm:
                        if fm.group(2):
                            t = (8, 8)
                        else:
                            t = c_type(fm.group(1))
                        umembers.append((fm.group(3), t))
                    li += 1
                members.append((umembers[0][0], ("union", umembers)))
                li += 1
                continue
            fm = re.match(r"([\w\s]+?)\s*(\**)\s*(\w+)(?:\s+PROTOBUF_C__DEPRECATED)?;", line)
            if fm:
                if fm.group(2):
                    t = (8, 8)
                else:
                    t = c_type(fm.group(1))
                members.append((fm.group(3), t))
            li += 1
        # compute size + offsets
        off = 0
        max_align = 1
        offsets = {}
        for fieldname, spec in members:
            if isinstance(spec, tuple) and len(spec) == 2 and spec[0] == "union":
                usz = align_up(max(m[1][0] for m in spec[1]), max(m[1][1] for m in spec[1]))
                ual = max(m[1][1] for m in spec[1])
                sz, al = usz, ual
            else:
                sz, al = spec
            off = align_up(off, al)
            if isinstance(spec, tuple) and len(spec) == 2 and spec[0] == "union":
                for uname, _u in spec[1]:
                    offsets[uname] = off
            else:
                offsets[fieldname] = off
            off += sz
            max_align = max(max_align, al)
        total = align_up(off, max_align)
        STRUCTS[name] = (total, offsets, members)


parse_structs(full_h)
parse_structs(p3_h)

# ---------------------------------------------------------------------------
# parse the .c descriptor tables
# ---------------------------------------------------------------------------

def parse_field_descriptors(src):
    out = {}
    for m in re.finditer(
        r"static const ProtobufCFieldDescriptor (\w+__field_descriptors)\[\d*\]\s*=\s*\{(.*?)\n\};",
        src, re.S):
        name = m.group(1)
        body = re.sub(r"/\*.*?\*/", "", m.group(2), flags=re.S)
        blocks = re.findall(r"\{\s*(.*?)\s*\}", body, re.S)
        fields = []
        for b in blocks:
            parts = split_top_level(b)
            fields.append({
                "name": parts[0].strip('"'),
                "id": int(parts[1]),
                "label": parts[2],
                "type": parts[3],
                "quantifier_offset": parts[4],
                "offset": parts[5],
                "descriptor": parts[6],
                "default_value": parts[7],
                "flags": parts[8],
            })
        out[name] = fields
    return out


full_fd = parse_field_descriptors(full_c)
p3_fd = parse_field_descriptors(p3_c)


def parse_uints_array(src, arrname):
    m = re.search(
        r"static const unsigned " + re.escape(arrname) + r"\[\d*\]\s*=\s*\{(.*?)\n\};",
        src, re.S)
    if not m:
        return None
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    return [int(n) for n in re.findall(r"\d+", body)]


def parse_ranges(src, arrname):
    m = re.search(
        r"static const ProtobufCIntRange " + re.escape(arrname) + r"\[[\d\s\+]*\]\s*=\s*\{(.*?)\n\};",
        src, re.S)
    if not m:
        return None
    return [(int(a), int(b)) for a, b in
            re.findall(r"\{\s*(-?\d+)\s*,\s*(\d+)\s*\}", m.group(1))]


def parse_message_descriptors(src):
    out = {}
    for m in re.finditer(
        r"const ProtobufCMessageDescriptor (\w+__descriptor)\s*=\s*\{(.*?)\n\};",
        src, re.S):
        name = m.group(1)
        body = re.sub(r"/\*.*?\*/", "", m.group(2), flags=re.S)
        parts = [p.strip() for p in body.split(",") if p.strip()]
        out[name] = {
            "name": parts[1].strip('"'),
            "short_name": parts[2].strip('"'),
            "c_name": parts[3].strip('"'),
            "package": parts[4].strip('"'),
            "n_fields": int(parts[6]),
            "n_field_ranges": int(parts[9]),
        }
    return out


full_md = parse_message_descriptors(full_c)
p3_md = parse_message_descriptors(p3_c)


def parse_enum_value_array(src, arrname):
    m = re.search(
        r"static const ProtobufCEnumValue " + re.escape(arrname) + r"\[\d*\]\s*=\s*\{(.*?)\n\};",
        src, re.S)
    if not m:
        return None
    return [(n, cn, int(v)) for n, cn, v in
            re.findall(r'\{\s*"([^"]+)",\s*"([^"]+)",\s*(-?\d+)\s*\}', m.group(1))]


def parse_enum_value_index_array(src, arrname):
    m = re.search(
        r"static const ProtobufCEnumValueIndex " + re.escape(arrname) + r"\[\d*\]\s*=\s*\{(.*?)\n\};",
        src, re.S)
    if not m:
        return None
    return [(n, int(i)) for n, i in re.findall(r'\{\s*"([^"]+)",\s*(\d+)\s*\}', m.group(1))]


def parse_enum_descriptors(src):
    out = {}
    for m in re.finditer(
        r"const ProtobufCEnumDescriptor (\w+__descriptor)\s*=\s*\{(.*?)\n\};",
        src, re.S):
        name = m.group(1)
        body = re.sub(r"/\*.*?\*/", "", m.group(2), flags=re.S)
        parts = [p.strip() for p in body.split(",") if p.strip()]
        out[name] = {
            "name": parts[1].strip('"'), "short_name": parts[2].strip('"'),
            "c_name": parts[3].strip('"'), "package": parts[4].strip('"'),
            "n_values": int(parts[5]), "n_value_names": int(parts[7]),
            "n_value_ranges": int(parts[9]),
        }
    return out


full_ed = parse_enum_descriptors(full_c)
p3_ed = parse_enum_descriptors(p3_c)

LABEL = {
    "PROTOBUF_C_LABEL_REQUIRED": 0, "PROTOBUF_C_LABEL_OPTIONAL": 1,
    "PROTOBUF_C_LABEL_REPEATED": 2, "PROTOBUF_C_LABEL_NONE": 3,
}
TYPE = {
    "PROTOBUF_C_TYPE_INT32": 0, "PROTOBUF_C_TYPE_SINT32": 1,
    "PROTOBUF_C_TYPE_SFIXED32": 2, "PROTOBUF_C_TYPE_INT64": 3,
    "PROTOBUF_C_TYPE_SINT64": 4, "PROTOBUF_C_TYPE_SFIXED64": 5,
    "PROTOBUF_C_TYPE_UINT32": 6, "PROTOBUF_C_TYPE_FIXED32": 7,
    "PROTOBUF_C_TYPE_UINT64": 8, "PROTOBUF_C_TYPE_FIXED64": 9,
    "PROTOBUF_C_TYPE_FLOAT": 10, "PROTOBUF_C_TYPE_DOUBLE": 11,
    "PROTOBUF_C_TYPE_BOOL": 12, "PROTOBUF_C_TYPE_ENUM": 13,
    "PROTOBUF_C_TYPE_STRING": 14, "PROTOBUF_C_TYPE_BYTES": 15,
    "PROTOBUF_C_TYPE_MESSAGE": 16,
}
FLAG = {
    "PROTOBUF_C_FIELD_FLAG_PACKED": 1, "PROTOBUF_C_FIELD_FLAG_DEPRECATED": 2,
    "PROTOBUF_C_FIELD_FLAG_ONEOF": 4,
}


def parse_default_statics(src):
    statics = {}
    for m in re.finditer(
        r"static const (int32_t|uint32_t|int64_t|uint64_t|float|double) "
        r"(\w+__default_value)\s*=\s*([^;]+);", src):
        ty, sym, val = m.group(1), m.group(2), m.group(3).strip().rstrip("u")
        if ty == "float":
            bits = struct.unpack("<I", struct.pack("<f", float(val)))[0]
            statics[sym] = f"Some(DefaultValue::F32(0x{bits:08x}))"
        elif ty == "double":
            bits = struct.unpack("<Q", struct.pack("<d", float(val)))[0]
            statics[sym] = f"Some(DefaultValue::F64(0x{bits:016x}))"
        elif ty == "int32_t":
            statics[sym] = f"Some(DefaultValue::I32({int(val)}))"
        elif ty == "uint32_t":
            statics[sym] = f"Some(DefaultValue::U32({int(val)}))"
        elif ty == "int64_t":
            statics[sym] = f"Some(DefaultValue::I64({int(val)}i64))"
        elif ty == "uint64_t":
            statics[sym] = f"Some(DefaultValue::U64({int(val)}))"
    for m in re.finditer(
        r"static const ProtobufCBinaryData (\w+__default_value)\s*=\s*\{\s*(\d+)\s*,\s*(\w+__default_value_data)\s*\};",
        src):
        sym, length, data_sym = m.group(1), int(m.group(2)), m.group(3)
        dm = re.search(
            r"(?:uint8_t|char) " + re.escape(data_sym) + r"\[\]\s*=\s*\"([^\"]*)\";", src)
        data = parse_c_string(dm.group(1))
        assert len(data) == length, (sym, len(data), length)
        rust = ", ".join(f"0x{b:02x}" for b in data)
        statics[sym] = f"Some(DefaultValue::Bin(&[{rust}]))"
    for m in re.finditer(
        r"char (\w+__default_value)\[\]\s*=\s*\"([^\"]*)\";", src):
        sym = m.group(1)
        s = parse_c_string(m.group(2))
        rust = "".join(
            f"\\x{b:02x}" if b < 0x20 or b >= 0x7F or b in (0x22, 0x5C) else chr(b)
            for b in s)
        statics[sym] = f'Some(DefaultValue::Str("{rust}"))'
    return statics


DEFAULT_STATICS = {}
DEFAULT_STATICS.update(parse_default_statics(full_c))
DEFAULT_STATICS.update(parse_default_statics(p3_c))


def default_to_rust(expr):
    expr = expr.strip()
    if expr == "NULL":
        return "None"
    if expr == "&protobuf_c_empty_string":
        return 'Some(DefaultValue::Str(""))'
    if expr.startswith("&"):
        sym = expr[1:]
        if sym in DEFAULT_STATICS:
            return DEFAULT_STATICS[sym]
        raise ValueError(f"unresolved default static {sym}")
    return "None"


def offset_of_expr(expr, struct, offsets):
    expr = expr.strip()
    if expr == "0":
        return 0
    m = re.match(r"offsetof\((\w+),\s*(\w+)\)", expr)
    if not m:
        raise ValueError(f"bad offset expr {expr!r}")
    _, field = m.group(1), m.group(2)
    if field not in offsets:
        raise ValueError(f"{struct}: no member {field}")
    return offsets[field]


# ---------------------------------------------------------------------------
# INIT macros
# ---------------------------------------------------------------------------

def parse_init_macro(hdr, struct_name):
    scope, ty = struct_name.split("__", 1)
    macro = f"{scope.upper()}__{camel_to_snake_upper(ty)}__INIT"
    m = re.search(
        r"#define\s+" + re.escape(macro) + r"\s+\\\s*\{(.*?)\}\s*\n",
        hdr, re.S)
    if not m:
        return None
    body = m.group(1)
    body = re.sub(r"PROTOBUF_C_MESSAGE_INIT\s*\([^)]*\)", "", body)
    body = re.sub(r"\\\n\s*", " ", body)
    parts = []
    depth = 0
    cur = ""
    for ch in body:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def init_value_to_rust(expr):
    expr = expr.strip()
    if expr == "NULL":
        return None
    if expr.startswith("(char *)protobuf_c_empty_string"):
        return ("str", "")
    if expr.startswith("{") and "default_value_data" in expr:
        m = re.search(r"\{\s*(\d+)\s*,\s*(\w+__default_value_data)\s*\}", expr)
        length = int(m.group(1))
        data_sym = m.group(2)
        for src in (full_c, p3_c):
            dm = re.search(
                r"(?:uint8_t|char) " + re.escape(data_sym) + r"\[\]\s*=\s*\"([^\"]*)\";", src)
            if dm:
                data = parse_c_string(dm.group(1))
                assert len(data) == length
                rust = ", ".join(f"0x{b:02x}" for b in data)
                return ("bin", f"BinValue {{ len: {length}, data: Some(vec![{rust}]) }}")
        raise ValueError(f"no data for {data_sym}")
    if re.fullmatch(r"-?\d+u?", expr):
        return ("int", int(expr.rstrip("u")))
    if re.fullmatch(r"-?\d+\.\d+", expr):
        return ("float", float(expr))
    if expr in ENUM_INDEX_BY_NAME:
        return ("enum", ENUM_INDEX_BY_NAME[expr])
    if expr.endswith("__default_value"):
        if expr in DEFAULT_STATICS:
            dv = DEFAULT_STATICS[expr]
            if "F32" in dv:
                return ("floatbits", int(dv.split("0x")[1][:8], 16))
            if "F64" in dv:
                return ("doublebits", int(dv.split("0x")[1][:16], 16))
            if "I32" in dv:
                return ("int", int(dv.split("(")[1].split(")")[0]))
            if "U32" in dv:
                return ("int", int(dv.split("(")[1].split("u")[0]))
            if "Str" in dv:
                return ("str", dv.split('("')[1].split('")')[0])
        return None
    return None


def init_defaults(hdr, struct_name):
    parts = parse_init_macro(hdr, struct_name)
    if parts is None:
        return []
    size, offsets, members = STRUCTS[struct_name]
    result = []
    mi = 0
    for p in parts:
        if mi >= len(members):
            break
        fname = members[mi][0]
        if re.fullmatch(r"\d+,\s*NULL", p):
            result.append((fname, "repeated-empty", None))
            mi += 2
            continue
        v = init_value_to_rust(p)
        result.append((fname, "val", v))
        mi += 1
    return result


TS = TYPE["PROTOBUF_C_TYPE_STRING"]
TB = TYPE["PROTOBUF_C_TYPE_BYTES"]
TM = TYPE["PROTOBUF_C_TYPE_MESSAGE"]
TU32 = TYPE["PROTOBUF_C_TYPE_UINT32"]
TF32 = TYPE["PROTOBUF_C_TYPE_FIXED32"]
TFLOAT = TYPE["PROTOBUF_C_TYPE_FLOAT"]
TI64 = TYPE["PROTOBUF_C_TYPE_INT64"]
TSI64 = TYPE["PROTOBUF_C_TYPE_SINT64"]
TSF64 = TYPE["PROTOBUF_C_TYPE_SFIXED64"]
TU64 = TYPE["PROTOBUF_C_TYPE_UINT64"]
TF64 = TYPE["PROTOBUF_C_TYPE_FIXED64"]
TDOUBLE = TYPE["PROTOBUF_C_TYPE_DOUBLE"]


# ---------------------------------------------------------------------------
# emit
# ---------------------------------------------------------------------------

MESSAGES = [
    ("foo__sub_mess__sub_sub_mess", "Foo__SubMess__SubSubMess", full_c, full_h, "sub_sub_mess"),
    ("foo__sub_mess", "Foo__SubMess", full_c, full_h, "sub_mess"),
    ("foo__test_field_no15", "Foo__TestFieldNo15", full_c, full_h, "test_field_no15"),
    ("foo__test_field_no16", "Foo__TestFieldNo16", full_c, full_h, "test_field_no16"),
    ("foo__test_field_no2047", "Foo__TestFieldNo2047", full_c, full_h, "test_field_no2047"),
    ("foo__test_field_no2048", "Foo__TestFieldNo2048", full_c, full_h, "test_field_no2048"),
    ("foo__test_field_no262143", "Foo__TestFieldNo262143", full_c, full_h, "test_field_no262143"),
    ("foo__test_field_no262144", "Foo__TestFieldNo262144", full_c, full_h, "test_field_no262144"),
    ("foo__test_field_no33554431", "Foo__TestFieldNo33554431", full_c, full_h, "test_field_no33554431"),
    ("foo__test_field_no33554432", "Foo__TestFieldNo33554432", full_c, full_h, "test_field_no33554432"),
    ("foo__test_mess", "Foo__TestMess", full_c, full_h, "test_mess"),
    ("foo__test_mess_packed", "Foo__TestMessPacked", full_c, full_h, "test_mess_packed"),
    ("foo__test_mess_optional", "Foo__TestMessOptional", full_c, full_h, "test_mess_optional"),
    ("foo__test_mess_oneof", "Foo__TestMessOneof", full_c, full_h, "test_mess_oneof"),
    ("foo__test_mess_required_int32", "Foo__TestMessRequiredInt32", full_c, full_h, "test_mess_required_int32"),
    ("foo__test_mess_required_string", "Foo__TestMessRequiredString", full_c, full_h, "test_mess_required_string"),
    ("foo__test_mess_required_message", "Foo__TestMessRequiredMessage", full_c, full_h, "test_mess_required_message"),
    ("foo__empty_mess", "Foo__EmptyMess", full_c, full_h, "empty_mess"),
    ("foo__default_required_values", "Foo__DefaultRequiredValues", full_c, full_h, "default_required_values"),
    ("foo__default_optional_values", "Foo__DefaultOptionalValues", full_c, full_h, "default_optional_values"),
    ("foo__test_message_check__sub_message", "Foo__TestMessageCheck__SubMessage", full_c, full_h, "check_sub"),
    ("foo__test_message_check", "Foo__TestMessageCheck", full_c, full_h, "test_message_check"),
    ("foo__test_required_fields_bitmap", "Foo__TestRequiredFieldsBitmap", full_c, full_h, "test_required_fields_bitmap"),
    ("foo__test_mess_sub_mess", "Foo__TestMessSubMess", full_c, full_h, "test_mess_sub_mess"),
    ("foo__person__phone_number__comment", "Foo__Person__PhoneNumber__Comment", p3_c, p3_h, "p3_comment"),
    ("foo__person__phone_number", "Foo__Person__PhoneNumber", p3_c, p3_h, "p3_phone_number"),
    ("foo__person", "Foo__Person", p3_c, p3_h, "p3_person"),
    ("foo__lookup_result", "Foo__LookupResult", p3_c, p3_h, "p3_lookup_result"),
    ("foo__name", "Foo__Name", p3_c, p3_h, "p3_name"),
]

ENUMS = [
    ("foo__test_enum_small", full_c, "test_enum_small"),
    ("foo__test_enum", full_c, "test_enum"),
    ("foo__test_enum_dup_values", full_c, "test_enum_dup"),
    ("foo__person__phone_type", p3_c, "p3_phone_type"),
]

md_of = {}
md_of.update(full_md)
md_of.update(p3_md)
fd_of = {}
fd_of.update(full_fd)
fd_of.update(p3_fd)
ed_of = {}
ed_of.update(full_ed)
ed_of.update(p3_ed)

out = []
w = out.append

w("//! Generated descriptor fixtures for the PBC-0001 probe.")
w("//!")
w("//! Generated by `forensics/oracle/probes/gen_descriptors.py` from the")
w("//! checked-in protoc-gen-c 1.5.2 fixture files")
w("//! (`forensics/oracle/probes/protobuf-c-gen/`), which were generated with")
w("//! the pinned plugin from the pinned tarball's own t/test-full.proto and")
w("//! t/test-proto3.proto (protoc 3.21.12, the era the plugin builds")
w("//! against).  The C struct layout (sizes/offsets, x86-64 SysV) is computed")
w("//! here so the Rust descriptors carry the same sizeof_message/quantifier")
w("//! offsets as the C oracle descriptors.")
w("")
w("use bind9_rs_tools::compat::protobuf_c::{")
w("    BinValue, DefaultValue, DescriptorRef, EnumDescriptor, EnumValue,")
w("    EnumValueIndex, Field, FieldDescriptor, IntRange, Message, MessageDescriptor,")
w("    MethodDescriptor, ServiceDescriptor, Value,")
w("    SERVICE_DESCRIPTOR_MAGIC, MESSAGE_DESCRIPTOR_MAGIC, ENUM_DESCRIPTOR_MAGIC,")
w("    LABEL_REQUIRED, LABEL_OPTIONAL, LABEL_REPEATED, LABEL_NONE,")
w("    TYPE_INT32, TYPE_SINT32, TYPE_SFIXED32, TYPE_INT64, TYPE_SINT64, TYPE_SFIXED64,")
w("    TYPE_UINT32, TYPE_FIXED32, TYPE_UINT64, TYPE_FIXED64, TYPE_FLOAT, TYPE_DOUBLE,")
w("    TYPE_BOOL, TYPE_ENUM, TYPE_STRING, TYPE_BYTES, TYPE_MESSAGE,")
w("    FIELD_FLAG_PACKED, FIELD_FLAG_ONEOF, TRUE, FALSE,")
w("};")
w("")
w("fn set_scalar(m: &mut Message, idx: usize, has: bool, v: Value) {")
w("    m.fields[idx] = Field::Scalar { has: if has { TRUE } else { FALSE }, value: v };")
w("}")
w("fn set_ptr(m: &mut Message, idx: usize, v: Value) {")
w("    m.fields[idx] = Field::Pointer { has: FALSE, value: Some(v) };")
w("}")
w("fn set_bin(m: &mut Message, idx: usize, len: usize, bytes: Vec<u8>) {")
w("    m.fields[idx] = Field::Pointer { has: FALSE, value: Some(Value::Bin(BinValue { len, data: Some(bytes) })) };")
w("}")
w("")

# init fns (need the All struct name -> use a global static)
w("static ALL: std::sync::OnceLock<&'static All> = std::sync::OnceLock::new();")
w("pub fn all() -> &'static All {")
w("    *ALL.get_or_init(build)")
w("}")
w("")
w("pub struct All {")
for _prefix, _struct, _src, _hdr, key in MESSAGES:
    w(f"    pub {key}: &'static MessageDescriptor,")
for _prefix, _src, key in ENUMS:
    w(f"    pub {key}: &'static EnumDescriptor,")
w("    pub dir_lookup: &'static ServiceDescriptor,")
w("}")
w("")
w("pub fn build() -> &'static All {")

# enum construction
for prefix, src, key in ENUMS:
    ed = ed_of[f"{prefix}__descriptor"]
    values = parse_enum_value_array(src, f"{prefix}__enum_values_by_number")
    byname = parse_enum_value_index_array(src, f"{prefix}__enum_values_by_name")
    ranges = parse_ranges(src, f"{prefix}__value_ranges")
    vals = ", ".join(
        f'EnumValue {{ name: "{v[0]}", c_name: "{v[1]}", value: {v[2]} }}' for v in values)
    bn = ", ".join(f'EnumValueIndex {{ name: "{n}", index: {i} }}' for n, i in byname)
    rg = ", ".join(f"IntRange {{ start_value: {a}, orig_index: {b} }}" for a, b in ranges)
    w(f"    let {key}: &'static EnumDescriptor = Box::leak(Box::new(EnumDescriptor {{")
    w(f"        magic: ENUM_DESCRIPTOR_MAGIC,")
    w(f'        name: "{ed["name"]}", short_name: "{ed["short_name"]}",')
    w(f'        c_name: "{ed["c_name"]}", package_name: "{ed["package"]}",')
    w(f"        values: Box::leak(vec![{vals}].into_boxed_slice()),")
    w(f"        values_by_name: Box::leak(vec![{bn}].into_boxed_slice()),")
    w(f"        value_ranges: Box::leak(vec![{rg}].into_boxed_slice()),")
    w(f"        n_value_ranges: {ed['n_value_ranges']},")
    w(f"    }}));")
    w("")

# init fns + message construction, in dependency order
for prefix, st, src, hdr, key in MESSAGES:
    md = md_of[f"{prefix}__descriptor"]
    fields = fd_of.get(f"{prefix}__field_descriptors", [])
    indices = parse_uints_array(src, f"{prefix}__field_indices_by_name")
    ranges = parse_ranges(src, f"{prefix}__number_ranges") or []
    size, offsets, members = STRUCTS[st]

    fl = []
    for f in fields:
        label = LABEL[f["label"]]
        ty = TYPE[f["type"]]
        qo = offset_of_expr(f["quantifier_offset"], st, offsets)
        off = offset_of_expr(f["offset"], st, offsets)
        dv = default_to_rust(f["default_value"])
        flags = 0
        for tok in f["flags"].split("|"):
            if tok.strip() in FLAG:
                flags |= FLAG[tok.strip()]
        fl.append((f, label, ty, qo, off, dv, flags))

    # init fn from the INIT macro
    w(f"    // --- {st} ---")
    defaults = init_defaults(hdr, st)
    has_defaults = any(
        kind == "val" and v is not None
        for _fname, kind, v in defaults
    )
    w(f"    fn {key}_init({'m' if has_defaults else '_m'}: &mut Message) {{")
    fname_to_idx = {f[0]["name"]: i for i, f in enumerate(fl)}
    for fname, kind, v in defaults:
        if kind == "repeated-empty":
            continue
        idx = fname_to_idx.get(fname)
        if idx is None:
            continue
        fdesc = [f for f in fl if f[0]["name"] == fname][0]
        label, ty, qo = fdesc[1], fdesc[2], fdesc[3]
        if v is None:
            continue
        kind2, val = v
        if ty in (TS, TB, TM):
            if kind2 == "str":
                w(f'        set_ptr(m, {idx}, Value::Str("{val}".into()));')
            elif kind2 == "bin":
                m2 = re.search(r"BinValue \{ len: (\d+), data: Some\(vec!\[([^]]*)\]\) \}", val)
                if m2:
                    w(f"        set_bin(m, {idx}, {m2.group(1)}, vec![{m2.group(2)}]);")
                else:
                    w(f"        set_bin(m, {idx}, {val});")
        else:
            has = "true" if qo == 0 else "false"
            if kind2 == "int":
                if ty in (TU32, TF32, TFLOAT):
                    w(f"        set_scalar(m, {idx}, {has}, Value::U32({val}));")
                elif ty in (TI64, TSI64, TSF64):
                    w(f"        set_scalar(m, {idx}, {has}, Value::I64({val}i64));")
                elif ty in (TU64, TF64, TDOUBLE):
                    w(f"        set_scalar(m, {idx}, {has}, Value::U64({val}));")
                else:
                    w(f"        set_scalar(m, {idx}, {has}, Value::I32({val}));")
            elif kind2 == "enum":
                w(f"        set_scalar(m, {idx}, {has}, Value::Enum({val}));")
            elif kind2 == "float":
                if ty == TDOUBLE:
                    bits = struct.unpack("<Q", struct.pack("<d", val))[0]
                    w(f"        set_scalar(m, {idx}, {has}, Value::F64(0x{bits:016x}));")
                else:
                    bits = struct.unpack("<I", struct.pack("<f", val))[0]
                    w(f"        set_scalar(m, {idx}, {has}, Value::F32(0x{bits:08x}));")
            elif kind2 == "floatbits":
                w(f"        set_scalar(m, {idx}, {has}, Value::F32(0x{val:08x}));")
            elif kind2 == "doublebits":
                w(f"        set_scalar(m, {idx}, {has}, Value::F64(0x{val:016x}));")
    w("    }")
    w("")

# message construction
for prefix, st, src, hdr, key in MESSAGES:
    md = md_of[f"{prefix}__descriptor"]
    fields = fd_of.get(f"{prefix}__field_descriptors", [])
    indices = parse_uints_array(src, f"{prefix}__field_indices_by_name")
    ranges = parse_ranges(src, f"{prefix}__number_ranges") or []
    size, offsets, members = STRUCTS[st]

    fl = []
    for f in fields:
        label = LABEL[f["label"]]
        ty = TYPE[f["type"]]
        qo = offset_of_expr(f["quantifier_offset"], st, offsets)
        off = offset_of_expr(f["offset"], st, offsets)
        dv = default_to_rust(f["default_value"])
        flags = 0
        for tok in f["flags"].split("|"):
            if tok.strip() in FLAG:
                flags |= FLAG[tok.strip()]
        fl.append((f, label, ty, qo, off, dv, flags))

    w(f"    let {key}: &'static MessageDescriptor = Box::leak(Box::new(MessageDescriptor {{")
    w(f"        magic: MESSAGE_DESCRIPTOR_MAGIC,")
    w(f'        name: "{md["name"]}", short_name: "{md["short_name"]}",')
    w(f'        c_name: "{md["c_name"]}", package_name: "{md["package"]}",')
    w(f"        sizeof_message: {size},")
    w(f"        fields: Box::leak(vec![")
    for f, label, ty, qo, off, dv, flags in fl:
        desc = "None"
        if f["descriptor"].startswith("&"):
            sym = f["descriptor"][1:]
            found = False
            for p2, _st2, _s2, _h2, k2 in MESSAGES:
                if sym == f"{p2}__descriptor":
                    desc = f"Some(DescriptorRef::Msg({k2}))"
                    found = True
            for p2, _s2, k2 in ENUMS:
                if sym == f"{p2}__descriptor":
                    desc = f"Some(DescriptorRef::Enum({k2}))"
                    found = True
            if not found:
                raise ValueError(f"unresolved descriptor ref {sym}")
        w(f'            FieldDescriptor {{ name: "{f["name"]}", id: {f["id"]}, label: {label},')
        w(f"                ty: {ty}, quantifier_offset: {qo}, offset: {off},")
        w(f"                descriptor: {desc}, default_value: {dv}, flags: {flags} }},")
    w(f"        ].into_boxed_slice()),")
    if indices:
        inds = ", ".join(str(i) for i in indices)
        w(f"        fields_sorted_by_name: Some(Box::leak(vec![{inds}].into_boxed_slice())),")
    else:
        w(f"        fields_sorted_by_name: None,")
    rg = ", ".join(f"IntRange {{ start_value: {a}, orig_index: {b} }}" for a, b in ranges)
    w(f"        field_ranges: Box::leak(vec![{rg}].into_boxed_slice()),")
    w(f"        n_field_ranges: {md['n_field_ranges']},")
    w(f"        message_init: Some({key}_init),")
    w(f"    }}));")
    w("")

# service
w("    let dir_lookup: &'static ServiceDescriptor = Box::leak(Box::new(ServiceDescriptor {")
w("        magic: SERVICE_DESCRIPTOR_MAGIC,")
w('        name: "foo.DirLookup", short_name: "DirLookup", c_name: "Foo__DirLookup", package: "foo",')
w("        methods: Box::leak(vec![MethodDescriptor { name: \"ByName\", input: p3_name, output: p3_lookup_result }].into_boxed_slice()),")
w("        method_indices_by_name: Some(Box::leak(vec![0].into_boxed_slice())),")
w("    }));")
w("")
w("    Box::leak(Box::new(All {")
for _prefix, _struct, _src, _hdr, key in MESSAGES:
    w(f"        {key},")
for _prefix, _src, key in ENUMS:
    w(f"        {key},")
w("        dir_lookup,")
w("    }))")
w("}")
w("")

# sizes
w("// struct sizes (x86-64 SysV, matching the C oracle's sizeof())")
w("pub const SIZES: &[(&str, usize)] = &[")
for prefix, st, src, hdr, key in MESSAGES:
    size, offsets, members = STRUCTS[st]
    name = st.replace("Foo__", "")
    w(f'    ("{name}", {size}),')
w("];")

open("bind9-rs-tools/src/bin/protobuf_c_gen/mod.rs", "w").write("\n".join(out) + "\n")
print(f"wrote bind9-rs-tools/src/bin/protobuf_c_gen.rs ({len(out)} lines)")

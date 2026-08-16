//! jsonc-probe — Rust mirror of `forensics/oracle/probes/probe-jsonc.c`
//! for the JSON-0001 court (§35, §37).  Runs in the same oracle-json-c
//! container; stdout must be byte-identical.
//!
//! Usage: jsonc-probe

use bind9_rs_tools::compat::json_c::*;

fn typname(t: &JsonValue) -> &'static str {
    match t.json_type() {
        JsonType::Null => "null",
        JsonType::Boolean => "boolean",
        JsonType::Double => "double",
        JsonType::Int => "int",
        JsonType::Object => "object",
        JsonType::Array => "array",
        JsonType::String => "string",
    }
}

fn show(label: &str, o: &JsonValue, flags: u32) {
    let s = json_object_to_json_string_ext(o, flags);
    println!("    {label:<12} -> {}", String::from_utf8_lossy(&s));
}

fn parse_one(inp: &str) {
    let (o, err) = json_tokener_parse_verbose(inp);
    match o {
        None => {
            println!(
                "  {inp:<28} -> NULL err={err} {}",
                json_tokener_error_desc(err)
            );
        }
        Some(JsonValue::Null) => {
            // the C probe sees the null OBJECT as a NULL pointer with
            // success (json_object_get(NULL) == NULL)
            println!("  {inp:<28} -> NULL err=0 success");
        }
        Some(v) => {
            println!("  {inp:<28} -> type={}", typname(&v));
            show("PLAIN", &v, JSON_C_TO_STRING_PLAIN);
            show("SPACED", &v, JSON_C_TO_STRING_SPACED);
            show("PRETTY", &v, JSON_C_TO_STRING_PRETTY);
            show(
                "PRETTY|TAB",
                &v,
                JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_PRETTY_TAB,
            );
            show(
                "PRETTY|SPACED",
                &v,
                JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED,
            );
            show("NOZERO", &v, JSON_C_TO_STRING_NOZERO);
            show("NOSLASH", &v, JSON_C_TO_STRING_NOSLASHESCAPE);
            show("COLOR", &v, JSON_C_TO_STRING_COLOR);
            show(
                "SPACED|NOSLASH",
                &v,
                JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE,
            );
        }
    }
}

fn parse_strict(inp: &str) {
    let (o, err) = json_tokener_parse_ex(inp, JSON_TOKENER_STRICT, JSON_TOKENER_DEFAULT_DEPTH);
    let s = match o {
        Some(JsonValue::Null) => "NULL".to_string(),
        Some(v) => String::from_utf8_lossy(&json_object_to_json_string(&v)).into_owned(),
        None => "NULL".to_string(),
    };
    println!(
        "  STRICT {inp:<22} -> {s} err={err} {}",
        json_tokener_error_desc(err)
    );
}

fn main() {
    println!("== version ==\n{} {}", json_c_version(), JSON_C_VERSION_NUM);

    println!("== error descs ==");
    for i in 0..=16 {
        println!("  {i}: {}", json_tokener_error_desc(i));
    }
    println!("  99: {}", json_tokener_error_desc(99));

    println!("== parse corpus ==");
    let corpus = [
        "null",
        "true",
        "false",
        "TRUE",
        "FALSE",
        "Null",
        "nulll",
        "123",
        "-123",
        "0",
        "-0",
        "01",
        "1.5",
        "1.50",
        "-1.5e-3",
        "1e10",
        "1e+",
        "1E10",
        "123e+",
        "9223372036854775807",
        "9223372036854775808",
        "18446744073709551615",
        "18446744073709551616",
        "-9223372036854775808",
        "-9223372036854775809",
        "NaN",
        "Infinity",
        "-Infinity",
        "iNFINITY",
        "123abc",
        "nullx",
        "truefalse",
        "nul",
        "tru",
        "nuX",
        "truX",
        "01.",
        ".5",
        "1.2.3",
        "-",
        "-x",
        "1e",
        "1e-",
        "1e+5",
        "1.5e",
        "\"hello\"",
        "\"\"",
        "'single'",
        "\"a\\nb\\tc\\r\\fd\\\\e\\/f\"",
        "\"\\u0041\\u00e9\\ud83d\\ude00\"",
        "\"\\ud83d\"",
        "\"\\ude00\"",
        "\"a\\u0000b\"",
        "\"a\\q\"",
        "\"abc",
        "\"a\\u12\"",
        "[]",
        "[1,2,3]",
        "[1,]",
        "[,1]",
        "[1 2]",
        "[1,2",
        "[[[1]]]",
        "{}",
        "{\"a\":1}",
        "{\"a\":1,\"b\":[true,null,\"x/y\"]}",
        "{'a':1}",
        "{a:1}",
        "{\"a\" 1}",
        "{\"a\":1 \"b\":2}",
        "{\"a\":1,\"a\":2}",
        "{\"a\":1,}",
        "{,\"a\":1}",
        "{\"a\"}",
        "{\"a\":}",
        "/* hi */1",
        "// hi\n1",
        "1/*x*/2",
        "/*x*/",
        "/x",
        "1 /*a*/ + 2",
        " 1 ",
        "\t1\n",
        "\"\\u00e9\"x",
        "1 2",
        "\"a\" \"b\"",
    ];
    for c in corpus {
        parse_one(c);
    }

    println!("== strict ==");
    let strict = [
        "01",
        "1e+",
        "1 2",
        "[1,]",
        "'a'",
        "NaN",
        "Infinity",
        "iNFINITY",
        "null",
        "\"a\\nb\"",
        "/*x*/1",
        "123",
        "1.5",
        "true",
        "{}",
    ];
    for s in strict {
        parse_strict(s);
    }

    println!("== depth ==");
    for n in 31..=34 {
        let buf = "[".repeat(n) + &"]".repeat(n);
        let (o, err) = json_tokener_parse_verbose(&buf);
        println!(
            "  depth {n} -> {} err={err} {}",
            if o.is_some() { "OK" } else { "NULL" },
            json_tokener_error_desc(err)
        );
    }

    println!("== programmatic ==");
    {
        let ds = [
            0.0f64,
            -0.0,
            1.5,
            42.0,
            0.1,
            1e300,
            1e-5,
            1e15,
            3.141592653589793,
            123456789.123456789,
            2.2250738585072014e-308,
            1.7976931348623157e308,
            2.5e-4,
            1e-4,
            123456.789,
            -1.5e20,
        ];
        for d in ds {
            let dv = JsonValue::Double(d, None);
            show("dbl PLAIN", &dv, JSON_C_TO_STRING_PLAIN);
            show(
                "dbl NOZERO",
                &dv,
                JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOZERO,
            );
            println!("    dbl value   -> {}", json_printf_g17(d));
        }
    }
    {
        let o = JsonValue::Object(vec![
            (b"i64max".to_vec(), JsonValue::Int64(i64::MAX)),
            (b"i64min".to_vec(), JsonValue::Int64(i64::MIN)),
            (b"u64max".to_vec(), JsonValue::Uint64(u64::MAX)),
            (b"zero".to_vec(), JsonValue::Int64(0)),
            (b"neg".to_vec(), JsonValue::Int64(-42)),
        ]);
        show("ints", &o, JSON_C_TO_STRING_SPACED);
    }
    {
        let o = JsonValue::Object(vec![
            (b"s".to_vec(), JsonValue::String(b"x/y\\z\"q\nb".to_vec())),
            (b"ctrl".to_vec(), JsonValue::String(b"a\x01b\x1fc".to_vec())),
        ]);
        show("strings", &o, JSON_C_TO_STRING_PLAIN);
        show(
            "strings NOSLASH",
            &o,
            JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE,
        );
    }

    println!("== done ==");
}

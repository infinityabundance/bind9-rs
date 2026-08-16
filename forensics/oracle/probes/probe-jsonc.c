/* probe-jsonc.c — json-c 0.19 surface probe (§35, §37).
 *
 * Exercises the conservation surface: version + error descriptions, a
 * deterministic parse corpus (scalars, numbers at every boundary, strings
 * with escapes/surrogates/control chars, comments, NaN/Infinity, strict
 * mode, depth limits, malformed inputs), serialization with every flag
 * combination, and programmatic constructors (doubles incl. the %.17g
 * path, int64/uint64 boundaries).
 *
 * NOTE: json-c objects cache a single shared printbuf, so each flag's
 * serialization is printed immediately (never two calls in one printf).
 * The Rust mirror (jsonc-probe.rs) must produce byte-identical stdout.
 */
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>

static const char *typname(enum json_type t) {
    switch (t) {
        case json_type_null: return "null";
        case json_type_boolean: return "boolean";
        case json_type_double: return "double";
        case json_type_int: return "int";
        case json_type_object: return "object";
        case json_type_array: return "array";
        case json_type_string: return "string";
        default: return "?";
    }
}

static void show(const char *label, struct json_object *o, int flags) {
    const char *s = json_object_to_json_string_ext(o, flags);
    printf("    %-12s -> %s\n", label, s);
}

static void parse_one(const char *in) {
    enum json_tokener_error err;
    struct json_object *o = json_tokener_parse_verbose(in, &err);
    if (o == NULL) {
        printf("  %-28s -> NULL err=%d %s\n", in, err, json_tokener_error_desc(err));
        return;
    }
    printf("  %-28s -> type=%s\n", in, typname(json_object_get_type(o)));
    show("PLAIN", o, JSON_C_TO_STRING_PLAIN);
    show("SPACED", o, JSON_C_TO_STRING_SPACED);
    show("PRETTY", o, JSON_C_TO_STRING_PRETTY);
    show("PRETTY|TAB", o, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_PRETTY_TAB);
    show("PRETTY|SPACED", o, JSON_C_TO_STRING_PRETTY | JSON_C_TO_STRING_SPACED);
    show("NOZERO", o, JSON_C_TO_STRING_NOZERO);
    show("NOSLASH", o, JSON_C_TO_STRING_NOSLASHESCAPE);
    show("COLOR", o, JSON_C_TO_STRING_COLOR);
    show("SPACED|NOSLASH", o, JSON_C_TO_STRING_SPACED | JSON_C_TO_STRING_NOSLASHESCAPE);
}

static void parse_strict(const char *in) {
    struct json_tokener *tok = json_tokener_new();
    json_tokener_set_flags(tok, JSON_TOKENER_STRICT);
    struct json_object *o = json_tokener_parse_ex(tok, in, -1);
    enum json_tokener_error err = json_tokener_get_error(tok);
    printf("  STRICT %-22s -> %s err=%d %s\n", in,
           o ? json_object_to_json_string(o) : "NULL", err,
           json_tokener_error_desc(err));
    json_tokener_free(tok);
}

int main(void) {
    printf("== version ==\n%s %d\n", json_c_version(), JSON_C_VERSION_NUM);

    printf("== error descs ==\n");
    for (int i = 0; i <= 16; i++)
        printf("  %d: %s\n", i, json_tokener_error_desc(i));
    printf("  99: %s\n", json_tokener_error_desc(99));

    printf("== parse corpus ==\n");
    const char *corpus[] = {
        "null", "true", "false", "TRUE", "FALSE", "Null", "nulll",
        "123", "-123", "0", "-0", "01", "1.5", "1.50", "-1.5e-3",
        "1e10", "1e+", "1E10", "123e+", "9223372036854775807",
        "9223372036854775808", "18446744073709551615",
        "18446744073709551616", "-9223372036854775808",
        "-9223372036854775809", "NaN", "Infinity", "-Infinity", "iNFINITY",
        "123abc", "nullx", "truefalse", "nul", "tru", "nuX", "truX",
        "01.", ".5", "1.2.3", "-", "-x", "1e", "1e-", "1e+5", "1.5e",
        "\"hello\"", "\"\"", "'single'", "\"a\\nb\\tc\\r\\fd\\\\e\\/f\"",
        "\"\\u0041\\u00e9\\ud83d\\ude00\"", "\"\\ud83d\"", "\"\\ude00\"",
        "\"a\\u0000b\"", "\"a\\q\"", "\"abc", "\"a\\u12\"",
        "[]", "[1,2,3]", "[1,]", "[,1]", "[1 2]", "[1,2", "[[[1]]]",
        "{}", "{\"a\":1}", "{\"a\":1,\"b\":[true,null,\"x/y\"]}",
        "{'a':1}", "{a:1}", "{\"a\" 1}", "{\"a\":1 \"b\":2}", "{\"a\":1,\"a\":2}",
        "{\"a\":1,}", "{,\"a\":1}", "{\"a\"}", "{\"a\":}",
        "/* hi */1", "// hi\n1", "1/*x*/2", "/*x*/", "/x", "1 /*a*/ + 2",
        " 1 ", "\t1\n", "\"\\u00e9\"x", "1 2", "\"a\" \"b\"",
        NULL};
    for (int i = 0; corpus[i]; i++) parse_one(corpus[i]);

    printf("== strict ==\n");
    const char *strict[] = {"01", "1e+", "1 2", "[1,]", "'a'", "NaN",
                            "Infinity", "iNFINITY", "null", "\"a\\nb\"",
                            "/*x*/1", "123", "1.5", "true", "{}", NULL};
    for (int i = 0; strict[i]; i++) parse_strict(strict[i]);

    printf("== depth ==\n");
    for (int n = 31; n <= 34; n++) {
        char buf[80];
        int i;
        for (i = 0; i < n; i++) buf[i] = '[';
        for (i = 0; i < n; i++) buf[n + i] = ']';
        buf[2 * n] = 0;
        enum json_tokener_error err;
        struct json_object *o = json_tokener_parse_verbose(buf, &err);
        printf("  depth %d -> %s err=%d %s\n", n, o ? "OK" : "NULL", err,
               json_tokener_error_desc(err));
    }

    printf("== programmatic ==\n");
    {
        double ds[] = {0.0, -0.0, 1.5, 42.0, 0.1, 1e300, 1e-5, 1e15,
                       3.141592653589793, 123456789.123456789,
                       2.2250738585072014e-308, 1.7976931348623157e308,
                       2.5e-4, 1e-4, 123456.789, -1.5e20};
        for (size_t i = 0; i < sizeof(ds) / sizeof(ds[0]); i++) {
            struct json_object *d = json_object_new_double(ds[i]);
            show("dbl PLAIN", d, JSON_C_TO_STRING_PLAIN);
            show("dbl NOZERO", d, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOZERO);
            printf("    dbl value   -> %.17g\n", ds[i]);
            json_object_put(d);
        }
    }
    {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "i64max", json_object_new_int64(9223372036854775807LL));
        json_object_object_add(o, "i64min", json_object_new_int64(-9223372036854775807LL - 1));
        json_object_object_add(o, "u64max", json_object_new_uint64(18446744073709551615ULL));
        json_object_object_add(o, "zero", json_object_new_int64(0));
        json_object_object_add(o, "neg", json_object_new_int64(-42));
        show("ints", o, JSON_C_TO_STRING_SPACED);
        json_object_put(o);
    }
    {
        struct json_object *o = json_object_new_object();
        json_object_object_add(o, "s", json_object_new_string("x/y\\z\"q\nb"));
        json_object_object_add(o, "ctrl",
                               json_object_new_string("a\x01" "b\x1f" "c"));
        show("strings", o, JSON_C_TO_STRING_PLAIN);
        show("strings NOSLASH", o, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
        json_object_put(o);
    }

    printf("== done ==\n");
    return 0;
}

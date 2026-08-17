/*
 * probe-protobuf-c.c — oracle probe for the PBC-0001 court (§26, §38).
 *
 * Exercises the protobuf-c 1.5.2 runtime surface BIND 9.20.26 links against
 * for DNSTAP (lib/dns/dnstap.c): pack/unpack/pack_to_buffer/get_packed_size,
 * the varint/fixed/ZigZag encoders, the length-prefix stack (incl. the
 * 1->2-byte memmove paths), wire-type validation, the required-field bitmap,
 * unknown-field passthrough, merge_messages, message_check, the allocator
 * hooks, buffer-simple, descriptor lookups, enum lookups (incl. aliases) and
 * service dispatch.
 *
 * The descriptors come from the pinned protoc-gen-c 1.5.2, generated from
 * the pinned tarball's own t/test-full.proto and t/test-proto3.proto
 * (protobuf-c-gen/*.pb-c.{c,h} — generated once with protoc 3.21.12, the
 * bookworm-era compiler the pinned plugin builds against, and checked in).
 * This is exactly the pipeline BIND uses for dns_message.pb-c.h: generated
 * descriptors + the runtime library.
 *
 * Every observable result is printed with the same format the Rust mirror
 * (bind9-rs-tools/src/bin/protobuf-c-probe.rs) reproduces; stdout must be
 * byte-identical.  All inputs are fixed constants; floats/doubles are printed
 * as exact bit patterns; no pointers or addresses are printed.
 *
 * Build: gcc -I/opt/dep/include -o cprobe probe-protobuf-c.c \
 *            protobuf-c-gen/test-full.pb-c.c \
 *            protobuf-c-gen/test-proto3.pb-c.c \
 *            -L/opt/dep/lib -lprotobuf-c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "protobuf-c-gen/test-full.pb-c.h"
#include "protobuf-c-gen/test-proto3.pb-c.h"

/* ------------------------------------------------------------------ */
/* deterministic printers                                             */
/* ------------------------------------------------------------------ */

static void
hexout(const uint8_t *d, size_t n)
{
	printf("hex:");
	for (size_t i = 0; i < n; i++)
		printf(" %02x", d[i]);
	printf("\n");
}

/* escape non-printable bytes exactly like the Rust mirror */
static void
strout(const char *s)
{
	printf("str:");
	if (s == NULL) {
		printf(" (null)\n");
		return;
	}
	for (const unsigned char *p = (const unsigned char *) s; *p; p++) {
		switch (*p) {
		case '\n': printf("\\n"); break;
		case '\t': printf("\\t"); break;
		case '\r': printf("\\r"); break;
		case '\\': printf("\\\\"); break;
		case '"':  printf("\\\""); break;
		default:
			if (*p >= 0x20 && *p <= 0x7e)
				printf("%c", *p);
			else
				printf("\\x%02x", *p);
			break;
		}
	}
	printf(" (len=%zu)\n", s ? strlen(s) : 0);
}

/* pack a message, print size + hex, unpack, print readback helpers
 * (defined per message in each section), re-pack and compare */
static void
section(const char *name)
{
	printf("--- %s ---\n", name);
}

static void
repack_check(const ProtobufCMessage *m, size_t size, const uint8_t *packed)
{
	size_t size2 = protobuf_c_message_get_packed_size(m);
	uint8_t *out = malloc(size2);
	size_t wrote = protobuf_c_message_pack(m, out);
	printf("repack size=%zu wrote=%zu match=%s\n",
	       size2, wrote, (wrote == size && memcmp(out, packed, size) == 0) ? "yes" : "NO");
	free(out);
}

static void
roundtrip(const ProtobufCMessage *m)
{
	size_t size = protobuf_c_message_get_packed_size(m);
	uint8_t *packed = malloc(size ? size : 1);
	size_t wrote = protobuf_c_message_pack(m, packed);
	printf("size=%zu wrote=%zu\n", size, wrote);
	hexout(packed, wrote);
	repack_check(m, wrote, packed);
	free(packed);
}

/* ------------------------------------------------------------------ */
/* fixed corpora (identical constants in the Rust mirror)             */
/* ------------------------------------------------------------------ */

static const int32_t pack_i32[24] = {
	0, -1, 1, 127, 128, 16383, 16384, 2097151, 2097152, -2147483647,
	2147483647, -123456789, 42, -42, 300, -300, 70000, -70000, 5, -5, 6, 7, 8, -8
};
static const int32_t pack_si32[24] = {
	0, -1, 1, 127, 128, 16383, 16384, 2097151, 2097152, -2147483648,
	2147483647, -123456789, 42, -42, 300, -300, 70000, -70000, 5, -5, 6, 7, 8, -8
};
static const int32_t pack_sf32[24] = {
	-1, 0, 1, 127, 128, 16383, 16384, 2097151, 2097152, -2147483648,
	2147483647, -123456789, 42, -42, 300, -300, 70000, -70000, 5, -5, 6, 7, 8, -8
};
static const int64_t pack_i64[24] = {
	0, -1, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455,
	268435456, 4294967295LL, 4294967296LL, 1099511627775LL, 1099511627776LL,
	281474976710655LL, 281474976710656LL, 72057594037927935LL,
	72057594037927936LL, -9223372036854775807LL, 9223372036854775807LL,
	-1234567890123LL, 42, -8
};
static const int64_t pack_si64[24] = {
	0, -1, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455,
	268435456, 4294967295LL, 4294967296LL, 1099511627775LL, 1099511627776LL,
	281474976710655LL, 281474976710656LL, 72057594037927935LL,
	72057594037927936LL, -9223372036854775807LL, 9223372036854775807LL,
	-1234567890123LL, 42, -8
};
static const int64_t pack_sf64[24] = {
	0, -1, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455,
	268435456, 4294967295LL, 4294967296LL, 1099511627775LL, 1099511627776LL,
	281474976710655LL, 281474976710656LL, 72057594037927935LL,
	72057594037927936LL, -9223372036854775807LL, 9223372036854775807LL,
	-1234567890123LL, 42, -8
};
static const uint32_t pack_u32[24] = {
	0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456,
	4294967295u, 300, 70000, 42, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};
static const uint32_t pack_fx32[24] = {
	0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456,
	4294967295u, 300, 70000, 42, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14
};
static const uint64_t pack_u64[24] = {
	0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456,
	4294967295ULL, 4294967296ULL, 1099511627775ULL, 1099511627776ULL,
	281474976710655ULL, 281474976710656ULL, 72057594037927935ULL,
	72057594037927936ULL, 18446744073709551615ULL, 300, 42, 5, 6, 7
};
static const uint64_t pack_fx64[24] = {
	0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455, 268435456,
	4294967295ULL, 4294967296ULL, 1099511627775ULL, 1099511627776ULL,
	281474976710655ULL, 281474976710656ULL, 72057594037927935ULL,
	72057594037927936ULL, 18446744073709551615ULL, 300, 42, 5, 6, 7
};
static const uint32_t pack_fl[24] = {
	0x00000000, 0x3f800000, 0x40490fdb, 0x7f800000, 0xff800000, 0x3fc00000,
	0xbf800000, 0x00000001, 0x3eaaaaab, 0x3f000000, 0x40000000, 0x40490fdb,
	0x41200000, 0x42c80000, 0x477fff00, 0x3f000000, 0x3f800000, 0x3dcccccd,
	0x3d8f5c29, 0x3ba3d70a, 0x00000000, 0x00000000, 0x80000000, 0x3f000000
};
static const uint64_t pack_db[24] = {
	0x0000000000000000ULL, 0x3ff0000000000000ULL, 0x400921fb54442d18ULL,
	0x7ff0000000000000ULL, 0xfff0000000000000ULL, 0x3ff8000000000000ULL,
	0xbff0000000000000ULL, 0x0000000000000001ULL, 0x3fd5555555555555ULL,
	0x3fe0000000000000ULL, 0x4000000000000000ULL, 0x400921fb54442d18ULL,
	0x4024000000000000ULL, 0x4059000000000000ULL, 0x40efffe000000000ULL,
	0x3fe0000000000000ULL, 0x3ff0000000000000ULL, 0x3fb999999999999aULL,
	0x3fb1eb851eb851ecULL, 0x3f747ae147ae147bULL, 0x0000000000000000ULL,
	0x0000000000000000ULL, 0x8000000000000000ULL, 0x3fe0000000000000ULL
};
static const protobuf_c_boolean pack_bool[24] = {
	1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 1
};
static const Foo__TestEnumSmall pack_esm[24] = {
	-1, 0, 1, 0, 1, -1, 1, 0, 1, 0, -1, 1, 0, 1, 0, -1, 1, 0, 1, -1, 0, 1, 0, 1
};
static const Foo__TestEnum pack_en[24] = {
	FOO__TEST_ENUM__VALUENEG123456, FOO__TEST_ENUM__VALUENEG1,
	FOO__TEST_ENUM__VALUE0, FOO__TEST_ENUM__VALUE1,
	FOO__TEST_ENUM__VALUE127, FOO__TEST_ENUM__VALUE128,
	FOO__TEST_ENUM__VALUE16383, FOO__TEST_ENUM__VALUE16384,
	FOO__TEST_ENUM__VALUE2097151, FOO__TEST_ENUM__VALUE2097152,
	FOO__TEST_ENUM__VALUE268435455, FOO__TEST_ENUM__VALUE268435456,
	FOO__TEST_ENUM__VALUE0, FOO__TEST_ENUM__VALUE1,
	FOO__TEST_ENUM__VALUE127, FOO__TEST_ENUM__VALUE128,
	FOO__TEST_ENUM__VALUE16383, FOO__TEST_ENUM__VALUE16384,
	FOO__TEST_ENUM__VALUE2097151, FOO__TEST_ENUM__VALUE2097152,
	FOO__TEST_ENUM__VALUE268435455, FOO__TEST_ENUM__VALUE268435456,
	FOO__TEST_ENUM__VALUENEG1, FOO__TEST_ENUM__VALUENEG123456
};

/* --- section 1: version --- */

static void
test_version(void)
{
	section("version");
	printf("version: %s\n", protobuf_c_version());
	printf("version_number: %" PRIu32 "\n", protobuf_c_version_number());
}

/* --- section 2: struct/descriptor sizes --- */

static void
test_sizes(void)
{
	section("sizes");
	printf("TestMessPacked=%zu\n", sizeof(Foo__TestMessPacked));
	printf("TestMess=%zu\n", sizeof(Foo__TestMess));
	printf("TestMessOptional=%zu\n", sizeof(Foo__TestMessOptional));
	printf("TestMessOneof=%zu\n", sizeof(Foo__TestMessOneof));
	printf("SubMess=%zu\n", sizeof(Foo__SubMess));
	printf("SubSubMess=%zu\n", sizeof(Foo__SubMess__SubSubMess));
	printf("TestMessageCheck=%zu\n", sizeof(Foo__TestMessageCheck));
	printf("CheckSub=%zu\n", sizeof(Foo__TestMessageCheck__SubMessage));
	printf("DefaultRequiredValues=%zu\n", sizeof(Foo__DefaultRequiredValues));
	printf("DefaultOptionalValues=%zu\n", sizeof(Foo__DefaultOptionalValues));
	printf("TestRequiredFieldsBitmap=%zu\n", sizeof(Foo__TestRequiredFieldsBitmap));
	printf("TestMessSubMess=%zu\n", sizeof(Foo__TestMessSubMess));
	printf("EmptyMess=%zu\n", sizeof(Foo__EmptyMess));
	printf("proto3 Person=%zu\n", sizeof(Foo__Person));
	printf("proto3 PhoneNumber=%zu\n", sizeof(Foo__Person__PhoneNumber));
	printf("proto3 Comment=%zu\n", sizeof(Foo__Person__PhoneNumber__Comment));
	printf("proto3 Name=%zu\n", sizeof(Foo__Name));
	printf("proto3 LookupResult=%zu\n", sizeof(Foo__LookupResult));
	printf("desc TestMessPacked sizeof_message=%zu\n",
	       foo__test_mess_packed__descriptor.sizeof_message);
	printf("desc TestMessOneof sizeof_message=%zu\n",
	       foo__test_mess_oneof__descriptor.sizeof_message);
	printf("desc proto3 Person sizeof_message=%zu\n",
	       foo__person__descriptor.sizeof_message);
}

/* --- section 3: packed repeated battery --- */

static void
test_packed_battery(void)
{
	section("packed");
	Foo__TestMessPacked m = FOO__TEST_MESS_PACKED__INIT;
	m.n_test_int32 = 24; m.test_int32 = (int32_t *) pack_i32;
	m.n_test_sint32 = 24; m.test_sint32 = (int32_t *) pack_si32;
	m.n_test_sfixed32 = 24; m.test_sfixed32 = (int32_t *) pack_sf32;
	m.n_test_int64 = 24; m.test_int64 = (int64_t *) pack_i64;
	m.n_test_sint64 = 24; m.test_sint64 = (int64_t *) pack_si64;
	m.n_test_sfixed64 = 24; m.test_sfixed64 = (int64_t *) pack_sf64;
	m.n_test_uint32 = 24; m.test_uint32 = (uint32_t *) pack_u32;
	m.n_test_fixed32 = 24; m.test_fixed32 = (uint32_t *) pack_fx32;
	m.n_test_uint64 = 24; m.test_uint64 = (uint64_t *) pack_u64;
	m.n_test_fixed64 = 24; m.test_fixed64 = (uint64_t *) pack_fx64;
	m.n_test_float = 24; m.test_float = (float *) pack_fl;
	m.n_test_double = 24; m.test_double = (double *) pack_db;
	m.n_test_boolean = 24; m.test_boolean = (protobuf_c_boolean *) pack_bool;
	m.n_test_enum_small = 24; m.test_enum_small = (Foo__TestEnumSmall *) pack_esm;
	m.n_test_enum = 24; m.test_enum = (Foo__TestEnum *) pack_en;

	size_t size = protobuf_c_message_get_packed_size(&m.base);
	uint8_t *packed = malloc(size);
	size_t wrote = protobuf_c_message_pack(&m.base, packed);
	printf("size=%zu wrote=%zu\n", size, wrote);
	hexout(packed, wrote);

	Foo__TestMessPacked *u = foo__test_mess_packed__unpack(NULL, wrote, packed);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("int32 n=%zu [", u->n_test_int32);
		for (size_t i = 0; i < u->n_test_int32; i++)
			printf("%s%d", i ? ", " : "", u->test_int32[i]);
		printf("]\n");
		printf("sint32 n=%zu [", u->n_test_sint32);
		for (size_t i = 0; i < u->n_test_sint32; i++)
			printf("%s%d", i ? ", " : "", u->test_sint32[i]);
		printf("]\n");
		printf("sfixed32 n=%zu [", u->n_test_sfixed32);
		for (size_t i = 0; i < u->n_test_sfixed32; i++)
			printf("%s%d", i ? ", " : "", u->test_sfixed32[i]);
		printf("]\n");
		printf("int64 n=%zu [", u->n_test_int64);
		for (size_t i = 0; i < u->n_test_int64; i++)
			printf("%s%" PRId64, i ? ", " : "", u->test_int64[i]);
		printf("]\n");
		printf("sint64 n=%zu [", u->n_test_sint64);
		for (size_t i = 0; i < u->n_test_sint64; i++)
			printf("%s%" PRId64, i ? ", " : "", u->test_sint64[i]);
		printf("]\n");
		printf("sfixed64 n=%zu [", u->n_test_sfixed64);
		for (size_t i = 0; i < u->n_test_sfixed64; i++)
			printf("%s%" PRId64, i ? ", " : "", u->test_sfixed64[i]);
		printf("]\n");
		printf("uint32 n=%zu [", u->n_test_uint32);
		for (size_t i = 0; i < u->n_test_uint32; i++)
			printf("%s%" PRIu32, i ? ", " : "", u->test_uint32[i]);
		printf("]\n");
		printf("fixed32 n=%zu [", u->n_test_fixed32);
		for (size_t i = 0; i < u->n_test_fixed32; i++)
			printf("%s%" PRIu32, i ? ", " : "", u->test_fixed32[i]);
		printf("]\n");
		printf("uint64 n=%zu [", u->n_test_uint64);
		for (size_t i = 0; i < u->n_test_uint64; i++)
			printf("%s%" PRIu64, i ? ", " : "", u->test_uint64[i]);
		printf("]\n");
		printf("fixed64 n=%zu [", u->n_test_fixed64);
		for (size_t i = 0; i < u->n_test_fixed64; i++)
			printf("%s%" PRIu64, i ? ", " : "", u->test_fixed64[i]);
		printf("]\n");
		printf("float n=%zu [", u->n_test_float);
		for (size_t i = 0; i < u->n_test_float; i++) {
			uint32_t bits; memcpy(&bits, &u->test_float[i], 4);
			printf("%s0x%08x", i ? ", " : "", bits);
		}
		printf("]\n");
		printf("double n=%zu [", u->n_test_double);
		for (size_t i = 0; i < u->n_test_double; i++) {
			uint64_t bits; memcpy(&bits, &u->test_double[i], 8);
			printf("%s0x%016" PRIx64, i ? ", " : "", bits);
		}
		printf("]\n");
		printf("bool n=%zu [", u->n_test_boolean);
		for (size_t i = 0; i < u->n_test_boolean; i++)
			printf("%s%d", i ? ", " : "", u->test_boolean[i] ? 1 : 0);
		printf("]\n");
		printf("enum_small n=%zu [", u->n_test_enum_small);
		for (size_t i = 0; i < u->n_test_enum_small; i++)
			printf("%s%d", i ? ", " : "", u->test_enum_small[i]);
		printf("]\n");
		printf("enum n=%zu [", u->n_test_enum);
		for (size_t i = 0; i < u->n_test_enum; i++)
			printf("%s%d", i ? ", " : "", u->test_enum[i]);
		printf("]\n");

		size_t r2 = protobuf_c_message_get_packed_size(&u->base);
		uint8_t *rp = malloc(r2);
		size_t rw = protobuf_c_message_pack(&u->base, rp);
		printf("repack size=%zu match=%s\n", r2,
		       (rw == wrote && memcmp(rp, packed, wrote) == 0) ? "yes" : "NO");
		free(rp);
		foo__test_mess_packed__free_unpacked(u, NULL);
	}
	free(packed);
}

/* --- section 4: unpacked repeated battery --- */

static void
test_repeated_battery(void)
{
	section("repeated");
	static const int32_t r_i32[3] = { 1, -1, 300 };
	static const int32_t r_si32[3] = { 1, -1, 300 };
	static const int32_t r_sf32[3] = { 1, -1, 300 };
	static const int64_t r_i64[3] = { 1, -1, 4294967296LL };
	static const int64_t r_si64[3] = { 1, -1, 4294967296LL };
	static const int64_t r_sf64[3] = { 1, -1, 4294967296LL };
	static const uint32_t r_u32[3] = { 1, 300, 4294967295u };
	static const uint32_t r_fx32[3] = { 1, 300, 4294967295u };
	static const uint64_t r_u64[3] = { 1, 300, 18446744073709551615ULL };
	static const uint64_t r_fx64[3] = { 1, 300, 18446744073709551615ULL };
	static const uint32_t r_fl[3] = { 0x3f800000, 0x40000000, 0x40490fdb };
	static const uint64_t r_db[3] = { 0x3ff0000000000000ULL, 0x4000000000000000ULL, 0x400921fb54442d18ULL };
	static const protobuf_c_boolean r_bool[3] = { 1, 0, 1 };
	static const Foo__TestEnumSmall r_esm[3] = { -1, 0, 1 };
	static const Foo__TestEnum r_en[3] = {
		FOO__TEST_ENUM__VALUENEG123456, FOO__TEST_ENUM__VALUE0,
		FOO__TEST_ENUM__VALUE268435456
	};
	static const char *r_str[3] = { "abc", "", "hello world" };
	static const uint8_t r_b1[] = { 'a', 'b', 'c' };
	static const uint8_t r_b2[] = { 0 };
	static const uint8_t r_b3[] = { 'h', 'e', 'l', 'l', 'o' };
	static const ProtobufCBinaryData r_bin[3] = {
		{ 3, (uint8_t *) r_b1 }, { 0, NULL }, { 5, (uint8_t *) r_b3 }
	};

	Foo__SubMess sub1 = FOO__SUB_MESS__INIT;
	Foo__SubMess sub2 = FOO__SUB_MESS__INIT;
	sub1.test = 5;
	sub2.test = -9;
	sub2.has_val1 = 1;
	sub2.val1 = 77;
	Foo__SubMess *subs[2] = { &sub1, &sub2 };

	Foo__TestMess m = FOO__TEST_MESS__INIT;
	m.n_test_int32 = 3; m.test_int32 = (int32_t *) r_i32;
	m.n_test_sint32 = 3; m.test_sint32 = (int32_t *) r_si32;
	m.n_test_sfixed32 = 3; m.test_sfixed32 = (int32_t *) r_sf32;
	m.n_test_int64 = 3; m.test_int64 = (int64_t *) r_i64;
	m.n_test_sint64 = 3; m.test_sint64 = (int64_t *) r_si64;
	m.n_test_sfixed64 = 3; m.test_sfixed64 = (int64_t *) r_sf64;
	m.n_test_uint32 = 3; m.test_uint32 = (uint32_t *) r_u32;
	m.n_test_fixed32 = 3; m.test_fixed32 = (uint32_t *) r_fx32;
	m.n_test_uint64 = 3; m.test_uint64 = (uint64_t *) r_u64;
	m.n_test_fixed64 = 3; m.test_fixed64 = (uint64_t *) r_fx64;
	m.n_test_float = 3; m.test_float = (float *) r_fl;
	m.n_test_double = 3; m.test_double = (double *) r_db;
	m.n_test_boolean = 3; m.test_boolean = (protobuf_c_boolean *) r_bool;
	m.n_test_enum_small = 3; m.test_enum_small = (Foo__TestEnumSmall *) r_esm;
	m.n_test_enum = 3; m.test_enum = (Foo__TestEnum *) r_en;
	m.n_test_string = 3; m.test_string = r_str;
	m.n_test_bytes = 3; m.test_bytes = (ProtobufCBinaryData *) r_bin;
	m.n_test_message = 2; m.test_message = subs;

	size_t size = protobuf_c_message_get_packed_size(&m.base);
	uint8_t *packed = malloc(size);
	size_t wrote = protobuf_c_message_pack(&m.base, packed);
	printf("size=%zu wrote=%zu\n", size, wrote);
	hexout(packed, wrote);

	Foo__TestMess *u = foo__test_mess__unpack(NULL, wrote, packed);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("int32 [%d, %d, %d]\n", u->test_int32[0], u->test_int32[1], u->test_int32[2]);
		printf("sint32 [%d, %d, %d]\n", u->test_sint32[0], u->test_sint32[1], u->test_sint32[2]);
		printf("sfixed32 [%d, %d, %d]\n", u->test_sfixed32[0], u->test_sfixed32[1], u->test_sfixed32[2]);
		printf("int64 [%" PRId64 ", %" PRId64 ", %" PRId64 "]\n",
		       u->test_int64[0], u->test_int64[1], u->test_int64[2]);
		printf("sint64 [%" PRId64 ", %" PRId64 ", %" PRId64 "]\n",
		       u->test_sint64[0], u->test_sint64[1], u->test_sint64[2]);
		printf("sfixed64 [%" PRId64 ", %" PRId64 ", %" PRId64 "]\n",
		       u->test_sfixed64[0], u->test_sfixed64[1], u->test_sfixed64[2]);
		printf("uint32 [%" PRIu32 ", %" PRIu32 ", %" PRIu32 "]\n",
		       u->test_uint32[0], u->test_uint32[1], u->test_uint32[2]);
		printf("fixed32 [%" PRIu32 ", %" PRIu32 ", %" PRIu32 "]\n",
		       u->test_fixed32[0], u->test_fixed32[1], u->test_fixed32[2]);
		printf("uint64 [%" PRIu64 ", %" PRIu64 ", %" PRIu64 "]\n",
		       u->test_uint64[0], u->test_uint64[1], u->test_uint64[2]);
		printf("fixed64 [%" PRIu64 ", %" PRIu64 ", %" PRIu64 "]\n",
		       u->test_fixed64[0], u->test_fixed64[1], u->test_fixed64[2]);
		{
			uint32_t b0, b1, b2; memcpy(&b0, &u->test_float[0], 4);
			memcpy(&b1, &u->test_float[1], 4); memcpy(&b2, &u->test_float[2], 4);
			printf("float [0x%08x, 0x%08x, 0x%08x]\n", b0, b1, b2);
		}
		{
			uint64_t b0, b1, b2; memcpy(&b0, &u->test_double[0], 8);
			memcpy(&b1, &u->test_double[1], 8); memcpy(&b2, &u->test_double[2], 8);
			printf("double [0x%016" PRIx64 ", 0x%016" PRIx64 ", 0x%016" PRIx64 "]\n", b0, b1, b2);
		}
		printf("bool [%d, %d, %d]\n", u->test_boolean[0] ? 1 : 0,
		       u->test_boolean[1] ? 1 : 0, u->test_boolean[2] ? 1 : 0);
		printf("enum_small [%d, %d, %d]\n",
		       u->test_enum_small[0], u->test_enum_small[1], u->test_enum_small[2]);
		printf("enum [%d, %d, %d]\n", u->test_enum[0], u->test_enum[1], u->test_enum[2]);
		printf("string n=%zu\n", u->n_test_string);
		for (size_t i = 0; i < u->n_test_string; i++) {
			printf("  [%zu] ", i); strout(u->test_string[i]);
		}
		printf("bytes n=%zu\n", u->n_test_bytes);
		for (size_t i = 0; i < u->n_test_bytes; i++) {
			printf("  [%zu] len=%zu ", i, u->test_bytes[i].len);
			hexout(u->test_bytes[i].data, u->test_bytes[i].len);
		}
		printf("message n=%zu\n", u->n_test_message);
		for (size_t i = 0; i < u->n_test_message; i++) {
			printf("  [%zu] test=%d has_val1=%d val1=%d\n",
			       i, u->test_message[i]->test,
			       u->test_message[i]->has_val1 ? 1 : 0,
			       u->test_message[i]->val1);
		}
		foo__test_mess__free_unpacked(u, NULL);
	}
	free(packed);
}

/* --- section 5: optional battery --- */

static void
test_optional_battery(void)
{
	section("optional");
	Foo__SubMess sub = FOO__SUB_MESS__INIT;
	sub.test = 42;
	sub.has_val1 = 1;
	sub.val1 = 9;

	Foo__TestMessOptional m = FOO__TEST_MESS_OPTIONAL__INIT;
	m.has_test_int32 = 1; m.test_int32 = -5;
	m.has_test_sint32 = 1; m.test_sint32 = -5;
	m.has_test_sfixed32 = 1; m.test_sfixed32 = -5;
	m.has_test_int64 = 1; m.test_int64 = -1234567890123LL;
	m.has_test_sint64 = 1; m.test_sint64 = -1234567890123LL;
	m.has_test_sfixed64 = 1; m.test_sfixed64 = -1234567890123LL;
	m.has_test_uint32 = 1; m.test_uint32 = 4294967295u;
	m.has_test_fixed32 = 1; m.test_fixed32 = 4294967295u;
	m.has_test_uint64 = 1; m.test_uint64 = 18446744073709551615ULL;
	m.has_test_fixed64 = 1; m.test_fixed64 = 18446744073709551615ULL;
	m.has_test_float = 1; memcpy(&m.test_float, &pack_fl[2], 4);
	m.has_test_double = 1; memcpy(&m.test_double, &pack_db[2], 8);
	m.has_test_boolean = 1; m.test_boolean = 1;
	m.has_test_enum_small = 1; m.test_enum_small = FOO__TEST_ENUM_SMALL__NEG_VALUE;
	m.has_test_enum = 1; m.test_enum = FOO__TEST_ENUM__VALUE268435456;
	m.test_string = "optional str";
	uint8_t ob[5] = { 'o', 'p', 't', 's', '!' };
	m.has_test_bytes = 1; m.test_bytes.len = 5; m.test_bytes.data = ob;
	m.test_message = &sub;

	roundtrip(&m.base);

	Foo__TestMessOptional *u = NULL;
	size_t size = protobuf_c_message_get_packed_size(&m.base);
	uint8_t *packed = malloc(size);
	protobuf_c_message_pack(&m.base, packed);
	u = (Foo__TestMessOptional *) protobuf_c_message_unpack(
		&foo__test_mess_optional__descriptor, NULL, size, packed);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("int32 has=%d val=%d\n", u->has_test_int32 ? 1 : 0, u->test_int32);
		printf("sint32 has=%d val=%d\n", u->has_test_sint32 ? 1 : 0, u->test_sint32);
		printf("sfixed32 has=%d val=%d\n", u->has_test_sfixed32 ? 1 : 0, u->test_sfixed32);
		printf("int64 has=%d val=%" PRId64 "\n", u->has_test_int64 ? 1 : 0, u->test_int64);
		printf("sint64 has=%d val=%" PRId64 "\n", u->has_test_sint64 ? 1 : 0, u->test_sint64);
		printf("sfixed64 has=%d val=%" PRId64 "\n", u->has_test_sfixed64 ? 1 : 0, u->test_sfixed64);
		printf("uint32 has=%d val=%" PRIu32 "\n", u->has_test_uint32 ? 1 : 0, u->test_uint32);
		printf("fixed32 has=%d val=%" PRIu32 "\n", u->has_test_fixed32 ? 1 : 0, u->test_fixed32);
		printf("uint64 has=%d val=%" PRIu64 "\n", u->has_test_uint64 ? 1 : 0, u->test_uint64);
		printf("fixed64 has=%d val=%" PRIu64 "\n", u->has_test_fixed64 ? 1 : 0, u->test_fixed64);
		{
			uint32_t bits; memcpy(&bits, &u->test_float, 4);
			printf("float has=%d val=0x%08x\n", u->has_test_float ? 1 : 0, bits);
		}
		{
			uint64_t bits; memcpy(&bits, &u->test_double, 8);
			printf("double has=%d val=0x%016" PRIx64 "\n", u->has_test_double ? 1 : 0, bits);
		}
		printf("bool has=%d val=%d\n", u->has_test_boolean ? 1 : 0, u->test_boolean ? 1 : 0);
		printf("enum_small has=%d val=%d\n", u->has_test_enum_small ? 1 : 0, u->test_enum_small);
		printf("enum has=%d val=%d\n", u->has_test_enum ? 1 : 0, u->test_enum);
		printf("string "); strout(u->test_string);
		printf("bytes has=%d len=%zu ", u->has_test_bytes ? 1 : 0, u->test_bytes.len);
		hexout(u->test_bytes.data, u->test_bytes.len);
		printf("message test=%d has_val1=%d val1=%d\n",
		       u->test_message ? u->test_message->test : -999,
		       u->test_message ? (u->test_message->has_val1 ? 1 : 0) : -1,
		       u->test_message ? u->test_message->val1 : -999);
		protobuf_c_message_free_unpacked(&u->base, NULL);
	}
	free(packed);

	printf("unset size=%zu\n", protobuf_c_message_get_packed_size(
		&((Foo__TestMessOptional) FOO__TEST_MESS_OPTIONAL__INIT).base));
	uint8_t empty[1];
	Foo__TestMessOptional fresh = FOO__TEST_MESS_OPTIONAL__INIT;
	printf("unset pack=%zu\n", protobuf_c_message_pack(&fresh.base, empty));
}

/* --- section 6: oneof battery --- */

static void
test_oneof_battery(void)
{
	section("oneof");
	Foo__SubMess sub = FOO__SUB_MESS__INIT;
	sub.test = 3;

	Foo__TestMessOneof m = FOO__TEST_MESS_ONEOF__INIT;
	printf("none size=%zu\n", foo__test_mess_oneof__get_packed_size(&m));
	uint8_t scratch[256];

	m.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_INT32;
	m.test_int32 = 42;
	roundtrip(&m.base);
	Foo__TestMessOneof *u = NULL;
	{
		size_t size = foo__test_mess_oneof__get_packed_size(&m);
		uint8_t *packed = malloc(size);
		foo__test_mess_oneof__pack(&m, packed);
		u = foo__test_mess_oneof__unpack(NULL, size, packed);
		printf("case=%d int32=%d\n", u->test_oneof_case, u->test_int32);
		foo__test_mess_oneof__free_unpacked(u, NULL);
		free(packed);
	}

	/* switch to string: the int32 storage is reused */
	m.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_STRING;
	m.test_string = "oneof string";
	roundtrip(&m.base);
	{
		size_t size = foo__test_mess_oneof__get_packed_size(&m);
		uint8_t *packed = malloc(size);
		foo__test_mess_oneof__pack(&m, packed);
		u = foo__test_mess_oneof__unpack(NULL, size, packed);
		printf("case=%d string=", u->test_oneof_case);
		strout(u->test_string);
		foo__test_mess_oneof__free_unpacked(u, NULL);
		free(packed);
	}

	m.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_BYTES;
	m.test_bytes.len = 5; m.test_bytes.data = (uint8_t *) "bytes";
	roundtrip(&m.base);
	{
		size_t size = foo__test_mess_oneof__get_packed_size(&m);
		uint8_t *packed = malloc(size);
		foo__test_mess_oneof__pack(&m, packed);
		u = foo__test_mess_oneof__unpack(NULL, size, packed);
		printf("case=%d bytes len=%zu ", u->test_oneof_case, u->test_bytes.len);
		hexout(u->test_bytes.data, u->test_bytes.len);
		foo__test_mess_oneof__free_unpacked(u, NULL);
		free(packed);
	}

	m.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_MESSAGE;
	m.test_message = &sub;
	roundtrip(&m.base);
	{
		size_t size = foo__test_mess_oneof__get_packed_size(&m);
		uint8_t *packed = malloc(size);
		foo__test_mess_oneof__pack(&m, packed);
		u = foo__test_mess_oneof__unpack(NULL, size, packed);
		printf("case=%d message test=%d\n",
		       u->test_oneof_case, u->test_message ? u->test_message->test : -1);
		foo__test_mess_oneof__free_unpacked(u, NULL);
		free(packed);
	}

	m.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_DOUBLE;
	memcpy(&m.test_double, &pack_db[4], 8);
	roundtrip(&m.base);

	/* both members present on the wire: last wins */
	{
		uint8_t wire[] = { 0x08, 0x2a, 0x82, 0x01, 0x03, 'a', 'b', 'c' };
		u = foo__test_mess_oneof__unpack(NULL, sizeof(wire), wire);
		printf("both case=%d string=", u->test_oneof_case);
		strout(u->test_string);
		foo__test_mess_oneof__free_unpacked(u, NULL);
	}
	(void) scratch;
}

/* --- section 7: defaults battery --- */

static void
test_defaults_battery(void)
{
	section("defaults");
	Foo__DefaultRequiredValues dr = FOO__DEFAULT_REQUIRED_VALUES__INIT;
	roundtrip(&dr.base);
	Foo__DefaultRequiredValues *u = foo__default_required_values__unpack(
		NULL, 0, NULL);
	printf("empty-unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("v_int32=%d v_uint32=%u v_int64=%d v_uint64=%u\n",
		       u->v_int32, u->v_uint32, u->v_int64, u->v_uint64);
		{
			uint32_t bits; memcpy(&bits, &u->v_float, 4);
			printf("v_float=0x%08x\n", bits);
		}
		{
			uint64_t bits; memcpy(&bits, &u->v_double, 8);
			printf("v_double=0x%016" PRIx64 "\n", bits);
		}
		printf("v_string "); strout(u->v_string);
		printf("v_bytes len=%zu ", u->v_bytes.len);
		hexout(u->v_bytes.data, u->v_bytes.len);
		foo__default_required_values__free_unpacked(u, NULL);
	}

	Foo__DefaultOptionalValues dob = FOO__DEFAULT_OPTIONAL_VALUES__INIT;
	printf("optional-fresh size=%zu\n",
	       foo__default_optional_values__get_packed_size(&dob));
	uint8_t e[1];
	printf("optional-fresh pack=%zu\n",
	       foo__default_optional_values__pack(&dob, e));
	dob.has_v_int32 = 1; dob.v_int32 = 7;
	dob.has_v_double = 1; memcpy(&dob.v_double, &pack_db[2], 8);
	roundtrip(&dob.base);
	u = NULL;
	{
		size_t size = foo__default_optional_values__get_packed_size(&dob);
		uint8_t *packed = malloc(size);
		foo__default_optional_values__pack(&dob, packed);
		Foo__DefaultOptionalValues *uo =
			foo__default_optional_values__unpack(NULL, size, packed);
		printf("unpack v_int32 has=%d val=%d\n",
		       uo->has_v_int32 ? 1 : 0, uo->v_int32);
		printf("unpack v_uint32 has=%d val=%u\n",
		       uo->has_v_uint32 ? 1 : 0, uo->v_uint32);
		{
			uint64_t bits; memcpy(&bits, &uo->v_double, 8);
			printf("unpack v_double has=%d val=0x%016" PRIx64 "\n",
			       uo->has_v_double ? 1 : 0, bits);
		}
		foo__default_optional_values__free_unpacked(uo, NULL);
		free(packed);
	}

	/* SubMess/SubSubMess defaults (incl. embedded-NUL defaults) */
	Foo__SubMess__SubSubMess ssm = FOO__SUB_MESS__SUB_SUB_MESS__INIT;
	printf("subsub-fresh size=%zu\n",
	       protobuf_c_message_get_packed_size(&ssm.base));
	printf("subsub val1=%d has=%d\n", ssm.val1, ssm.has_val1 ? 1 : 0);
	printf("subsub bytes1 len=%zu ", ssm.bytes1.len);
	hexout(ssm.bytes1.data, ssm.bytes1.len);
	printf("subsub str1 "); strout(ssm.str1);
	printf("subsub str2 len=%zu ", ssm.str2.len);
	hexout(ssm.str2.data, ssm.str2.len);

	ssm.has_val1 = 1; ssm.val1 = 5;
	uint8_t b1[3] = { 'a', 'b', 'c' };
	ssm.bytes1.len = 3; ssm.bytes1.data = b1;
	ssm.str1 = "custom str";
	uint8_t b2[5] = { 'a', 'b', 'c', 'd', 'e' };
	ssm.has_str2 = 1; ssm.str2.len = 5; ssm.str2.data = b2;
	roundtrip(&ssm.base);
	{
		size_t size = protobuf_c_message_get_packed_size(&ssm.base);
		uint8_t *packed = malloc(size);
		protobuf_c_message_pack(&ssm.base, packed);
		Foo__SubMess__SubSubMess *uo =
			(Foo__SubMess__SubSubMess *) protobuf_c_message_unpack(
				&foo__sub_mess__sub_sub_mess__descriptor, NULL, size, packed);
		printf("readback val1=%d has=%d bytes1 len=%zu str1 ",
		       uo->val1, uo->has_val1 ? 1 : 0, uo->bytes1.len);
		strout(uo->str1);
		printf("readback str2 len=%zu ", uo->str2.len);
		hexout(uo->str2.data, uo->str2.len);
		protobuf_c_message_free_unpacked(&uo->base, NULL);
		free(packed);
	}

	/* SubMess with sub1/sub2 set */
	Foo__SubMess__SubSubMess s1 = FOO__SUB_MESS__SUB_SUB_MESS__INIT;
	s1.has_val1 = 1; s1.val1 = 11;
	Foo__SubMess__SubSubMess s2 = FOO__SUB_MESS__SUB_SUB_MESS__INIT;
	s2.has_val1 = 1; s2.val1 = 22;
	s2.str1 = "s2 str";
	Foo__SubMess sm = FOO__SUB_MESS__INIT;
	sm.test = 5;
	static int32_t smrep[3] = { 1, 2, 3 };
	sm.n_rep = 3; sm.rep = smrep;
	sm.sub1 = &s1;
	sm.sub2 = &s2;
	roundtrip(&sm.base);
	{
		size_t size = foo__sub_mess__get_packed_size(&sm);
		uint8_t *packed = malloc(size);
		foo__sub_mess__pack(&sm, packed);
		Foo__SubMess *uo = foo__sub_mess__unpack(NULL, size, packed);
		printf("readback test=%d n_rep=%zu rep=[", uo->test, uo->n_rep);
		for (size_t i = 0; i < uo->n_rep; i++)
			printf("%s%d", i ? ", " : "", uo->rep[i]);
		printf("] sub1=%d sub2=%d\n", uo->sub1 ? 1 : 0, uo->sub2 ? 1 : 0);
		printf("sub1 val1=%d sub2 val1=%d sub2 str1 ",
		       uo->sub1 ? uo->sub1->val1 : -1,
		       uo->sub2 ? uo->sub2->val1 : -1);
		if (uo->sub2)
			strout(uo->sub2->str1);
		foo__sub_mess__free_unpacked(uo, NULL);
		free(packed);
	}
}

/* --- section 8: field-number header boundaries --- */

static void
test_fieldno(void)
{
	section("fieldno");
	Foo__TestFieldNo15 f15 = FOO__TEST_FIELD_NO15__INIT;
	f15.test = "x";
	Foo__TestFieldNo16 f16 = FOO__TEST_FIELD_NO16__INIT;
	f16.test = "x";
	Foo__TestFieldNo2047 f2047 = FOO__TEST_FIELD_NO2047__INIT;
	f2047.test = "x";
	Foo__TestFieldNo2048 f2048 = FOO__TEST_FIELD_NO2048__INIT;
	f2048.test = "x";
	Foo__TestFieldNo262143 f262143 = FOO__TEST_FIELD_NO262143__INIT;
	f262143.test = "x";
	Foo__TestFieldNo262144 f262144 = FOO__TEST_FIELD_NO262144__INIT;
	f262144.test = "x";
	Foo__TestFieldNo33554431 f33554431 = FOO__TEST_FIELD_NO33554431__INIT;
	f33554431.test = "x";
	Foo__TestFieldNo33554432 f33554432 = FOO__TEST_FIELD_NO33554432__INIT;
	f33554432.test = "x";
	uint8_t buf[16];
	printf("15 size=%zu pack=%zu ", foo__test_field_no15__get_packed_size(&f15),
	       foo__test_field_no15__pack(&f15, buf));
	hexout(buf, foo__test_field_no15__get_packed_size(&f15));
	printf("16 size=%zu pack=%zu ", foo__test_field_no16__get_packed_size(&f16),
	       foo__test_field_no16__pack(&f16, buf));
	hexout(buf, foo__test_field_no16__get_packed_size(&f16));
	printf("2047 size=%zu pack=%zu ", foo__test_field_no2047__get_packed_size(&f2047),
	       foo__test_field_no2047__pack(&f2047, buf));
	hexout(buf, foo__test_field_no2047__get_packed_size(&f2047));
	printf("2048 size=%zu pack=%zu ", foo__test_field_no2048__get_packed_size(&f2048),
	       foo__test_field_no2048__pack(&f2048, buf));
	hexout(buf, foo__test_field_no2048__get_packed_size(&f2048));
	printf("262143 size=%zu pack=%zu ", foo__test_field_no262143__get_packed_size(&f262143),
	       foo__test_field_no262143__pack(&f262143, buf));
	hexout(buf, foo__test_field_no262143__get_packed_size(&f262143));
	printf("262144 size=%zu pack=%zu ", foo__test_field_no262144__get_packed_size(&f262144),
	       foo__test_field_no262144__pack(&f262144, buf));
	hexout(buf, foo__test_field_no262144__get_packed_size(&f262144));
	printf("33554431 size=%zu pack=%zu ", foo__test_field_no33554431__get_packed_size(&f33554431),
	       foo__test_field_no33554431__pack(&f33554431, buf));
	hexout(buf, foo__test_field_no33554431__get_packed_size(&f33554431));
	printf("33554432 size=%zu pack=%zu ", foo__test_field_no33554432__get_packed_size(&f33554432),
	       foo__test_field_no33554432__pack(&f33554432, buf));
	hexout(buf, foo__test_field_no33554432__get_packed_size(&f33554432));
}

/* --- section 9: message_check battery --- */

static void
test_check_battery(void)
{
	section("check");
	Foo__TestMessageCheck ok = FOO__TEST_MESSAGE_CHECK__INIT;
	Foo__TestMessageCheck__SubMessage sm = FOO__TEST_MESSAGE_CHECK__SUB_MESSAGE__INIT;
	sm.str = "req";
	ok.required_msg = &sm;
	ok.required_string = "reqstr";
	uint8_t rb[3] = { 'r', 'e', 'q' };
	ok.required_bytes.len = 3; ok.required_bytes.data = rb;
	printf("valid check=%d\n", protobuf_c_message_check(&ok.base) ? 1 : 0);

	Foo__TestMessageCheck m1 = FOO__TEST_MESSAGE_CHECK__INIT;
	m1.required_msg = &sm;
	m1.required_string = NULL;
	m1.required_bytes.len = 0; m1.required_bytes.data = NULL;
	printf("missing-req-string check=%d\n", protobuf_c_message_check(&m1.base) ? 1 : 0);

	Foo__TestMessageCheck m2 = FOO__TEST_MESSAGE_CHECK__INIT;
	m2.required_msg = NULL;
	m2.required_string = "reqstr";
	m2.required_bytes.len = 0; m2.required_bytes.data = NULL;
	printf("missing-req-message check=%d\n", protobuf_c_message_check(&m2.base) ? 1 : 0);

	Foo__TestMessageCheck m3 = FOO__TEST_MESSAGE_CHECK__INIT;
	m3.required_msg = &sm;
	m3.required_string = "reqstr";
	m3.required_bytes.len = 3; m3.required_bytes.data = NULL;
	printf("req-bytes-null-data check=%d\n", protobuf_c_message_check(&m3.base) ? 1 : 0);

	Foo__TestMessageCheck m4 = FOO__TEST_MESSAGE_CHECK__INIT;
	m4.required_msg = &sm;
	m4.required_string = "reqstr";
	m4.required_bytes.len = 0; m4.required_bytes.data = NULL;
	m4.n_repeated_msg = 2; m4.repeated_msg = NULL;
	printf("repeated-msg-null-array check=%d\n", protobuf_c_message_check(&m4.base) ? 1 : 0);

	Foo__TestMessageCheck m5 = FOO__TEST_MESSAGE_CHECK__INIT;
	m5.required_msg = &sm;
	m5.required_string = "reqstr";
	m5.required_bytes.len = 0; m5.required_bytes.data = NULL;
	m5.n_repeated_string = 2; m5.repeated_string = NULL;
	printf("repeated-string-null-array check=%d\n", protobuf_c_message_check(&m5.base) ? 1 : 0);

	Foo__TestMessageCheck m6 = FOO__TEST_MESSAGE_CHECK__INIT;
	m6.required_msg = &sm;
	m6.required_string = "reqstr";
	m6.required_bytes.len = 0; m6.required_bytes.data = NULL;
	m6.n_repeated_bytes = 2;
	static ProtobufCBinaryData rb2[2] = {
		{ 3, NULL }, { 0, NULL }
	};
	m6.repeated_bytes = rb2;
	printf("repeated-bytes-null-data check=%d\n", protobuf_c_message_check(&m6.base) ? 1 : 0);

	Foo__TestMessageCheck m7 = FOO__TEST_MESSAGE_CHECK__INIT;
	m7.required_msg = &sm;
	m7.required_string = "reqstr";
	m7.required_bytes.len = 0; m7.required_bytes.data = NULL;
	m7.optional_msg = &sm;
	m7.optional_string = "opt";
	m7.has_optional_bytes = 1; m7.optional_bytes.len = 5; m7.optional_bytes.data = NULL;
	printf("opt-bytes-null-data check=%d\n", protobuf_c_message_check(&m7.base) ? 1 : 0);

	Foo__TestMessageCheck m8 = FOO__TEST_MESSAGE_CHECK__INIT;
	m8.required_msg = &sm;
	m8.required_string = "reqstr";
	m8.required_bytes.len = 0; m8.required_bytes.data = NULL;
	m8.optional_msg = &sm;
	m8.optional_string = "opt";
	printf("opt-set-valid check=%d\n", protobuf_c_message_check(&m8.base) ? 1 : 0);

	/* oneof-skip: unset oneof members are not checked */
	Foo__TestMessOneof o1 = FOO__TEST_MESS_ONEOF__INIT;
	printf("oneof-unset check=%d\n", protobuf_c_message_check(&o1.base) ? 1 : 0);
	o1.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_STRING;
	o1.test_string = NULL;
	printf("oneof-string-null check=%d\n", protobuf_c_message_check(&o1.base) ? 1 : 0);
	o1.test_string = "set";
	printf("oneof-string-set check=%d\n", protobuf_c_message_check(&o1.base) ? 1 : 0);

	/* nested required-missing via repeated message array */
	Foo__TestMessageCheck__SubMessage bad = FOO__TEST_MESSAGE_CHECK__SUB_MESSAGE__INIT;
	bad.str = NULL;
	Foo__TestMessageCheck m9 = FOO__TEST_MESSAGE_CHECK__INIT;
	m9.required_msg = &sm;
	m9.required_string = "reqstr";
	m9.required_bytes.len = 0; m9.required_bytes.data = NULL;
	Foo__TestMessageCheck__SubMessage *badarr[1];
	badarr[0] = &bad;
	m9.n_repeated_msg = 1; m9.repeated_msg = badarr;
	printf("nested-req-missing check=%d\n", protobuf_c_message_check(&m9.base) ? 1 : 0);
}

/* --- section 10: enum lookups --- */

static void
test_enum_lookups(void)
{
	section("enums");
	const ProtobufCEnumValue *v;
	const char *names[] = {
		"VALUE0", "VALUENEG123456", "VALUE268435456", "NOPE", ""
	};
	for (size_t i = 0; i < 5; i++) {
		v = protobuf_c_enum_descriptor_get_value_by_name(
			&foo__test_enum__descriptor, names[i]);
		if (v)
			printf("by_name %s -> %s %d\n", names[i], v->name, v->value);
		else
			printf("by_name %s -> NULL\n", names[i]);
	}
	const int vals[] = { -123456, -1, 0, 1, 127, 128, 16383, 16384, 2097151,
			     2097152, 268435455, 268435456, 2, -2, 1000000000 };
	for (size_t i = 0; i < 15; i++) {
		v = protobuf_c_enum_descriptor_get_value(&foo__test_enum__descriptor,
							 vals[i]);
		if (v)
			printf("by_value %d -> %s %d\n", vals[i], v->name, v->value);
		else
			printf("by_value %d -> NULL\n", vals[i]);
	}
	const char *dn[] = { "VALUE_A", "VALUE_B", "VALUE_D", "VALUE_E", "VALUE_F",
			     "VALUE_AA", "VALUE_BB", "VALUE_X" };
	for (size_t i = 0; i < 8; i++) {
		v = protobuf_c_enum_descriptor_get_value_by_name(
			&foo__test_enum_dup_values__descriptor, dn[i]);
		if (v)
			printf("dup by_name %s -> %s %d\n", dn[i], v->name, v->value);
		else
			printf("dup by_name %s -> NULL\n", dn[i]);
	}
	const int dv[] = { 42, 666, 1000, 1001, 41, 43, 667, 999, 1002 };
	for (size_t i = 0; i < 9; i++) {
		v = protobuf_c_enum_descriptor_get_value(
			&foo__test_enum_dup_values__descriptor, dv[i]);
		if (v)
			printf("dup by_value %d -> %s %d\n", dv[i], v->name, v->value);
		else
			printf("dup by_value %d -> NULL\n", dv[i]);
	}
	v = protobuf_c_enum_descriptor_get_value_by_name(
		&foo__test_enum_small__descriptor, "NEG_VALUE");
	printf("small by_name NEG_VALUE -> %s %d\n", v->name, v->value);
	v = protobuf_c_enum_descriptor_get_value(
		&foo__test_enum_small__descriptor, 1);
	printf("small by_value 1 -> %s %d\n", v->name, v->value);
	v = protobuf_c_enum_descriptor_get_value(
		&foo__test_enum_small__descriptor, 2);
	printf("small by_value 2 -> %s\n", v ? v->name : "NULL");
}

/* --- section 11: descriptor lookups --- */

static void
test_descriptor_lookups(void)
{
	section("descriptor-lookups");
	const ProtobufCFieldDescriptor *f;
	const char *names[] = { "test_int32", "test_uint64", "test_boolean",
				"nope", "" };
	for (size_t i = 0; i < 5; i++) {
		f = protobuf_c_message_descriptor_get_field_by_name(
			&foo__test_mess_packed__descriptor, names[i]);
		if (f)
			printf("by_name %s -> id=%u type=%d label=%d flags=%u\n",
			       names[i], f->id, f->type, f->label, f->flags);
		else
			printf("by_name %s -> NULL\n", names[i]);
	}
	const unsigned tags[] = { 1, 7, 15, 0, 16, 1000000 };
	for (size_t i = 0; i < 6; i++) {
		f = protobuf_c_message_descriptor_get_field(
			&foo__test_mess_packed__descriptor, tags[i]);
		if (f)
			printf("by_tag %u -> %s id=%u\n", tags[i], f->name, f->id);
		else
			printf("by_tag %u -> NULL\n", tags[i]);
	}
	/* oneof flag + packed flag observable through the descriptor */
	f = protobuf_c_message_descriptor_get_field_by_name(
		&foo__test_mess_oneof__descriptor, "test_int32");
	printf("oneof test_int32 flags=%u\n", f->flags);
	f = protobuf_c_message_descriptor_get_field_by_name(
		&foo__test_mess_oneof__descriptor, "test_string");
	printf("oneof test_string flags=%u\n", f->flags);
}

/* --- section 12: services --- */

static int g_destroyed = 0;

static void
my_destroy(Foo__DirLookup_Service *service)
{
	g_destroyed = 1;
	(void) service;
}

static void
dir_lookup_by_name_impl(Foo__DirLookup_Service *service,
			const Foo__Name *input,
			Foo__LookupResult_Closure closure,
			void *closure_data)
{
	Foo__LookupResult result = FOO__LOOKUP_RESULT__INIT;
	printf("  handler input name=");
	strout(input->name);
	printf("  handler closure_data=%p\n", closure_data);
	(void) service;
	closure(&result, closure_data);
}

static void
result_closure(const Foo__LookupResult *result, void *closure_data)
{
	printf("  closure called closure_data=%p person=%d\n",
	       closure_data, result->person ? 1 : 0);
}

static void
test_services(void)
{
	section("services");
	Foo__DirLookup_Service service;
	foo__dir_lookup__init(&service, my_destroy);
	service.by_name = dir_lookup_by_name_impl;

	const ProtobufCMethodDescriptor *md =
		protobuf_c_service_descriptor_get_method_by_name(
			&foo__dir_lookup__descriptor, "ByName");
	printf("method ByName -> %s (in=%s out=%s)\n", md->name,
	       md->input->short_name, md->output->short_name);
	md = protobuf_c_service_descriptor_get_method_by_name(
		&foo__dir_lookup__descriptor, "Nope");
	printf("method Nope -> %s\n", md ? md->name : "NULL");

	Foo__Name name = FOO__NAME__INIT;
	name.name = "alice";
	printf("invoke:\n");
	foo__dir_lookup__by_name((ProtobufCService *) &service, &name,
				 result_closure, (void *) 0x1234);
	printf("destroyed before destroy=%d\n", g_destroyed);
	protobuf_c_service_destroy((ProtobufCService *) &service);
	printf("destroyed after destroy=%d\n", g_destroyed);
}

/* --- section 13: proto3 (unlabeled) battery --- */

static void
test_proto3_battery(void)
{
	section("proto3");
	Foo__Person p = FOO__PERSON__INIT;
	printf("fresh size=%zu\n", foo__person__get_packed_size(&p));
	uint8_t e[1];
	printf("fresh pack=%zu\n", foo__person__pack(&p, e));

	Foo__Person__PhoneNumber__Comment comment = FOO__PERSON__PHONE_NUMBER__COMMENT__INIT;
	comment.comment = "nice";
	Foo__Person__PhoneNumber phone1 = FOO__PERSON__PHONE_NUMBER__INIT;
	phone1.number = "1234";
	phone1.type = FOO__PERSON__PHONE_TYPE__WORK;
	phone1.comment = &comment;
	Foo__Person__PhoneNumber phone2 = FOO__PERSON__PHONE_NUMBER__INIT;
	phone2.number = "5678";
	phone2.type = FOO__PERSON__PHONE_TYPE__MOBILE;
	Foo__Person__PhoneNumber *phones[2] = { &phone1, &phone2 };

	p.name = "dave b";
	p.id = 42;
	p.email = "dave@example.com";
	p.n_phone = 2;
	p.phone = phones;
	roundtrip(&p.base);
	Foo__Person *u = NULL;
	{
		size_t size = foo__person__get_packed_size(&p);
		uint8_t *packed = malloc(size);
		foo__person__pack(&p, packed);
		u = foo__person__unpack(NULL, size, packed);
		printf("readback name "); strout(u->name);
		printf("readback id=%d\n", u->id);
		printf("readback email "); strout(u->email);
		printf("readback n_phone=%zu\n", u->n_phone);
		for (size_t i = 0; i < u->n_phone; i++) {
			printf("  phone[%zu] number ", i);
			strout(u->phone[i]->number);
			printf("  phone[%zu] type=%d comment=%d\n", i,
			       u->phone[i]->type,
			       u->phone[i]->comment ? 1 : 0);
			if (u->phone[i]->comment) {
				printf("  phone[%zu] comment ", i);
				strout(u->phone[i]->comment->comment);
			}
		}
		foo__person__free_unpacked(u, NULL);
		free(packed);
	}

	/* zeroish skipping: id=0 and email="" are omitted */
	Foo__Person p2 = FOO__PERSON__INIT;
	p2.name = "zeroish";
	p2.id = 0;
	p2.email = "";
	roundtrip(&p2.base);
}

/* --- section 14: unknown fields --- */

static void
test_unknown_fields(void)
{
	section("unknown-fields");
	/* known field 1 (test_int32=7) plus unknowns: varint 99, fixed32 100,
	 * fixed64 101, len-prefixed 102 (5 bytes "hello"), len-prefixed 104
	 * with EMPTY payload, varint 103 */
	static const uint8_t wire[] = {
		0x08, 0x07,
		0x98, 0x06, 0x96, 0x01,
		0xa5, 0x06, 0x01, 0x02, 0x03, 0x04,
		0xa9, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0xb2, 0x06, 0x05, 'h', 'e', 'l', 'l', 'o',
		0xc2, 0x06, 0x00,
		0xb8, 0x06, 0x01,
	};
	Foo__TestMessOptional *u = (Foo__TestMessOptional *) protobuf_c_message_unpack(&foo__test_mess_optional__descriptor, 
		NULL, sizeof(wire), wire);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("known int32 has=%d val=%d\n",
		       u->has_test_int32 ? 1 : 0, u->test_int32);
		printf("n_unknown=%u\n", u->base.n_unknown_fields);
		for (unsigned i = 0; i < u->base.n_unknown_fields; i++) {
			printf("  unknown[%u] tag=%u wire=%u len=%zu ",
			       i, u->base.unknown_fields[i].tag,
			       u->base.unknown_fields[i].wire_type,
			       u->base.unknown_fields[i].len);
			hexout(u->base.unknown_fields[i].data,
			       u->base.unknown_fields[i].len);
		}
		size_t size = protobuf_c_message_get_packed_size(&u->base);
		uint8_t *rp = malloc(size);
		size_t rw = protobuf_c_message_pack(&u->base, rp);
		printf("repack size=%zu match=%s\n", rw,
		       (rw == sizeof(wire) && memcmp(rp, wire, sizeof(wire)) == 0)
		       ? "yes" : "NO");
		printf("repack ");
		hexout(rp, rw);
		free(rp);
		protobuf_c_message_free_unpacked(&u->base, NULL);
	}
}

/* --- section 15: merge semantics --- */

static void
test_merge(void)
{
	section("merge");
	/* test_int32 twice (last wins) then test_message twice (merge: repeated
	 * concat, earlier-only optionals zero-copied, required last-wins) */
	/* submsg1 = {test=1, val1=5 (has), rep=[1,2]} -> 8 bytes
	 * submsg2 = {test=2, rep=[3]} -> 4 bytes */
	static const uint8_t wire[] = {
		0x08, 0x05, 0x08, 0x06,
		0x92, 0x01, 0x08, 0x20, 0x01, 0x30, 0x05, 0x40, 0x01, 0x40, 0x02,
		0x92, 0x01, 0x04, 0x20, 0x02, 0x40, 0x03,
	};
	Foo__TestMessOptional *u = (Foo__TestMessOptional *) protobuf_c_message_unpack(&foo__test_mess_optional__descriptor, 
		NULL, sizeof(wire), wire);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	if (u) {
		printf("int32=%d (last wins)\n", u->test_int32);
		Foo__SubMess *sm = u->test_message;
		printf("sub test=%d has_val1=%d val1=%d n_rep=%zu rep=[",
		       sm->test, sm->has_val1 ? 1 : 0, sm->val1, sm->n_rep);
		for (size_t i = 0; i < sm->n_rep; i++)
			printf("%s%d", i ? ", " : "", sm->rep[i]);
		printf("]\n");
		protobuf_c_message_free_unpacked(&u->base, NULL);
	}
}

/* --- section 16: unpack error taxonomy --- */

static void
unpack_err(const char *name, const ProtobufCMessageDescriptor *desc,
	   const uint8_t *data, size_t len)
{
	ProtobufCMessage *m = protobuf_c_message_unpack(desc, NULL, len, data);
	printf("%s: %s\n", name, m ? "NOT-NULL" : "NULL");
	if (m)
		protobuf_c_message_free_unpacked(m, NULL);
}

static void
test_errors(void)
{
	section("errors");
	static const uint8_t bad_tag0[] = { 0x00 };
	static const uint8_t trunc_varint[] = { 0x08, 0x80 };
	static const uint8_t wire3[] = { 0x0b };
	static const uint8_t wire4[] = { 0x0c };
	static const uint8_t wire6[] = { 0x0e };
	static const uint8_t wire7[] = { 0x0f };
	static const uint8_t short64[] = { 0x09, 0x01 };
	static const uint8_t short32[] = { 0x0d, 0x01 };
	static const uint8_t len_over_intmax[] = { 0x0a, 0xff, 0xff, 0xff, 0xff, 0x0f };
	static const uint8_t len_too_long[] = { 0x0a, 0x64, 'x' };
	static const uint8_t len_truncated[] = { 0x0a, 0x80 };
	static const uint8_t packed_fixed_bad[] = { 0x1a, 0x02, 0x01, 0x02 };
	static const uint8_t packed_varint_bad[] = { 0x0a, 0x01, 0x80 };
	static const uint8_t wrong_wiretype[] = { 0x0d, 0x01, 0x00, 0x00, 0x00 };
	unpack_err("bad-tag0", &foo__test_mess_optional__descriptor,
		   bad_tag0, sizeof(bad_tag0));
	unpack_err("truncated-varint", &foo__test_mess_optional__descriptor,
		   trunc_varint, sizeof(trunc_varint));
	unpack_err("wiretype-3", &foo__test_mess_optional__descriptor,
		   wire3, sizeof(wire3));
	unpack_err("wiretype-4", &foo__test_mess_optional__descriptor,
		   wire4, sizeof(wire4));
	unpack_err("wiretype-6", &foo__test_mess_optional__descriptor,
		   wire6, sizeof(wire6));
	unpack_err("wiretype-7", &foo__test_mess_optional__descriptor,
		   wire7, sizeof(wire7));
	unpack_err("short-64bit", &foo__test_mess_optional__descriptor,
		   short64, sizeof(short64));
	unpack_err("short-32bit", &foo__test_mess_optional__descriptor,
		   short32, sizeof(short32));
	unpack_err("len-over-intmax", &foo__test_mess_optional__descriptor,
		   len_over_intmax, sizeof(len_over_intmax));
	unpack_err("len-too-long", &foo__test_mess_optional__descriptor,
		   len_too_long, sizeof(len_too_long));
	unpack_err("len-truncated", &foo__test_mess_optional__descriptor,
		   len_truncated, sizeof(len_truncated));
	unpack_err("packed-fixed32-badlen", &foo__test_mess_packed__descriptor,
		   packed_fixed_bad, sizeof(packed_fixed_bad));
	unpack_err("packed-varint-bad-tail", &foo__test_mess_packed__descriptor,
		   packed_varint_bad, sizeof(packed_varint_bad));
	unpack_err("wrong-wiretype", &foo__test_mess_optional__descriptor,
		   wrong_wiretype, sizeof(wrong_wiretype));
	unpack_err("missing-required", &foo__test_mess_required_string__descriptor,
		   NULL, 0);
	unpack_err("missing-required-int32", &foo__test_mess_required_int32__descriptor,
		   NULL, 0);
	/* empty input is VALID: an empty message unpack succeeds */
	{
		Foo__EmptyMess *em = foo__empty_mess__unpack(NULL, 0, NULL);
		printf("empty-unpack: %s\n", em ? "ok" : "NULL");
		if (em)
			foo__empty_mess__free_unpacked(em, NULL);
	}
	/* bool parsed from a 2-byte varint (any nonzero 7-bit group -> TRUE) */
	{
		static const uint8_t boolwire[] = { 0x68, 0x80, 0x01 };
		Foo__TestMessOptional *u = (Foo__TestMessOptional *) protobuf_c_message_unpack(&foo__test_mess_optional__descriptor, 
			NULL, sizeof(boolwire), boolwire);
		printf("bool-2byte-varint: has=%d val=%d\n",
		       u->has_test_boolean ? 1 : 0, u->test_boolean ? 1 : 0);
		protobuf_c_message_free_unpacked(&u->base, NULL);
	}
	/* required-with-default: empty input succeeds (defaults applied) */
	{
		Foo__DefaultRequiredValues *u = foo__default_required_values__unpack(
			NULL, 0, NULL);
		printf("required-with-default empty: %s v_int32=%d\n",
		       u ? "ok" : "NULL", u ? u->v_int32 : -999);
		if (u)
			foo__default_required_values__free_unpacked(u, NULL);
	}
}

/* --- section 17: allocator --- */

static size_t g_n_alloc = 0;
static size_t g_n_free = 0;
static size_t g_total = 0;

static void *
count_alloc(void *data, size_t size)
{
	(void) data;
	g_n_alloc++;
	g_total += size;
	printf("  alloc %zu\n", size);
	return malloc(size);
}

static void
count_free(void *data, void *ptr)
{
	(void) data;
	g_n_free++;
	printf("  free\n");
	free(ptr);
}

static void
test_allocator(void)
{
	section("allocator");
	Foo__SubMess sub = FOO__SUB_MESS__INIT;
	sub.test = 1;
	static int32_t srep[3] = { 1, 2, 3 };
	sub.n_rep = 3; sub.rep = srep;

	Foo__TestMessOptional m = FOO__TEST_MESS_OPTIONAL__INIT;
	/* all 18 fields set: the scanned-member slab (16 stack + heap growth)
	 * and every heap-owning field type are exercised */
	m.has_test_int32 = 1; m.test_int32 = -5;
	m.has_test_sint32 = 1; m.test_sint32 = -5;
	m.has_test_sfixed32 = 1; m.test_sfixed32 = -5;
	m.has_test_int64 = 1; m.test_int64 = -1234567890123LL;
	m.has_test_sint64 = 1; m.test_sint64 = -1234567890123LL;
	m.has_test_sfixed64 = 1; m.test_sfixed64 = -1234567890123LL;
	m.has_test_uint32 = 1; m.test_uint32 = 4294967295u;
	m.has_test_fixed32 = 1; m.test_fixed32 = 4294967295u;
	m.has_test_uint64 = 1; m.test_uint64 = 18446744073709551615ULL;
	m.has_test_fixed64 = 1; m.test_fixed64 = 18446744073709551615ULL;
	m.has_test_float = 1; memcpy(&m.test_float, &pack_fl[2], 4);
	m.has_test_double = 1; memcpy(&m.test_double, &pack_db[2], 8);
	m.has_test_boolean = 1; m.test_boolean = 1;
	m.has_test_enum_small = 1; m.test_enum_small = FOO__TEST_ENUM_SMALL__NEG_VALUE;
	m.has_test_enum = 1; m.test_enum = FOO__TEST_ENUM__VALUE268435456;
	m.test_string = "hello world";
	uint8_t ob[5] = { 'b', 'y', 't', 'e', 's' };
	m.has_test_bytes = 1; m.test_bytes.len = 5; m.test_bytes.data = ob;
	m.test_message = &sub;

	ProtobufCAllocator alloc = { count_alloc, count_free, NULL };
	uint8_t *packed = malloc(protobuf_c_message_get_packed_size(&m.base));
	protobuf_c_message_pack(&m.base, packed);
	Foo__TestMessOptional *u = (Foo__TestMessOptional *) protobuf_c_message_unpack(&foo__test_mess_optional__descriptor, 
		&alloc, protobuf_c_message_get_packed_size(&m.base), packed);
	printf("unpack=%s\n", u ? "ok" : "NULL");
	protobuf_c_message_free_unpacked(&u->base, &alloc);
	printf("totals allocs=%zu frees=%zu bytes=%zu\n",
	       g_n_alloc, g_n_free, g_total);
	free(packed);

	/* >16 scanned members: heap slab + heap required-bitmap paths */
	g_n_alloc = 0; g_n_free = 0; g_total = 0;
	Foo__TestRequiredFieldsBitmap rb = FOO__TEST_REQUIRED_FIELDS_BITMAP__INIT;
	rb.field1 = "a";
	rb.field129 = "b";
	size_t rsize = foo__test_required_fields_bitmap__get_packed_size(&rb);
	uint8_t *rpacked = malloc(rsize);
	foo__test_required_fields_bitmap__pack(&rb, rpacked);
	printf("bitmap-message size=%zu\n", rsize);
	Foo__TestRequiredFieldsBitmap *ru = foo__test_required_fields_bitmap__unpack(
		&alloc, rsize, rpacked);
	printf("bitmap unpack=%s field1=%s field129=%s\n",
	       ru ? "ok" : "NULL",
	       ru ? ru->field1 : "?",
	       ru ? ru->field129 : "?");
	foo__test_required_fields_bitmap__free_unpacked(ru, &alloc);
	printf("bitmap totals allocs=%zu frees=%zu bytes=%zu\n",
	       g_n_alloc, g_n_free, g_total);
	free(rpacked);

	/* bitmap-missing-required: crafted wire with only field1 -> the
	 * 129th bit is not set, so the required check fails (a NULL required
	 * string would PACK as an empty string and pass, so the wire must be
	 * crafted without field129) */
	{
		static const uint8_t wire129[] = { 0x0a, 0x01, 'a' };
		Foo__TestRequiredFieldsBitmap *ru2 =
			foo__test_required_fields_bitmap__unpack(&alloc, sizeof(wire129), wire129);
		printf("bitmap missing-129: %s\n", ru2 ? "NOT-NULL" : "NULL");
		if (ru2)
			foo__test_required_fields_bitmap__free_unpacked(ru2, &alloc);
	}
}

/* --- section 18: buffer-simple --- */

static void
test_buffer_simple(void)
{
	section("buffer-simple");
	Foo__TestMessPacked m = FOO__TEST_MESS_PACKED__INIT;
	m.n_test_int32 = 24; m.test_int32 = (int32_t *) pack_i32;
	m.n_test_sint32 = 24; m.test_sint32 = (int32_t *) pack_si32;
	m.n_test_sfixed32 = 24; m.test_sfixed32 = (int32_t *) pack_sf32;
	m.n_test_int64 = 24; m.test_int64 = (int64_t *) pack_i64;
	m.n_test_sint64 = 24; m.test_sint64 = (int64_t *) pack_si64;
	m.n_test_sfixed64 = 24; m.test_sfixed64 = (int64_t *) pack_sf64;
	m.n_test_uint32 = 24; m.test_uint32 = (uint32_t *) pack_u32;
	m.n_test_fixed32 = 24; m.test_fixed32 = (uint32_t *) pack_fx32;
	m.n_test_uint64 = 24; m.test_uint64 = (uint64_t *) pack_u64;
	m.n_test_fixed64 = 24; m.test_fixed64 = (uint64_t *) pack_fx64;
	m.n_test_float = 24; m.test_float = (float *) pack_fl;
	m.n_test_double = 24; m.test_double = (double *) pack_db;
	m.n_test_boolean = 24; m.test_boolean = (protobuf_c_boolean *) pack_bool;
	m.n_test_enum_small = 24; m.test_enum_small = (Foo__TestEnumSmall *) pack_esm;
	m.n_test_enum = 24; m.test_enum = (Foo__TestEnum *) pack_en;

	size_t size = protobuf_c_message_get_packed_size(&m.base);
	uint8_t *packed = malloc(size);
	protobuf_c_message_pack(&m.base, packed);

	uint8_t pad[8];
	ProtobufCBufferSimple bs = PROTOBUF_C_BUFFER_SIMPLE_INIT(pad);
	size_t bsize = protobuf_c_message_pack_to_buffer(&m.base, &bs.base);
	printf("pack_to_buffer size=%zu\n", bsize);
	printf("buffer alloced=%zu len=%zu must_free=%d\n",
	       bs.alloced, bs.len, bs.must_free_data ? 1 : 0);
	printf("buffer matches pack: %s\n",
	       (bs.len == size && memcmp(bs.data, packed, size) == 0) ? "yes" : "NO");
	PROTOBUF_C_BUFFER_SIMPLE_CLEAR(&bs);

	/* a small pad with a tiny message: no growth past the pad */
	{
		Foo__TestMessOptional om = FOO__TEST_MESS_OPTIONAL__INIT;
		om.has_test_int32 = 1; om.test_int32 = 5;
		uint8_t pad2[4];
		ProtobufCBufferSimple bs2 = PROTOBUF_C_BUFFER_SIMPLE_INIT(pad2);
		protobuf_c_message_pack_to_buffer(&om.base, &bs2.base);
		printf("small message: alloced=%zu len=%zu must_free=%d\n",
		       bs2.alloced, bs2.len, bs2.must_free_data ? 1 : 0);
		PROTOBUF_C_BUFFER_SIMPLE_CLEAR(&bs2);
	}
	free(packed);
}

/* --- section 19: dynamic descriptor (message_init_generic fallback) --- */

struct DynMsg {
	ProtobufCMessage base;
	int32_t f_i32;
	int64_t f_i64;
	protobuf_c_boolean f_bool;
	const char *f_str;
	ProtobufCBinaryData f_bytes;
	protobuf_c_boolean has_f_i32;
	protobuf_c_boolean has_f_i64;
	protobuf_c_boolean has_f_bool;
	protobuf_c_boolean has_f_bytes;
};

static const int32_t dyn_i32_def = -7;
static const int64_t dyn_i64_def = 1234567890123LL;
static const protobuf_c_boolean dyn_bool_def = 1;
static const char *dyn_str_def = "dyn-default";
static const uint8_t dyn_bytes_data[] = { 0x01, 0x02, 0x03 };
static const ProtobufCBinaryData dyn_bd_def = { 3, (uint8_t *) dyn_bytes_data };

static const ProtobufCFieldDescriptor dyn_fields[5] = {
	{ "f_i32", 1, PROTOBUF_C_LABEL_OPTIONAL, PROTOBUF_C_TYPE_INT32,
	  offsetof(struct DynMsg, has_f_i32), offsetof(struct DynMsg, f_i32),
	  NULL, &dyn_i32_def, 0, 0, NULL, NULL },
	{ "f_i64", 2, PROTOBUF_C_LABEL_OPTIONAL, PROTOBUF_C_TYPE_INT64,
	  offsetof(struct DynMsg, has_f_i64), offsetof(struct DynMsg, f_i64),
	  NULL, &dyn_i64_def, 0, 0, NULL, NULL },
	{ "f_bool", 3, PROTOBUF_C_LABEL_OPTIONAL, PROTOBUF_C_TYPE_BOOL,
	  offsetof(struct DynMsg, has_f_bool), offsetof(struct DynMsg, f_bool),
	  NULL, &dyn_bool_def, 0, 0, NULL, NULL },
	{ "f_str", 4, PROTOBUF_C_LABEL_OPTIONAL, PROTOBUF_C_TYPE_STRING,
	  0, offsetof(struct DynMsg, f_str), NULL, "dyn-default", 0, 0, NULL, NULL },
	{ "f_bytes", 5, PROTOBUF_C_LABEL_OPTIONAL, PROTOBUF_C_TYPE_BYTES,
	  offsetof(struct DynMsg, has_f_bytes), offsetof(struct DynMsg, f_bytes),
	  NULL, &dyn_bd_def, 0, 0, NULL, NULL },
};

	/* field indices sorted by field name (strcmp):
	 * fields[2]=f_bool < fields[4]=f_bytes < fields[0]=f_i32 <
	 * fields[1]=f_i64 < fields[3]=f_str */
	static const unsigned dyn_indices_by_name[5] = { 2, 4, 0, 1, 3 };

static const ProtobufCIntRange dyn_ranges[2] = { { 1, 0 }, { 0, 5 } };

static const ProtobufCMessageDescriptor dyn_descriptor = {
	PROTOBUF_C__MESSAGE_DESCRIPTOR_MAGIC,
	"dyn.DynMsg", "DynMsg", "DynMsg", "dyn",
	sizeof(struct DynMsg), 5, dyn_fields, dyn_indices_by_name,
	1, dyn_ranges, NULL, NULL, NULL, NULL
};

static void
test_dynamic_descriptor(void)
{
	section("dynamic");
	/* message_init == NULL exercises the runtime's message_init_generic */
	ProtobufCMessage *m = protobuf_c_message_unpack(&dyn_descriptor, NULL, 0, NULL);
	printf("unpack-empty=%s\n", m ? "ok" : "NULL");
	if (m) {
		struct DynMsg *d = (struct DynMsg *) m;
		printf("f_i32=%d has=%d\n", d->f_i32, d->has_f_i32 ? 1 : 0);
		printf("f_i64=%" PRId64 " has=%d\n", d->f_i64, d->has_f_i64 ? 1 : 0);
		printf("f_bool=%d has=%d\n", d->f_bool ? 1 : 0, d->has_f_bool ? 1 : 0);
		printf("f_str "); strout(d->f_str);
		printf("f_bytes len=%zu ", d->f_bytes.len);
		hexout(d->f_bytes.data, d->f_bytes.len);
		printf("fresh size=%zu\n", protobuf_c_message_get_packed_size(m));
		/* set the has flags so the defaults serialize; replace the
		 * default string so it is not skipped as the default */
		d->has_f_i32 = 1;
		d->has_f_i64 = 1;
		d->has_f_bool = 1;
		d->f_str = strdup("custom");
		d->has_f_bytes = 1;
		size_t size = protobuf_c_message_get_packed_size(m);
		uint8_t *packed = malloc(size);
		size_t wrote = protobuf_c_message_pack(m, packed);
		printf("size=%zu wrote=%zu ", size, wrote);
		hexout(packed, wrote);
		free(packed);
		protobuf_c_message_free_unpacked(m, NULL);
		printf("freed ok\n");
	}
	/* descriptor lookups on the dynamic descriptor */
	const ProtobufCFieldDescriptor *f =
		protobuf_c_message_descriptor_get_field_by_name(&dyn_descriptor, "f_i32");
	printf("by_name f_i32 -> id=%u\n", f->id);
	f = protobuf_c_message_descriptor_get_field(&dyn_descriptor, 5);
	printf("by_tag 5 -> %s\n", f->name);
	f = protobuf_c_message_descriptor_get_field(&dyn_descriptor, 6);
	printf("by_tag 6 -> %s\n", f ? f->name : "NULL");
}

/* --- section 20: empty message + free(NULL) --- */

static void
test_empty(void)
{
	section("empty");
	Foo__EmptyMess m = FOO__EMPTY_MESS__INIT;
	printf("size=%zu\n", foo__empty_mess__get_packed_size(&m));
	uint8_t buf[1];
	printf("pack=%zu ", foo__empty_mess__pack(&m, buf));
	hexout(buf, 0);
	printf("check=%d\n", protobuf_c_message_check(&m.base) ? 1 : 0);
	protobuf_c_message_free_unpacked(NULL, NULL);
	printf("free-NULL ok\n");
	/* unpack of a length-prefixed empty string into a required string:
	 * NULL-string pack path (string_pack(NULL) writes a single 0x00) */
	Foo__TestMessRequiredString rs = FOO__TEST_MESS_REQUIRED_STRING__INIT;
	rs.test = NULL;
	size_t size = foo__test_mess_required_string__get_packed_size(&rs);
	printf("null-string size=%zu\n", size);
	{
		uint8_t *packed = malloc(size);
		foo__test_mess_required_string__pack(&rs, packed);
		printf("null-string ");
		hexout(packed, size);
		free(packed);
	}
	Foo__TestMessRequiredMessage rm = FOO__TEST_MESS_REQUIRED_MESSAGE__INIT;
	rm.test = NULL;
	size = foo__test_mess_required_message__get_packed_size(&rm);
	printf("null-message size=%zu ", size);
	{
		uint8_t *packed = malloc(size);
		foo__test_mess_required_message__pack(&rm, packed);
		printf("null-message ");
		hexout(packed, size);
		free(packed);
	}
}

/* --- section 21: nested whole-tree battery --- */

static void
test_nested_battery(void)
{
	section("nested");
	Foo__TestMess rep = FOO__TEST_MESS__INIT;
	static int32_t n_i32[2] = { 1, 2 };
	static int32_t n_si32[1] = { -3 };
	static uint32_t n_u32[1] = { 7 };
	static protobuf_c_boolean n_bool[2] = { 1, 0 };
	static const char *n_str[1] = { "nested" };
	static uint8_t n_bytes1[2] = { 0xde, 0xad };
	static ProtobufCBinaryData n_bin[1] = { { 2, n_bytes1 } };
	Foo__SubMess n_sub = FOO__SUB_MESS__INIT;
	n_sub.test = 1;
	Foo__SubMess *n_msgs[1];
	n_msgs[0] = &n_sub;
	rep.n_test_int32 = 2; rep.test_int32 = n_i32;
	rep.n_test_sint32 = 1; rep.test_sint32 = n_si32;
	rep.n_test_uint32 = 1; rep.test_uint32 = n_u32;
	rep.n_test_boolean = 2; rep.test_boolean = n_bool;
	rep.n_test_string = 1; rep.test_string = n_str;
	rep.n_test_bytes = 1; rep.test_bytes = n_bin;
	rep.n_test_message = 1; rep.test_message = n_msgs;

	Foo__TestMessOptional opt = FOO__TEST_MESS_OPTIONAL__INIT;
	opt.has_test_int32 = 1; opt.test_int32 = 11;

	Foo__TestMessOneof oneof = FOO__TEST_MESS_ONEOF__INIT;
	oneof.test_oneof_case = FOO__TEST_MESS_ONEOF__TEST_ONEOF_TEST_INT32;
	oneof.test_int32 = 22;

	Foo__DefaultOptionalValues defs = FOO__DEFAULT_OPTIONAL_VALUES__INIT;
	defs.has_v_int32 = 1; defs.v_int32 = 33;

	Foo__TestMessSubMess tm = FOO__TEST_MESS_SUB_MESS__INIT;
	tm.rep_mess = &rep;
	tm.opt_mess = &opt;
	tm.oneof_mess = &oneof;
	tm.req_mess = &n_sub;
	tm.def_mess = &defs;

	roundtrip(&tm.base);
	Foo__TestMessSubMess *u = NULL;
	{
		size_t size = foo__test_mess_sub_mess__get_packed_size(&tm);
		uint8_t *packed = malloc(size);
		foo__test_mess_sub_mess__pack(&tm, packed);
		u = foo__test_mess_sub_mess__unpack(NULL, size, packed);
		printf("readback rep.n_int32=%zu rep.n_str=%zu rep.n_bytes=%zu "
		       "rep.n_msg=%zu\n",
		       u->rep_mess->n_test_int32, u->rep_mess->n_test_string,
		       u->rep_mess->n_test_bytes, u->rep_mess->n_test_message);
		printf("readback rep.int32[0]=%d rep.sint32[0]=%d rep.bool[0]=%d\n",
		       u->rep_mess->test_int32[0], u->rep_mess->test_sint32[0],
		       u->rep_mess->test_boolean[0] ? 1 : 0);
		printf("readback rep.str[0] "); strout(u->rep_mess->test_string[0]);
		printf("readback rep.bytes[0] len=%zu ", u->rep_mess->test_bytes[0].len);
		hexout(u->rep_mess->test_bytes[0].data, u->rep_mess->test_bytes[0].len);
		printf("readback rep.msg[0] test=%d\n",
		       u->rep_mess->test_message[0]->test);
		printf("readback opt.int32 has=%d val=%d\n",
		       u->opt_mess->has_test_int32 ? 1 : 0, u->opt_mess->test_int32);
		printf("readback oneof case=%d int32=%d\n",
		       u->oneof_mess->test_oneof_case, u->oneof_mess->test_int32);
		printf("readback defs.v_int32 has=%d val=%d\n",
		       u->def_mess->has_v_int32 ? 1 : 0, u->def_mess->v_int32);
		foo__test_mess_sub_mess__free_unpacked(u, NULL);
		free(packed);
	}
}

/* --- section 22: proto3 service round trip --- */

int
main(void)
{
	printf("=== protobuf-c 1.5.2 probe ===\n");
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
	return 0;
}

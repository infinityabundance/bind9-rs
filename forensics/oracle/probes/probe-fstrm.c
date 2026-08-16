/* probe-fstrm.c — fstrm 0.6.1 surface probe (§26, §37).
 *
 * Exercises the conservation surface: the control codec (the complete
 * t/test_control.c frame corpus: decode with/without header, get_type,
 * field enumeration, content-type matching incl. the empty-field match and
 * the STOP/FINISH-never-match rules, byte-exact re-encode); the writer
 * (options, unidirectional + bidirectional open state machines incl. the
 * content-type negotiation, writev incl. the >128-frame chunked path,
 * close/destroy result taxonomy); the reader (options incl. max_frame_size
 * bounds, open/read/stop/close states, content-type mismatch, the
 * max-frame-size enforcement); the file transports (path round trip with a
 * byte-exact file dump, the double-open and wrong-content-type error
 * surfaces); the unix/tcp writer transports (init validation: sun_path
 * length, inet_pton address parsing AF_INET/AF_INET6, strtoul base-0 port
 * parsing incl. trailing garbage, >65535, hex/octal/empty/negative); and
 * the fstrm_iothr async pipeline (option bounds, submit taxonomy,
 * get_input_queue/get_input_queue_idx, a file pipeline whose output is
 * byte-exact, the discard-on-unopenable-writer free-callback path, and the
 * full four-corner bidirectional handshake over AF_UNIX and TCP loopback
 * with an fstrm_reader on the accepting end).
 *
 * Runs in the same oracle-fstrm-0.6.1 container as the Rust mirror
 * (bind9-rs-tools/src/bin/fstrm-probe.rs); stdout must be byte-identical.
 * All inputs are fixed buffers/strings; nothing wall-clock, address or
 * pointer dependent is printed.  The consumer thread writes its transcript
 * to a file which the main thread prints after join, so the output is
 * deterministic.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <fstrm.h>

#define WORK "/tmp/fstrm_work"

/* ------------------------------------------------------------------ utils */

static void
print_string(const uint8_t *data, size_t len)
{
	fputc('"', stdout);
	while (len-- != 0) {
		unsigned c = *(data++);
		if (c >= 0x20 && c <= 0x7e) {
			if (c == '"')
				fputs("\\\"", stdout);
			else
				fputc(c, stdout);
		} else {
			fprintf(stdout, "\\x%02x", c);
		}
	}
	fputc('"', stdout);
}

static void
dump(const uint8_t *p, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++)
		printf("%02x", p[i]);
}

static const char *
res_str(fstrm_res res)
{
	switch (res) {
	case fstrm_res_success:
		return "success";
	case fstrm_res_failure:
		return "failure";
	case fstrm_res_again:
		return "again";
	case fstrm_res_invalid:
		return "invalid";
	case fstrm_res_stop:
		return "stop";
	default:
		return "?";
	}
}

static void
print_res(const char *what, fstrm_res res)
{
	printf("  %s -> %d (%s)\n", what, (int) res, res_str(res));
}

static void
mkwork(void)
{
	struct stat st;
	if (stat(WORK, &st) != 0)
		mkdir(WORK, 0777);
}

/* ------------------------------------------- control corpus (test_control.c) */

/* Placeholder "Content Type" values. */
static const uint8_t wharrgarbl[] = "wharr\x00garbl";
static const uint8_t wharrgarblv2[] = "wharrgarblv2";

static const uint8_t accept_1[] = { 0x00, 0x00, 0x00, 0x01 };
static const uint8_t accept_1_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x01,
};
static const uint8_t accept_2[] = {
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};
static const uint8_t accept_2_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x17,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};
static const uint8_t accept_3[] = {
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0c,
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};
static const uint8_t accept_3_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x2b,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0c,
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};
static const uint8_t ready_1[] = {
	0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0c,
	'w', 'h', 'a', 'r', 'r', 'g', 'a', 'r', 'b', 'l', 'v', '2',
};
static const uint8_t start_1[] = { 0x00, 0x00, 0x00, 0x02 };
static const uint8_t start_1_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x02,
};
static const uint8_t start_2[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};
static const uint8_t start_2_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x17,
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l',
};
static const uint8_t stop_1[] = { 0x00, 0x00, 0x00, 0x03 };
static const uint8_t stop_1_wh[] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x04,
	0x00, 0x00, 0x00, 0x03,
};

struct control_test {
	const uint8_t		*frame;
	size_t			len_frame;
	fstrm_control_type	type;
	uint32_t		flags;
	const uint8_t		*content_type;
	size_t			len_content_type;
	fstrm_res		match_res;
};

static const struct control_test control_tests[] = {
	{ .frame = accept_1, .len_frame = sizeof(accept_1), .type = FSTRM_CONTROL_ACCEPT },
	{ .frame = accept_1_wh, .len_frame = sizeof(accept_1_wh), .type = FSTRM_CONTROL_ACCEPT, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER },
	{ .frame = accept_2, .len_frame = sizeof(accept_2), .type = FSTRM_CONTROL_ACCEPT, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = accept_2_wh, .len_frame = sizeof(accept_2_wh), .type = FSTRM_CONTROL_ACCEPT, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = accept_3, .len_frame = sizeof(accept_3), .type = FSTRM_CONTROL_ACCEPT, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = accept_3_wh, .len_frame = sizeof(accept_3_wh), .type = FSTRM_CONTROL_ACCEPT, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = accept_3, .len_frame = sizeof(accept_3), .type = FSTRM_CONTROL_ACCEPT, .content_type = wharrgarblv2, .len_content_type = sizeof(wharrgarblv2) - 1 },
	{ .frame = accept_3_wh, .len_frame = sizeof(accept_3_wh), .type = FSTRM_CONTROL_ACCEPT, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .content_type = wharrgarblv2, .len_content_type = sizeof(wharrgarblv2) - 1 },
	{ .frame = ready_1, .len_frame = sizeof(ready_1), .type = FSTRM_CONTROL_READY, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = ready_1, .len_frame = sizeof(ready_1), .type = FSTRM_CONTROL_READY, .content_type = wharrgarblv2, .len_content_type = sizeof(wharrgarblv2) - 1 },
	{ .frame = start_1, .len_frame = sizeof(start_1), .type = FSTRM_CONTROL_START },
	{ .frame = start_1_wh, .len_frame = sizeof(start_1_wh), .type = FSTRM_CONTROL_START, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER },
	{ .frame = start_1, .len_frame = sizeof(start_1), .type = FSTRM_CONTROL_START, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = start_1_wh, .len_frame = sizeof(start_1_wh), .type = FSTRM_CONTROL_START, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = start_2, .len_frame = sizeof(start_2), .type = FSTRM_CONTROL_START, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = start_2, .len_frame = sizeof(start_2), .type = FSTRM_CONTROL_START, .content_type = wharrgarblv2, .len_content_type = sizeof(wharrgarblv2) - 1, .match_res = fstrm_res_failure },
	{ .frame = start_2_wh, .len_frame = sizeof(start_2_wh), .type = FSTRM_CONTROL_START, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .content_type = wharrgarbl, .len_content_type = sizeof(wharrgarbl) - 1 },
	{ .frame = stop_1, .len_frame = sizeof(stop_1), .type = FSTRM_CONTROL_STOP, .match_res = fstrm_res_failure },
	{ .frame = stop_1_wh, .len_frame = sizeof(stop_1_wh), .type = FSTRM_CONTROL_STOP, .flags = FSTRM_CONTROL_FLAG_WITH_HEADER, .match_res = fstrm_res_failure },
	{ .frame = NULL },
};

static const uint8_t invalid_1[] = { 0xff, };
static const uint8_t invalid_2[] = { 0xff, 0xff, };
static const uint8_t invalid_3[] = { 0xff, 0xff, 0xff, };
static const uint8_t invalid_4[] = { 0xff, 0xff, 0xff, };
static const uint8_t invalid_5[] = { 0xff, 0xff, 0xff, 0xff, };
static const uint8_t invalid_6[] = { 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t invalid_7[] = { 0xab, 0xad, 0x1d, 0xea, };
static const uint8_t invalid_8[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b',
};
static const uint8_t invalid_9[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0b,
	'w', 'h', 'a', 'r', 'r', 0x00, 'g', 'a', 'r', 'b', 'l', 'z',
};
static const uint8_t invalid_10[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00,
};
static const uint8_t invalid_11[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00,
};
static const uint8_t invalid_12[] = {
	0x00, 0x00, 0x00, 0x02,
	0x00, 0x00, 0x00, 0x01,
};

struct bytes {
	const uint8_t	*bytes;
	size_t		len;
};

static const struct bytes invalid[] = {
	{ invalid_1, sizeof(invalid_1) },
	{ invalid_2, sizeof(invalid_2) },
	{ invalid_3, sizeof(invalid_3) },
	{ invalid_4, sizeof(invalid_4) },
	{ invalid_5, sizeof(invalid_5) },
	{ invalid_6, sizeof(invalid_6) },
	{ invalid_7, sizeof(invalid_7) },
	{ invalid_8, sizeof(invalid_8) },
	{ invalid_9, sizeof(invalid_9) },
	{ invalid_10, sizeof(invalid_10) },
	{ invalid_11, sizeof(invalid_11) },
	{ invalid_12, sizeof(invalid_12) },
	{ NULL, 0 },
};

static fstrm_res
match_content_type(struct fstrm_control *c, const uint8_t *content_type,
		   size_t len_content_type)
{
	fstrm_res res;

	res = fstrm_control_match_field_content_type(c, content_type, len_content_type);
	printf("  Control frame is %scompatible with CONTENT_TYPE (%zu bytes): ",
	       res == fstrm_res_success ? "" : "NOT ", len_content_type);
	print_string(content_type, len_content_type);
	putchar('\n');

	return res;
}

static fstrm_res
decode_control_frame(struct fstrm_control *c, const uint8_t *control_frame,
		     size_t len_control_frame, uint32_t flags)
{
	fstrm_res res;
	fstrm_control_type type;

	res = fstrm_control_decode(c, control_frame, len_control_frame, flags);
	if (res == fstrm_res_success) {
		printf("Successfully decoded frame (%zu bytes):\n  ", len_control_frame);
		print_string(control_frame, len_control_frame);
		putchar('\n');
	} else {
		printf("Failed to decode frame (%zu bytes):\n  ", len_control_frame);
		print_string(control_frame, len_control_frame);
		putchar('\n');
		return res;
	}

	res = fstrm_control_get_type(c, &type);
	if (res != fstrm_res_success) {
		puts("  fstrm_control_get_type() failed.");
		return res;
	}
	printf("  The control frame is of type %s (0x%08x).\n",
	       fstrm_control_type_to_str(type), type);

	size_t n_ctype;
	res = fstrm_control_get_num_field_content_type(c, &n_ctype);
	if (res != fstrm_res_success) {
		puts("  fstrm_control_get_num_field_content_type() failed.");
		return res;
	}
	for (size_t idx = 0; idx < n_ctype; idx++) {
		const uint8_t *content_type;
		size_t len_content_type;

		res = fstrm_control_get_field_content_type(c, idx,
			&content_type, &len_content_type);
		if (res == fstrm_res_success) {
			printf("  The control frame has a CONTENT_TYPE field (%zu bytes): ",
			       len_content_type);
			print_string(content_type, len_content_type);
			putchar('\n');
		} else if (res == fstrm_res_failure) {
			puts("  The control frame does not have any CONTENT_TYPE fields.");
		} else {
			assert(0);
		}
	}

	return fstrm_res_success;
}

static void
test_reencode_frame(struct fstrm_control *c, const uint8_t *control_frame,
		    size_t len_control_frame, uint32_t flags)
{
	printf("Running %s().\n", __func__);

	fstrm_res res;
	size_t len_new_frame = 0, len_new_frame_2 = 0;

	res = fstrm_control_encoded_size(c, &len_new_frame, flags);
	assert(res == fstrm_res_success);
	printf("Need %zu bytes for new frame.\n", len_new_frame);
	assert(len_new_frame <= FSTRM_CONTROL_FRAME_LENGTH_MAX);
	uint8_t new_frame[len_new_frame];

	len_new_frame_2 = len_new_frame;
	res = fstrm_control_encode(c, new_frame, &len_new_frame_2, flags);
	assert(res == fstrm_res_success);
	printf("Successfully encoded a new frame (%zu bytes):\n  ", len_new_frame_2);
	print_string(new_frame, len_new_frame_2);
	putchar('\n');
	assert(len_new_frame == len_new_frame_2);
	assert(len_new_frame == len_control_frame);

	assert(memcmp(control_frame, new_frame, len_control_frame) == 0);
	puts("New frame is identical to original frame.");
}

static void
test_reencode_frame_static(struct fstrm_control *c, const uint8_t *control_frame,
			   size_t len_control_frame, uint32_t flags)
{
	printf("Running %s().\n", __func__);

	fstrm_res res;
	uint8_t new_frame[FSTRM_CONTROL_FRAME_LENGTH_MAX];
	size_t len_new_frame = sizeof(new_frame);

	res = fstrm_control_encode(c, new_frame, &len_new_frame, flags);
	assert(res == fstrm_res_success);
	assert(len_new_frame <= FSTRM_CONTROL_FRAME_LENGTH_MAX);
	printf("Successfully encoded a new frame (%zu bytes):\n  ", len_new_frame);
	print_string(new_frame, len_new_frame);
	putchar('\n');

	assert(memcmp(control_frame, new_frame, len_control_frame) == 0);
	puts("New frame is identical to original frame.");
}

static void
test_control_test(struct fstrm_control *c, const struct control_test *test)
{
	printf("Running %s().\n", __func__);

	if (test->flags & FSTRM_CONTROL_FLAG_WITH_HEADER)
		printf("Control frames include escape sequence and control frame length.\n"
		       "  (FSTRM_CONTROL_FLAG_WITH_HEADER enabled.)\n");

	fstrm_res res;
	fstrm_control_type type;

	res = decode_control_frame(c, test->frame, test->len_frame, test->flags);
	assert(res == fstrm_res_success);
	res = fstrm_control_get_type(c, &type);
	assert(res == fstrm_res_success);
	assert(type == test->type);

	res = match_content_type(c, test->content_type, test->len_content_type);
	assert(res == test->match_res);

	test_reencode_frame(c, test->frame, test->len_frame, test->flags);
	test_reencode_frame_static(c, test->frame, test->len_frame, test->flags);
}

static void
run_control_corpus(void)
{
	struct fstrm_control *c;

	c = fstrm_control_init();

	puts("====> The following tests must succeed. <====");
	printf("Running %s().\n\n", "test_control_tests");
	for (const struct control_test *test = &control_tests[0];
	     test->frame != NULL; test++)
	{
		test_control_test(c, test);
		putchar('\n');
	}

	puts("====> The following tests must fail. <====");
	printf("Running %s().\n", "test_invalid");
	for (const struct bytes *test = &invalid[0];
	     test->bytes != NULL; test++)
	{
		fstrm_res res;
		res = decode_control_frame(c, test->bytes, test->len, 0);
		assert(res != fstrm_res_success);
	}

	fstrm_control_destroy(&c);
}

/* ---------------------------------------------------- file round trip */

static void
run_file_round_trip(void)
{
	const char *path = WORK "/hello.fs";
	struct fstrm_file_options *fopt;
	struct fstrm_writer_options *wopt;
	struct fstrm_reader_options *ropt;
	struct fstrm_writer *w = NULL;
	struct fstrm_reader *r = NULL;
	fstrm_res res;
	unsigned char buf[256];

	puts("== file writer/reader round trip ==");

	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, path);

	wopt = fstrm_writer_options_init();
	res = fstrm_writer_options_add_content_type(wopt, "test:hello", 10);
	print_res("writer_options_add_content_type(test:hello)", res);
	res = fstrm_writer_options_add_content_type(wopt, (const void *) "x", 257);
	print_res("writer_options_add_content_type(257 bytes)", res);

	w = fstrm_file_writer_init(fopt, wopt);
	printf("  file_writer_init -> %s\n", w ? "non-NULL" : "NULL");
	assert(w != NULL);
	res = fstrm_writer_open(w);
	print_res("writer_open", res);
	res = fstrm_writer_open(w);
	print_res("writer_open (double)", res);
	for (int i = 0; i < 32; i++) {
		sprintf((char *) buf, "Hello world #%d", i);
		res = fstrm_writer_write(w, buf, strlen((char *) buf) + 1);
		assert(res == fstrm_res_success);
	}
	res = fstrm_writer_close(w);
	print_res("writer_close", res);
	res = fstrm_writer_close(w);
	print_res("writer_close (again)", res);
	res = fstrm_writer_destroy(&w);
	print_res("writer_destroy", res);
	fstrm_writer_options_destroy(&wopt);
	fstrm_writer_options_destroy(&wopt); /* NULL-safe */
	fstrm_file_options_destroy(&fopt);

	/* Byte-exact dump of the file. */
	FILE *f = fopen(path, "rb");
	assert(f != NULL);
	struct stat stb;
	assert(stat(path, &stb) == 0);
	size_t n = (size_t) stb.st_size;
	unsigned char *fb = malloc(n ? n : 1);
	assert(fb != NULL);
	assert(fread(fb, 1, n, f) == n || n == 0);
	fclose(f);
	printf("  file size %zu\n  file bytes ", n);
	dump(fb, n);
	putchar('\n');
	free(fb);

	/* Read it back. */
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, path);
	ropt = fstrm_reader_options_init();
	res = fstrm_reader_options_add_content_type(ropt, "test:hello", 10);
	print_res("reader_options_add_content_type(test:hello)", res);
	r = fstrm_file_reader_init(fopt, ropt);
	printf("  file_reader_init -> %s\n", r ? "non-NULL" : "NULL");
	assert(r != NULL);
	res = fstrm_reader_open(r);
	print_res("reader_open", res);
	res = fstrm_reader_open(r);
	print_res("reader_open (double)", res);
	for (int i = 0; i < 32; i++) {
		const uint8_t *data;
		size_t len_data;
		res = fstrm_reader_read(r, &data, &len_data);
		sprintf((char *) buf, "Hello world #%d", i);
		printf("  read #%d -> %d (%s), %zu bytes: ",
		       i, (int) res, res_str(res), len_data);
		print_string(data, len_data);
		putchar('\n');
		assert(res == fstrm_res_success);
		assert(len_data == strlen((char *) buf) + 1);
		assert(memcmp(buf, data, len_data) == 0);
	}
	const uint8_t *data;
	size_t len_data = 0;
	res = fstrm_reader_read(r, &data, &len_data);
	print_res("reader_read past end", res);
	res = fstrm_reader_read(r, &data, &len_data);
	print_res("reader_read (closing state)", res);
	res = fstrm_reader_close(r);
	print_res("reader_close", res);
	res = fstrm_reader_close(r);
	print_res("reader_close (again)", res);
	/* get_control on the reader. */
	const struct fstrm_control *c = NULL;
	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &c);
	printf("  reader_get_control(START) -> %d (%s), control %s\n",
	       (int) res, res_str(res), c ? "non-NULL" : "NULL");
	if (c != NULL) {
		size_t n_ctype;
		fstrm_control_type ty;
		fstrm_control_get_type(c, &ty);
		fstrm_control_get_num_field_content_type(c, &n_ctype);
		printf("    type %s n_ctype %zu\n", fstrm_control_type_to_str(ty), n_ctype);
		for (size_t idx = 0; idx < n_ctype; idx++) {
			const uint8_t *ct;
			size_t len_ct;
			fstrm_control_get_field_content_type(c, idx, &ct, &len_ct);
			printf("    ct[%zu] ", idx);
			print_string(ct, len_ct);
			putchar('\n');
		}
	}
	res = fstrm_reader_get_control(r, FSTRM_CONTROL_FINISH, &c);
	print_res("reader_get_control(FINISH)", res);
	res = fstrm_reader_destroy(&r);
	print_res("reader_destroy", res);
	fstrm_reader_options_destroy(&ropt);
	fstrm_file_options_destroy(&fopt);
}

/* --------------------------------------------------- reader limits */

static void
run_reader_limits(void)
{
	const char *path = WORK "/big.fs";
	struct fstrm_file_options *fopt;
	struct fstrm_writer_options *wopt;
	struct fstrm_reader_options *ropt;
	struct fstrm_writer *w;
	struct fstrm_reader *r;
	fstrm_res res;
	unsigned char big[600];

	puts("== reader limits ==");

	ropt = fstrm_reader_options_init();
	res = fstrm_reader_options_set_max_frame_size(ropt, 511);
	print_res("set_max_frame_size(511)", res);
	res = fstrm_reader_options_set_max_frame_size(ropt, 512);
	print_res("set_max_frame_size(512)", res);
	res = fstrm_reader_options_set_max_frame_size(ropt, (size_t) UINT32_MAX - 1);
	print_res("set_max_frame_size(UINT32_MAX-1)", res);
	res = fstrm_reader_options_set_max_frame_size(ropt, (size_t) UINT32_MAX);
	print_res("set_max_frame_size(UINT32_MAX)", res);
	fstrm_reader_options_destroy(&ropt);

	/* Write a file containing a 600-byte frame. */
	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, path);
	memset(big, 'z', sizeof(big));
	wopt = fstrm_writer_options_init();
	fstrm_writer_options_add_content_type(wopt, "test:hello", 10);
	w = fstrm_file_writer_init(fopt, wopt);
	assert(w != NULL);
	res = fstrm_writer_open(w);
	assert(res == fstrm_res_success);
	res = fstrm_writer_write(w, big, sizeof(big));
	assert(res == fstrm_res_success);
	res = fstrm_writer_close(w);
	assert(res == fstrm_res_success);
	fstrm_writer_destroy(&w);
	fstrm_writer_options_destroy(&wopt);

	/* A 512-byte max rejects the 600-byte frame. */
	ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt, "test:hello", 10);
	fstrm_reader_options_set_max_frame_size(ropt, 512);
	r = fstrm_file_reader_init(fopt, ropt);
	assert(r != NULL);
	res = fstrm_reader_open(r);
	print_res("reader open (max 512)", res);
	{
		const uint8_t *data;
		size_t len_data;
		res = fstrm_reader_read(r, &data, &len_data);
		print_res("reader read 600-byte frame (max 512)", res);
	}
	res = fstrm_reader_close(r);
	print_res("reader close after failure", res);
	fstrm_reader_destroy(&r);
	fstrm_reader_options_destroy(&ropt);

	/* The default (1048576) accepts it. */
	ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt, "test:hello", 10);
	r = fstrm_file_reader_init(fopt, ropt);
	assert(r != NULL);
	res = fstrm_reader_open(r);
	print_res("reader open (default max)", res);
	{
		const uint8_t *data;
		size_t len_data;
		res = fstrm_reader_read(r, &data, &len_data);
		printf("  reader read 600-byte frame (default max) -> %d (%s), %zu bytes\n",
		       (int) res, res_str(res), len_data);
		assert(res == fstrm_res_success && len_data == 600);
	}
	fstrm_reader_destroy(&r);
	fstrm_reader_options_destroy(&ropt);

	/* Content-type mismatch: the file says test:hello. */
	ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt, "test:other", 10);
	r = fstrm_file_reader_init(fopt, ropt);
	assert(r != NULL);
	res = fstrm_reader_open(r);
	print_res("reader open (content-type mismatch)", res);
	fstrm_reader_destroy(&r);
	fstrm_reader_options_destroy(&ropt);

	/* No configured content types: accept anything. */
	ropt = fstrm_reader_options_init();
	r = fstrm_file_reader_init(fopt, ropt);
	assert(r != NULL);
	res = fstrm_reader_open(r);
	print_res("reader open (no content types configured)", res);
	{
		const uint8_t *data;
		size_t len_data;
		res = fstrm_reader_read(r, &data, &len_data);
		printf("  reader read (no content types) -> %d (%s), %zu bytes\n",
		       (int) res, res_str(res), len_data);
		assert(res == fstrm_res_success && len_data == 600);
	}
	fstrm_reader_destroy(&r);
	fstrm_reader_options_destroy(&ropt);

	fstrm_file_options_destroy(&fopt);
}

/* --------------------------------------------------- writer errors */

static void
run_writer_errors(void)
{
	const char *path = WORK "/err.fs";
	struct fstrm_file_options *fopt;
	struct fstrm_writer *w;
	fstrm_res res;

	puts("== writer errors ==");

	/* A writer over an rdwr with no write method is NULL. */
	{
		struct fstrm_rdwr *rdwr = fstrm_rdwr_init(NULL);
		w = fstrm_writer_init(NULL, &rdwr);
		printf("  writer_init (no write method) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w == NULL);
		fstrm_rdwr_destroy(&rdwr);
	}

	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, path);
	w = fstrm_file_writer_init(fopt, NULL);
	assert(w != NULL);
	res = fstrm_writer_close(w);
	print_res("writer_close before open", res);
	res = fstrm_writer_writev(w, NULL, 0);
	print_res("writer_writev(iovcnt=0)", res);
	res = fstrm_writer_open(w);
	print_res("writer_open", res);
	res = fstrm_writer_write(w, "data", 4);
	print_res("writer_write", res);
	res = fstrm_writer_close(w);
	print_res("writer_close", res);
	res = fstrm_writer_write(w, "late", 4);
	print_res("writer_write after close", res);
	{
		struct fstrm_control *c = NULL;
		res = fstrm_writer_get_control(w, FSTRM_CONTROL_STOP, &c);
		print_res("writer_get_control(STOP)", res);
	}
	{
		struct fstrm_control *c = (struct fstrm_control *) 1;
		res = fstrm_writer_get_control(w, FSTRM_CONTROL_READY, &c);
		printf("  writer_get_control(READY) -> %d (%s), control %s\n",
		       (int) res, res_str(res), c ? "non-NULL" : "NULL");
	}
	fstrm_writer_destroy(&w);
	fstrm_file_options_destroy(&fopt);
}

/* --------------------------------------------------- writev chunked */

static void
run_writev_chunked(void)
{
	const char *path = WORK "/chunked.fs";
	struct fstrm_file_options *fopt;
	struct fstrm_writer_options *wopt;
	struct fstrm_reader_options *ropt;
	struct fstrm_writer *w;
	struct fstrm_reader *r;
	fstrm_res res;
	struct iovec iov[200];
	unsigned char frames[200][5];

	puts("== writev chunked ==");

	fopt = fstrm_file_options_init();
	fstrm_file_options_set_file_path(fopt, path);
	wopt = fstrm_writer_options_init();
	fstrm_writer_options_add_content_type(wopt, "test:hello", 10);
	w = fstrm_file_writer_init(fopt, wopt);
	assert(w != NULL);
	res = fstrm_writer_open(w);
	assert(res == fstrm_res_success);
	for (int i = 0; i < 200; i++) {
		sprintf((char *) frames[i], "m%03d", i);
		iov[i].iov_base = frames[i];
		iov[i].iov_len = 4;
	}
	res = fstrm_writer_writev(w, iov, 200);
	print_res("writer_writev(200 frames)", res);
	res = fstrm_writer_close(w);
	assert(res == fstrm_res_success);
	fstrm_writer_destroy(&w);
	fstrm_writer_options_destroy(&wopt);

	ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt, "test:hello", 10);
	r = fstrm_file_reader_init(fopt, ropt);
	assert(r != NULL);
	res = fstrm_reader_open(r);
	assert(res == fstrm_res_success);
	{
		const uint8_t *data;
		size_t len_data;
		for (int i = 0; i < 200; i++) {
			res = fstrm_reader_read(r, &data, &len_data);
			printf("  read #%d -> %d (%s), %zu bytes: ",
			       i, (int) res, res_str(res), len_data);
			print_string(data, len_data);
			putchar('\n');
			assert(res == fstrm_res_success);
			assert(len_data == 4 && memcmp(data, frames[i], 4) == 0);
		}
		res = fstrm_reader_read(r, &data, &len_data);
		print_res("reader_read past end", res);
	}
	fstrm_reader_destroy(&r);
	fstrm_reader_options_destroy(&ropt);
	fstrm_file_options_destroy(&fopt);
}

/* --------------------------------------------------- unix/tcp init validation */

static void
run_transport_init_validation(void)
{
	puts("== unix writer init validation ==");
	{
		struct fstrm_unix_writer_options *uwopt = fstrm_unix_writer_options_init();
		struct fstrm_writer *w;

		w = fstrm_unix_writer_init(uwopt, NULL);
		printf("  unix_writer_init(NULL path) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w == NULL);

		char longpath[109];
		memset(longpath, 'x', sizeof(longpath) - 1);
		longpath[108] = '\0';
		fstrm_unix_writer_options_set_socket_path(uwopt, longpath);
		w = fstrm_unix_writer_init(uwopt, NULL);
		printf("  unix_writer_init(108-char path) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w == NULL);

		char fitpath[108];
		memset(fitpath, 'x', sizeof(fitpath) - 1);
		fitpath[107] = '\0';
		fstrm_unix_writer_options_set_socket_path(uwopt, fitpath);
		w = fstrm_unix_writer_init(uwopt, NULL);
		printf("  unix_writer_init(107-char path) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w != NULL);
		fstrm_writer_destroy(&w);

		fstrm_unix_writer_options_destroy(&uwopt);
	}

	puts("== tcp writer init validation ==");
	{
		struct fstrm_tcp_writer_options *twopt = fstrm_tcp_writer_options_init();
		struct fstrm_writer *w;

		w = fstrm_tcp_writer_init(twopt, NULL);
		printf("  tcp_writer_init(no addr/port) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w == NULL);

		fstrm_tcp_writer_options_set_socket_address(twopt, "127.0.0.1");
		w = fstrm_tcp_writer_init(twopt, NULL);
		printf("  tcp_writer_init(addr, no port) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w == NULL);

		fstrm_tcp_writer_options_set_socket_port(twopt, "8080");
		w = fstrm_tcp_writer_init(twopt, NULL);
		printf("  tcp_writer_init(127.0.0.1, 8080) -> %s\n", w ? "non-NULL" : "NULL");
		assert(w != NULL);
		fstrm_writer_destroy(&w);

		static const struct {
			const char *addr;
			const char *port;
		} cases[] = {
			{ "127.0.0.1", "8080" },
			{ "::1", "8080" },
			{ "1.2.3.999", "8080" },
			{ "notanaddress", "8080" },
			{ "010.0.0.1", "8080" },
			{ "127.0.0.1:8080", "8080" },
			{ "127.0.0.1", "65535" },
			{ "127.0.0.1", "65536" },
			{ "127.0.0.1", "8080junk" },
			{ "127.0.0.1", "-1" },
			{ "127.0.0.1", "" },
			{ "127.0.0.1", "0x1F90" },
			{ "127.0.0.1", " 8080" },
			{ "127.0.0.1", "010" },
			{ "127.0.0.1", "+8080" },
		};
		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			fstrm_tcp_writer_options_set_socket_address(twopt, cases[i].addr);
			fstrm_tcp_writer_options_set_socket_port(twopt, cases[i].port);
			w = fstrm_tcp_writer_init(twopt, NULL);
			printf("  tcp_writer_init(\"%s\", \"%s\") -> %s\n",
			       cases[i].addr, cases[i].port, w ? "non-NULL" : "NULL");
			if (w != NULL)
				fstrm_writer_destroy(&w);
		}
		fstrm_tcp_writer_options_destroy(&twopt);
	}
}

/* --------------------------------------------------- socket interop */

struct consumer_args {
	int			server_fd;
	const char		*transcript;
};

static fstrm_res
sock_open(void *obj)
{
	(void) obj;
	return fstrm_res_success;
}

static fstrm_res
sock_close(void *obj)
{
	int fd = *(int *) obj;
	if (close(fd) != 0)
		return fstrm_res_failure;
	return fstrm_res_success;
}

static fstrm_res
sock_read(void *obj, void *data, size_t count)
{
	int fd = *(int *) obj;
	size_t got = 0;
	while (got < count) {
		ssize_t n = read(fd, (uint8_t *) data + got, count - got);
		if (n == -1 && errno == EINTR)
			continue;
		if (n <= 0)
			return fstrm_res_failure;
		got += (size_t) n;
	}
	return fstrm_res_success;
}

static fstrm_res
sock_write(void *obj, const struct iovec *iov, int iovcnt)
{
	int fd = *(int *) obj;
	for (int i = 0; i < iovcnt; i++) {
		const uint8_t *p = iov[i].iov_base;
		size_t len = iov[i].iov_len;
		while (len > 0) {
			ssize_t n = write(fd, p, len);
			if (n == -1 && errno == EINTR)
				continue;
			if (n <= 0)
				return fstrm_res_failure;
			p += n;
			len -= (size_t) n;
		}
	}
	return fstrm_res_success;
}

/* Emit a print_string-format line into the transcript file. */
static void
fprint_string(FILE *out, const uint8_t *data, size_t len)
{
	fputc('"', out);
	while (len-- != 0) {
		unsigned c = *(data++);
		if (c >= 0x20 && c <= 0x7e) {
			if (c == '"')
				fputs("\\\"", out);
			else
				fputc(c, out);
		} else {
			fprintf(out, "\\x%02x", c);
		}
	}
	fputc('"', out);
}

/* The consumer: fstrm_reader over the accepted socket fd. */
static void *
consumer_main(void *arg)
{
	struct consumer_args *ca = arg;
	int client_fd;
	FILE *out;

	client_fd = accept(ca->server_fd, NULL, NULL);
	assert(client_fd != -1);
	close(ca->server_fd);

	out = fopen(ca->transcript, "w");
	assert(out != NULL);

	fprintf(out, "accepted a connection\n");

	struct fstrm_rdwr *rdwr = fstrm_rdwr_init(&client_fd);
	fstrm_rdwr_set_destroy(rdwr, NULL);
	fstrm_rdwr_set_open(rdwr, sock_open);
	fstrm_rdwr_set_close(rdwr, sock_close);
	fstrm_rdwr_set_read(rdwr, sock_read);
	fstrm_rdwr_set_write(rdwr, sock_write);

	struct fstrm_reader_options *ropt = fstrm_reader_options_init();
	fstrm_reader_options_add_content_type(ropt, "test:hello", 10);
	struct fstrm_reader *r = fstrm_reader_init(ropt, &rdwr);
	assert(r != NULL);
	fstrm_reader_options_destroy(&ropt);

	fstrm_res res = fstrm_reader_open(r);
	fprintf(out, "reader open -> %d (%s)\n", (int) res, res_str(res));
	assert(res == fstrm_res_success);

	const struct fstrm_control *c = NULL;
	fstrm_control_type ty;
	size_t n_ctype;

	res = fstrm_reader_get_control(r, FSTRM_CONTROL_READY, &c);
	assert(res == fstrm_res_success && c != NULL);
	fstrm_control_get_type(c, &ty);
	fstrm_control_get_num_field_content_type(c, &n_ctype);
	fprintf(out, "ready: type %s n_ctype %zu\n", fstrm_control_type_to_str(ty), n_ctype);
	for (size_t idx = 0; idx < n_ctype; idx++) {
		const uint8_t *ct;
		size_t len_ct;
		fstrm_control_get_field_content_type(c, idx, &ct, &len_ct);
		fprintf(out, "  ready ct[%zu] ", idx);
		fprint_string(out, ct, len_ct);
		fputc('\n', out);
	}

	res = fstrm_reader_get_control(r, FSTRM_CONTROL_START, &c);
	assert(res == fstrm_res_success && c != NULL);
	fstrm_control_get_type(c, &ty);
	fstrm_control_get_num_field_content_type(c, &n_ctype);
	fprintf(out, "start: type %s n_ctype %zu\n", fstrm_control_type_to_str(ty), n_ctype);
	for (size_t idx = 0; idx < n_ctype; idx++) {
		const uint8_t *ct;
		size_t len_ct;
		fstrm_control_get_field_content_type(c, idx, &ct, &len_ct);
		fprintf(out, "  start ct[%zu] ", idx);
		fprint_string(out, ct, len_ct);
		fputc('\n', out);
	}

	int idx = 0;
	for (;;) {
		const uint8_t *data;
		size_t len_data;
		res = fstrm_reader_read(r, &data, &len_data);
		if (res == fstrm_res_stop) {
			fprintf(out, "read -> stop\n");
			break;
		}
		assert(res == fstrm_res_success);
		fprintf(out, "frame %d: %zu bytes ", idx++, len_data);
		fprint_string(out, data, len_data);
		fputc('\n', out);
	}

	res = fstrm_reader_close(r);
	fprintf(out, "reader close -> %d (%s)\n", (int) res, res_str(res));
	fstrm_reader_destroy(&r);
	fclose(out);
	return NULL;
}

static void
run_socket_interop(const char *kind, const char *socket_path,
		   const char *tcp_address, const char *transcript)
{
	struct consumer_args ca;
	pthread_t thr;
	struct fstrm_writer *w = NULL;
	struct fstrm_iothr *iothr;
	struct fstrm_iothr_options *iopt;
	struct fstrm_iothr_queue *ioq;
	fstrm_res res;

	if (kind[0] == 'u') {
		struct sockaddr_un sa;
		unlink(socket_path);
		ca.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		assert(ca.server_fd != -1);
		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strncpy(sa.sun_path, socket_path, sizeof(sa.sun_path) - 1);
		assert(bind(ca.server_fd, (struct sockaddr *) &sa, sizeof(sa)) == 0);
		assert(listen(ca.server_fd, 1) == 0);

		struct fstrm_unix_writer_options *uwopt = fstrm_unix_writer_options_init();
		fstrm_unix_writer_options_set_socket_path(uwopt, socket_path);
		struct fstrm_writer_options *wopt = fstrm_writer_options_init();
		fstrm_writer_options_add_content_type(wopt, "test:hello", 10);
		w = fstrm_unix_writer_init(uwopt, wopt);
		assert(w != NULL);
		fstrm_unix_writer_options_destroy(&uwopt);
		fstrm_writer_options_destroy(&wopt);
	} else {
		struct sockaddr_in sin;
		uint16_t port;
		char s_port[16];
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = 0;
		ca.server_fd = socket(AF_INET, SOCK_STREAM, 0);
		assert(ca.server_fd != -1);
		assert(bind(ca.server_fd, (struct sockaddr *) &sin, sizeof(sin)) == 0);
		assert(listen(ca.server_fd, 1) == 0);
		socklen_t slen = sizeof(sin);
		assert(getsockname(ca.server_fd, (struct sockaddr *) &sin, &slen) == 0);
		port = ntohs(sin.sin_port);
		snprintf(s_port, sizeof(s_port), "%u", port);

		struct fstrm_tcp_writer_options *twopt = fstrm_tcp_writer_options_init();
		fstrm_tcp_writer_options_set_socket_address(twopt, tcp_address);
		fstrm_tcp_writer_options_set_socket_port(twopt, s_port);
		struct fstrm_writer_options *wopt = fstrm_writer_options_init();
		fstrm_writer_options_add_content_type(wopt, "test:hello", 10);
		w = fstrm_tcp_writer_init(twopt, wopt);
		assert(w != NULL);
		fstrm_tcp_writer_options_destroy(&twopt);
		fstrm_writer_options_destroy(&wopt);
	}

	ca.transcript = transcript;
	assert(pthread_create(&thr, NULL, consumer_main, &ca) == 0);

	iopt = fstrm_iothr_options_init();
	iothr = fstrm_iothr_init(iopt, &w);
	assert(iothr != NULL);
	fstrm_iothr_options_destroy(&iopt);
	assert(w == NULL);

	ioq = fstrm_iothr_get_input_queue(iothr);
	assert(ioq != NULL);

	for (int i = 0; i < 8; i++) {
		char msg[16];
		sprintf(msg, "msg-%04d", i);
		for (;;) {
			res = fstrm_iothr_submit(iothr, ioq, strdup(msg), strlen(msg),
						 fstrm_free_wrapper, NULL);
			if (res == fstrm_res_success)
				break;
			assert(res == fstrm_res_again);
			poll(NULL, 0, 1);
		}
	}

	fstrm_iothr_destroy(&iothr);
	assert(pthread_join(thr, NULL) == 0);

	/* Print the consumer's transcript. */
	FILE *f = fopen(transcript, "r");
	assert(f != NULL);
	char line[512];
	while (fgets(line, sizeof(line), f) != NULL)
		fputs(line, stdout);
	fclose(f);
}

/* --------------------------------------------------- iothr surface */

static unsigned long iothr_freed;

static void
counting_free(void *data, void *free_data)
{
	(void) free_data;
	free(data);
	iothr_freed++;
}

static void
run_iothr_surface(void)
{
	struct fstrm_iothr_options *opt;
	fstrm_res res;

	puts("== iothr options ==");
	opt = fstrm_iothr_options_init();
	res = fstrm_iothr_options_set_buffer_hint(opt, 1023);
	print_res("set_buffer_hint(1023)", res);
	res = fstrm_iothr_options_set_buffer_hint(opt, 1024);
	print_res("set_buffer_hint(1024)", res);
	res = fstrm_iothr_options_set_buffer_hint(opt, 8192);
	print_res("set_buffer_hint(8192)", res);
	res = fstrm_iothr_options_set_buffer_hint(opt, 65536);
	print_res("set_buffer_hint(65536)", res);
	res = fstrm_iothr_options_set_buffer_hint(opt, 65537);
	print_res("set_buffer_hint(65537)", res);
	res = fstrm_iothr_options_set_flush_timeout(opt, 0);
	print_res("set_flush_timeout(0)", res);
	res = fstrm_iothr_options_set_flush_timeout(opt, 1);
	print_res("set_flush_timeout(1)", res);
	res = fstrm_iothr_options_set_flush_timeout(opt, 600);
	print_res("set_flush_timeout(600)", res);
	res = fstrm_iothr_options_set_flush_timeout(opt, 601);
	print_res("set_flush_timeout(601)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 1);
	print_res("set_input_queue_size(1)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 2);
	print_res("set_input_queue_size(2)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 3);
	print_res("set_input_queue_size(3)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 4);
	print_res("set_input_queue_size(4)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 6);
	print_res("set_input_queue_size(6)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 16384);
	print_res("set_input_queue_size(16384)", res);
	res = fstrm_iothr_options_set_input_queue_size(opt, 16385);
	print_res("set_input_queue_size(16385)", res);
	res = fstrm_iothr_options_set_num_input_queues(opt, 0);
	print_res("set_num_input_queues(0)", res);
	res = fstrm_iothr_options_set_num_input_queues(opt, 1);
	print_res("set_num_input_queues(1)", res);
	res = fstrm_iothr_options_set_num_input_queues(opt, 4);
	print_res("set_num_input_queues(4)", res);
	res = fstrm_iothr_options_set_output_queue_size(opt, 1);
	print_res("set_output_queue_size(1)", res);
	res = fstrm_iothr_options_set_output_queue_size(opt, 2);
	print_res("set_output_queue_size(2)", res);
	res = fstrm_iothr_options_set_output_queue_size(opt, 1024);
	print_res("set_output_queue_size(1024)", res);
	res = fstrm_iothr_options_set_output_queue_size(opt, 1025);
	print_res("set_output_queue_size(1025)", res);
	res = fstrm_iothr_options_set_queue_model(opt, FSTRM_IOTHR_QUEUE_MODEL_SPSC);
	print_res("set_queue_model(SPSC)", res);
	res = fstrm_iothr_options_set_queue_model(opt, FSTRM_IOTHR_QUEUE_MODEL_MPSC);
	print_res("set_queue_model(MPSC)", res);
	res = fstrm_iothr_options_set_queue_model(opt, (fstrm_iothr_queue_model) 2);
	print_res("set_queue_model(2)", res);
	res = fstrm_iothr_options_set_queue_notify_threshold(opt, 0);
	print_res("set_queue_notify_threshold(0)", res);
	res = fstrm_iothr_options_set_queue_notify_threshold(opt, 1);
	print_res("set_queue_notify_threshold(1)", res);
	res = fstrm_iothr_options_set_reopen_interval(opt, 0);
	print_res("set_reopen_interval(0)", res);
	res = fstrm_iothr_options_set_reopen_interval(opt, 1);
	print_res("set_reopen_interval(1)", res);
	res = fstrm_iothr_options_set_reopen_interval(opt, 600);
	print_res("set_reopen_interval(600)", res);
	res = fstrm_iothr_options_set_reopen_interval(opt, 601);
	print_res("set_reopen_interval(601)", res);
	fstrm_iothr_options_destroy(&opt);
	fstrm_iothr_options_destroy(&opt); /* NULL-safe */

	puts("== iothr init + submit ==");
	{
		const char *path = WORK "/iothr.fs";
		struct fstrm_file_options *fopt = fstrm_file_options_init();
		fstrm_file_options_set_file_path(fopt, path);
		struct fstrm_writer *w = fstrm_file_writer_init(fopt, NULL);
		assert(w != NULL);
		struct fstrm_iothr *iothr;
		struct fstrm_iothr_queue *ioq;

		/* A power-of-2 input queue size inits cleanly.  (The non-power-of-2
		 * path is excluded from the corpus: fstrm 0.6.1's iothr_init
		 * goto-fail path joins an uninitialized thread/condvar and
		 * segfaults — see FSTRM-LORE.) */
		struct fstrm_iothr_options *o2 = fstrm_iothr_options_init();
		fstrm_iothr_options_set_input_queue_size(o2, 8);
		iothr = fstrm_iothr_init(o2, &w);
		printf("  iothr_init(input_queue_size=8) -> %s\n", iothr ? "non-NULL" : "NULL");
		assert(iothr != NULL);
		fstrm_iothr_options_destroy(&o2);

		ioq = fstrm_iothr_get_input_queue(iothr);
		printf("  get_input_queue #1 -> %s\n", ioq ? "non-NULL" : "NULL");
		ioq = fstrm_iothr_get_input_queue(iothr);
		printf("  get_input_queue #2 (beyond num_input_queues) -> %s\n",
		       ioq ? "non-NULL" : "NULL");
		assert(ioq == NULL);
		ioq = fstrm_iothr_get_input_queue_idx(iothr, 0);
		printf("  get_input_queue_idx(0) -> %s\n", ioq ? "non-NULL" : "NULL");
		ioq = fstrm_iothr_get_input_queue_idx(iothr, 1);
		printf("  get_input_queue_idx(1) -> %s\n", ioq ? "non-NULL" : "NULL");
		assert(ioq == NULL);
		/* The handles from get_input_queue are one-shot (one per
		 * num_input_queues); index the array directly for the submits. */
		ioq = fstrm_iothr_get_input_queue_idx(iothr, 0);
		assert(ioq != NULL);

		res = fstrm_iothr_submit(iothr, ioq, NULL, 0, NULL, NULL);
		print_res("submit(len=0)", res);
		res = fstrm_iothr_submit(iothr, ioq, NULL, 0, NULL, NULL);
		print_res("submit(empty, len=0)", res);

		for (int i = 0; i < 16; i++) {
			char msg[32];
			sprintf(msg, "hello world #%d", i);
			for (;;) {
				res = fstrm_iothr_submit(iothr, ioq, strdup(msg), strlen(msg),
							 fstrm_free_wrapper, NULL);
				if (res == fstrm_res_success)
					break;
				assert(res == fstrm_res_again);
				poll(NULL, 0, 1);
			}
			printf("  submit #%d -> 0 (success)\n", i);
		}

		fstrm_iothr_destroy(&iothr);

		FILE *f = fopen(path, "rb");
		assert(f != NULL);
		struct stat stb;
		assert(stat(path, &stb) == 0);
		size_t n = (size_t) stb.st_size;
		unsigned char *fb = malloc(n ? n : 1);
		assert(fb != NULL);
		assert(fread(fb, 1, n, f) == n || n == 0);
		fclose(f);
		printf("  iothr file size %zu\n  iothr file bytes ", n);
		dump(fb, n);
		putchar('\n');
		free(fb);
		fstrm_file_options_destroy(&fopt);
	}

	puts("== iothr discard on unopenable writer ==");
	{
		struct fstrm_unix_writer_options *uwopt = fstrm_unix_writer_options_init();
		fstrm_unix_writer_options_set_socket_path(uwopt, WORK "/none.sock");
		struct fstrm_writer *w = fstrm_unix_writer_init(uwopt, NULL);
		assert(w != NULL);
		fstrm_unix_writer_options_destroy(&uwopt);

		struct fstrm_iothr *iothr = fstrm_iothr_init(NULL, &w);
		assert(iothr != NULL);
		struct fstrm_iothr_queue *ioq = fstrm_iothr_get_input_queue(iothr);
		assert(ioq != NULL);
		iothr_freed = 0;
		for (int i = 0; i < 4; i++) {
			char msg[16];
			sprintf(msg, "drop-%d", i);
			res = fstrm_iothr_submit(iothr, ioq, strdup(msg), strlen(msg),
						 counting_free, NULL);
			assert(res == fstrm_res_success);
		}
		fstrm_iothr_destroy(&iothr);
		printf("  freed %lu frames (discarded on shutdown)\n", iothr_freed);
		assert(iothr_freed == 4);
	}
}

/* ------------------------------------------------------------------ main */

int
main(void)
{
	mkwork();

	puts("== control types ==");
	printf("  type 0x%08x %s\n", 0x01, fstrm_control_type_to_str(FSTRM_CONTROL_ACCEPT));
	printf("  type 0x%08x %s\n", 0x02, fstrm_control_type_to_str(FSTRM_CONTROL_START));
	printf("  type 0x%08x %s\n", 0x03, fstrm_control_type_to_str(FSTRM_CONTROL_STOP));
	printf("  type 0x%08x %s\n", 0x04, fstrm_control_type_to_str(FSTRM_CONTROL_READY));
	printf("  type 0x%08x %s\n", 0x05, fstrm_control_type_to_str(FSTRM_CONTROL_FINISH));
	printf("  type 0x%08x %s\n", 0xff, fstrm_control_type_to_str((fstrm_control_type) 0xff));
	printf("  field 0x%08x %s\n", 0x01,
	       fstrm_control_field_type_to_str(FSTRM_CONTROL_FIELD_CONTENT_TYPE));
	printf("  field 0x%08x %s\n", 0xff,
	       fstrm_control_field_type_to_str((fstrm_control_field) 0xff));

	puts("== control corpus ==");
	run_control_corpus();

	run_file_round_trip();
	run_reader_limits();
	run_writer_errors();
	run_writev_chunked();
	run_transport_init_validation();

	puts("== unix socket interop ==");
	run_socket_interop("unix", WORK "/test.sock", NULL, WORK "/consumer.unix.txt");
	puts("== tcp socket interop ==");
	run_socket_interop("tcp", NULL, "127.0.0.1", WORK "/consumer.tcp.txt");

	run_iothr_surface();

	return EXIT_SUCCESS;
}

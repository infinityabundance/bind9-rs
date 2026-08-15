/*
 * probe_name_wire.c — oracle probe for dns_name_fromwire semantics.
 *
 * Reads one test case per stdin line: "<hex-wire> <offset>".  Parses a
 * (possibly compressed) name at the given offset with compression permitted
 * (DNS_DECOMPRESS_ANY), then emits:
 *
 *   OK <formatted> <consumed-hexoffset>
 *   ERR <result-code>
 *
 * The formatted form is dns_name_totext output.  Oracle-side tooling only.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/result.h>

static int
hexval(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

int
main(int argc, char **argv) {
	char line[8192];
	unsigned char wire[65536];
	isc_mem_t *mctx = NULL;
	isc_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name;
	isc_buffer_t source;
	char text[DNS_NAME_MAXTEXT + 1];

	UNUSED(argc);
	UNUSED(argv);

	isc_mem_create(&mctx);
	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char *space;
		unsigned int offset = 0;
		size_t len;
		unsigned int wlen = 0;
		int i;

		len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0) {
			continue;
		}
		space = strchr(line, ' ');
		if (space != NULL) {
			*space = '\0';
			offset = (unsigned int)strtoul(space + 1, NULL, 10);
		}
		for (i = 0; line[i] != '\0'; i += 2) {
			int hi = hexval(line[i]);
			int lo = hexval(line[i + 1]);
			if (hi < 0 || lo < 0 || line[i + 1] == '\0') {
				break;
			}
			wire[wlen++] = (unsigned char)((hi << 4) | lo);
		}
		if (wlen == 0 && offset == 0) {
			printf("ERR bad input\n");
			continue;
		}

		isc_buffer_init(&source, wire, wlen);
		isc_buffer_add(&source, wlen);
		isc_buffer_setactive(&source, wlen);
		isc_buffer_first(&source);
		/* isc_buffer_forward asserts the offset is within the buffer;
		 * offsets at or beyond the end must still yield a parse result
		 * (ISC_R_UNEXPECTEDEND), not an abort, and must not silently parse
		 * from position 0.  The isc_buffer_t struct is public, so set the
		 * cursor directly. */
		if (offset < wlen) {
			isc_buffer_forward(&source, offset);
		} else {
			source.current = wlen;
		}

		dns_name_reset(name);
		result = dns_name_fromwire(name, &source, DNS_DECOMPRESS_ALWAYS,
					  NULL);
		if (result != ISC_R_SUCCESS) {
			printf("ERR %s\n", isc_result_totext(result));
			continue;
		}

		isc_buffer_init(&source, text, sizeof(text));
		result = dns_name_totext(name, false, &source);
		if (result != ISC_R_SUCCESS) {
			printf("TOTEXT-ERR %s\n", isc_result_totext(result));
			continue;
		}
		text[isc_buffer_usedlength(&source)] = '\0';

		printf("OK %s\n", text);
	}

	isc_mem_destroy(&mctx);
	return 0;
}

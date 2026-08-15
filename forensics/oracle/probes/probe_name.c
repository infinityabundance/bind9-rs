/*
 * probe_name.c — oracle probe for dns_name_* semantics (bind9-rs courts).
 *
 * Reads one test case per line from stdin.  Each line is a raw name in
 * masterfile text form.  Writes one result line per input to stdout:
 *
 *   OK <formatted> <wire-hex> <countlabels> <length>
 *   ERR <result-code>
 *
 * formatted = dns_name_format() output; wire-hex = uncompressed wire bytes
 * in lowercase hex; countlabels/length = dns_name_countlabels()/
 * dns_name_length().  The origin is the root, so relative names become
 * absolute (the same behavior bind9-rs must reproduce).
 *
 * This probe links against the pinned BIND tree's libdns/libisc.  It exists
 * ONLY on the oracle side (spec §2).
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

static isc_mem_t *mctx = NULL;
static dns_compress_t cctx;

static void
emit_name(const dns_name_t *name) {
	char text[DNS_NAME_MAXTEXT + 1];
	unsigned char wire[DNS_NAME_MAXWIRE];
	isc_buffer_t tb;
	isc_buffer_t wb;
	isc_region_t r;
	char hex[DNS_NAME_MAXWIRE * 2 + 1];
	unsigned int i;
	isc_result_t result;

	isc_buffer_init(&tb, text, sizeof(text));
	result = dns_name_totext(name, false, &tb);
	if (result != ISC_R_SUCCESS) {
		printf("TOTEXT-ERR %s\n", isc_result_totext(result));
		return;
	}
	text[isc_buffer_usedlength(&tb)] = '\0';

	isc_buffer_init(&wb, wire, sizeof(wire));
	dns_compress_rollback(&cctx, 0);
	result = dns_name_towire(name, &cctx, &wb, NULL);
	if (result != ISC_R_SUCCESS) {
		printf("WIRE-ERR %s\n", isc_result_totext(result));
		return;
	}
	isc_buffer_usedregion(&wb, &r);
	for (i = 0; i < r.length; i++) {
		sprintf(hex + i * 2, "%02x", r.base[i]);
	}
	hex[r.length * 2] = '\0';

	printf("OK %s %s %u %u\n", text, hex, dns_name_countlabels(name),
	       name->length);
}

int
main(int argc, char **argv) {
	char line[4096];
	isc_result_t result;
	dns_fixedname_t fname;
	dns_name_t *name;
	dns_fixedname_t forigin;
	dns_name_t *origin;
	isc_buffer_t source;

	UNUSED(argc);
	UNUSED(argv);

	isc_mem_create(&mctx);
	dns_compress_init(&cctx, mctx, 0);
	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);

	/* Origin = root. */
	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	isc_buffer_init(&source, ".", 1);
	isc_buffer_add(&source, 1);
	result = dns_name_fromtext(origin, &source, NULL, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		fprintf(stderr, "cannot build root origin: %s\n",
			isc_result_totext(result));
		return 1;
	}

	while (fgets(line, sizeof(line), stdin) != NULL) {
		size_t len = strlen(line);
		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0) {
			continue;
		}
		isc_buffer_init(&source, line, (unsigned int)len);
		isc_buffer_add(&source, (unsigned int)len);

		dns_name_reset(name);
		result = dns_name_fromtext(name, &source, origin, 0, NULL);
		if (result != ISC_R_SUCCESS) {
			printf("ERR %s\n", isc_result_totext(result));
			continue;
		}
		emit_name(name);
	}

	isc_mem_destroy(&mctx);
	return 0;
}

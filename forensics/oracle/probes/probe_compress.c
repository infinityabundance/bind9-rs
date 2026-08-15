/*
 * probe_compress.c — oracle probe for dns_name_towire + dns_compress
 * semantics (byte-exact compression output).
 *
 * Reads one name (masterfile text, resolved against the root) per stdin
 * line.  Each name is rendered into a shared buffer with a persistent
 * compression context, exactly as a message renderer would; after each
 * name, the full buffer hex is printed:
 *
 *   <cumulative-hex>
 *
 * argv[1] selects the compression-context flags (comma-separated):
 *   disabled   DNS_COMPRESS_DISABLED — names are neither matched nor added
 *   case       DNS_COMPRESS_CASE — case-sensitive suffix matching (named's
 *              default for query responses unless the peer matches the
 *              view's nocasecompress ACL; lib/ns/client.c)
 *   large      DNS_COMPRESS_LARGE — 1024-slot table (AXFR/IXFR responses,
 *              lib/ns/xfrout.c; update requests, lib/dns/request.c)
 *   nopermit   dns_compress_setpermitted(false) after init — no pointers
 *              are emitted but names still populate the table (RFC 3597
 *              per-name control; lib/dns/name.c dns_name_towire)
 *
 * Oracle-side tooling only.
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
static unsigned char msg[65536];
static isc_buffer_t target;

static int
emit(const dns_name_t *name) {
	isc_region_t r;
	unsigned int i;
	isc_result_t result;

	result = dns_name_towire(name, &cctx, &target, NULL);
	if (result != ISC_R_SUCCESS) {
		printf("ERR %s\n", isc_result_totext(result));
		return -1;
	}
	isc_buffer_usedregion(&target, &r);
	for (i = 0; i < r.length; i++) {
		printf("%02x", r.base[i]);
	}
	printf("\n");
	return 0;
}

int
main(int argc, char **argv) {
	char line[4096];
	isc_result_t result;
	dns_fixedname_t fname, forigin;
	dns_name_t *name, *origin;
	isc_buffer_t source;
	dns_compress_flags_t flags = 0;

	isc_mem_create(&mctx);
	if (argc > 1) {
		char *copy = strdup(argv[1]);
		char *tok = strtok(copy, ",");
		while (tok != NULL) {
			if (strcmp(tok, "disabled") == 0) {
				flags |= DNS_COMPRESS_DISABLED;
			} else if (strcmp(tok, "case") == 0) {
				flags |= DNS_COMPRESS_CASE;
			} else if (strcmp(tok, "large") == 0) {
				flags |= DNS_COMPRESS_LARGE;
			}
			tok = strtok(NULL, ",");
		}
		free(copy);
	}
	dns_compress_init(&cctx, mctx, flags);
	if (argc > 1 && strstr(argv[1], "nopermit") != NULL) {
		dns_compress_setpermitted(&cctx, false);
	}
	isc_buffer_init(&target, msg, sizeof(msg));
	dns_fixedname_init(&fname);
	name = dns_fixedname_name(&fname);

	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	isc_buffer_init(&source, ".", 1);
	isc_buffer_add(&source, 1);
	result = dns_name_fromtext(origin, &source, NULL, 0, NULL);
	if (result != ISC_R_SUCCESS) {
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
		if (emit(name) != 0) {
			continue;
		}
	}

	dns_compress_invalidate(&cctx);
	isc_mem_destroy(&mctx);
	return 0;
}

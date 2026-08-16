/*
 * probe_rdata.c — oracle probe for dns_rdata_* semantics (bind9-rs courts).
 *
 * Reads one test case per line from stdin:
 *
 *   <type-mnemonic> <rdata text>
 *
 * (e.g. "A 192.0.2.1", "NS ns1.example.com.", "TYPE65280 \# 4 01020304").
 * The type mnemonic is lexed as the first token; dns_rdata_fromtext
 * consumes the rest, with the root as origin.
 *
 * For each case, one result line is written to stdout:
 *
 *   OK <totext>|<wire-hex>|<canonical-hex>|<fromwire-totext>
 *   ERR <result-code>
 *   <STAGE>-ERR <code>     (when a later stage fails)
 *
 * - totext          = dns_rdata_totext(rdata, NULL, ...) with no origin
 * - wire-hex        = dns_rdata_towire with a DISABLED compression context
 *                     (names rendered uncompressed, independent of order)
 * - canonical-hex   = dns_rdata_digest() DNSSEC canonical form
 * - fromwire-totext = dns_rdata_fromwire(DNS_DECOMPRESS_PERMITTED) over the
 *                     wire bytes, then dns_rdata_totext — the independent
 *                     wire->text round-trip
 *
 * All stage buffers are distinct so no stage can clobber another's data.
 * Oracle-side tooling only (spec §2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

static isc_mem_t *mctx = NULL;
static isc_lex_t *lex = NULL;
static dns_compress_t cctx;
static unsigned char rdbuf[65536];      /* dns_rdata_fromtext target       */
static unsigned char wirebuf[65536];    /* dns_rdata_towire output         */
static unsigned char canonicalbuf[65536]; /* dns_rdata_digest collection   */
static unsigned char textbuf[65536];    /* dns_rdata_totext output         */
static unsigned char rtbuf[65536];      /* fromwire target                 */
static unsigned char rttxtbuf[65536];   /* round-trip totext target        */

/*
 * Every stage has its own buffer: dns_rdata_totext writes into the target
 * while reading the rdata, so sharing a buffer between the fromwire target
 * and the round-trip totext target would clobber the rdata being rendered.
 */

static void
print_hex(const unsigned char *base, unsigned int len) {
	unsigned int i;
	for (i = 0; i < len; i++) {
		printf("%02x", base[i]);
	}
}

static isc_result_t
collect_canonical(void *arg, isc_region_t *region) {
	unsigned int *used = (unsigned int *)arg;
	if (*used + region->length > sizeof(canonicalbuf)) {
		return ISC_R_NOSPACE;
	}
	memcpy(canonicalbuf + *used, region->base, region->length);
	*used += region->length;
	return ISC_R_SUCCESS;
}

static void
emit_rdata(dns_rdata_t *rdata, dns_rdataclass_t rdclass,
	   dns_rdatatype_t type) {
	isc_buffer_t tb, wb;
	isc_region_t r;
	isc_result_t result;
	unsigned int canon_used = 0;

	/* totext (origin NULL). */
	isc_buffer_init(&tb, textbuf, sizeof(textbuf));
	result = dns_rdata_totext(rdata, NULL, &tb);
	if (result != ISC_R_SUCCESS) {
		printf("TOTEXT-ERR %s\n", isc_result_totext(result));
		return;
	}
	textbuf[isc_buffer_usedlength(&tb)] = '\0';

	/* towire with a disabled compression context (uncompressed names). */
	dns_compress_rollback(&cctx, 0);
	isc_buffer_init(&wb, wirebuf, sizeof(wirebuf));
	result = dns_rdata_towire(rdata, &cctx, &wb);
	if (result != ISC_R_SUCCESS) {
		printf("WIRE-ERR %s\n", isc_result_totext(result));
		return;
	}
	isc_buffer_usedregion(&wb, &r);

	/* DNSSEC canonical form via dns_rdata_digest. */
	canon_used = 0;
	result = dns_rdata_digest(rdata, collect_canonical, &canon_used);
	if (result != ISC_R_SUCCESS) {
		printf("CANON-ERR %s\n", isc_result_totext(result));
		return;
	}

	/* Independent wire->text round-trip. */
	{
		dns_rdata_t r2;
		isc_buffer_t src, tb2;

		dns_rdata_init(&r2);
		isc_buffer_constinit(&src, r.base, r.length);
		isc_buffer_add(&src, r.length);
		isc_buffer_setactive(&src, r.length);
		isc_buffer_init(&tb2, rtbuf, sizeof(rtbuf));
		result = dns_rdata_fromwire(&r2, rdclass, type, &src,
					    DNS_DECOMPRESS_PERMITTED, &tb2);
		if (result != ISC_R_SUCCESS) {
			printf("FROMWIRE-ERR %s\n", isc_result_totext(result));
			return;
		}
		isc_buffer_init(&tb2, rttxtbuf, sizeof(rttxtbuf));
		result = dns_rdata_totext(&r2, NULL, &tb2);
		if (result != ISC_R_SUCCESS) {
			printf("FROMWIRE-TOTEXT-ERR %s\n",
			       isc_result_totext(result));
			return;
		}
		rttxtbuf[isc_buffer_usedlength(&tb2)] = '\0';
	}

	printf("OK %s|", textbuf);
	print_hex(r.base, r.length);
	printf("|");
	print_hex(canonicalbuf, canon_used);
	printf("|%s\n", rttxtbuf);
}

int
main(void) {
	char line[16384];
	isc_result_t result;
	dns_fixedname_t forigin;
	dns_name_t *origin;

	isc_mem_create(&mctx);
	isc_lex_create(mctx, 1024, &lex);
	dns_compress_init(&cctx, mctx, DNS_COMPRESS_DISABLED);

	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	{
		isc_buffer_t source;
		isc_buffer_init(&source, ".", 1);
		isc_buffer_add(&source, 1);
		result = dns_name_fromtext(origin, &source, NULL, 0, NULL);
		if (result != ISC_R_SUCCESS) {
			return 1;
		}
	}

	while (fgets(line, sizeof(line), stdin) != NULL) {
		size_t len = strlen(line);
		isc_buffer_t source;
		isc_token_t token;
		dns_rdatatype_t type;
		dns_rdata_t rdata;
		isc_buffer_t target;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0) {
			continue;
		}

		/* Lex the type mnemonic as the first token. */
		isc_buffer_init(&source, line, (unsigned int)len);
		isc_buffer_add(&source, (unsigned int)len);
		result = isc_lex_openbuffer(lex, &source);
		if (result != ISC_R_SUCCESS) {
			printf("LEX-ERR %s\n", isc_result_totext(result));
			continue;
		}
		result = isc_lex_getmastertoken(lex, &token,
						isc_tokentype_string, false);
		if (result != ISC_R_SUCCESS) {
			printf("TYPE-LEX-ERR %s\n", isc_result_totext(result));
			continue;
		}
		result = dns_rdatatype_fromtext(&type, &token.value.as_textregion);
		if (result != ISC_R_SUCCESS) {
			printf("TYPE-ERR %s\n", isc_result_totext(result));
			continue;
		}

		dns_rdata_init(&rdata);
		isc_buffer_init(&target, rdbuf, sizeof(rdbuf));
		result = dns_rdata_fromtext(&rdata, dns_rdataclass_in, type,
					    lex, origin, 0, mctx, &target,
					    NULL);
		if (result != ISC_R_SUCCESS) {
			printf("ERR %s\n", isc_result_totext(result));
			continue;
		}
		emit_rdata(&rdata, dns_rdataclass_in, type);
	}

	dns_compress_invalidate(&cctx);
	isc_lex_destroy(&lex);
	isc_mem_destroy(&mctx);
	return 0;
}

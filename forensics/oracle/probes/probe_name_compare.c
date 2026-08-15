/*
 * probe_name_compare.c — oracle probe for dns_name_compare /
 * dns_name_fullcompare / dns_name_rdatacompare / dns_name_issubdomain /
 * dns_name_isequal semantics.
 *
 * Reads one test case per stdin line: "name1|name2" (raw masterfile text,
 * resolved against the root origin).  Emits:
 *
 *   OK <compare> <namereln> <nlabels> <subdomain> <isequal> <rdatacompare>
 *   ERR <result-code>
 *
 * compare/rdatacompare: -1/0/1; namereln: 0=none 1=contains 2=subdomain
 * 3=equal 4=commonancestor; nlabels: dns_name_fullcompare's common-label
 * count; subdomain/isequal: 0/1.
 *
 * Note: dns_name_compare REQUIRES both names absolute or both relative
 * (REQUIRE → abort).  All names here are resolved against the root, so they
 * are absolute.
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

#include <dns/fixedname.h>
#include <dns/name.h>
#include <dns/result.h>

static isc_mem_t *mctx = NULL;

static int
build_name(const char *text, dns_name_t *name, const dns_name_t *origin) {
	isc_buffer_t source;
	isc_result_t result;

	isc_buffer_init(&source, (void *)text, (unsigned int)strlen(text));
	isc_buffer_add(&source, (unsigned int)strlen(text));
	dns_name_reset(name);
	result = dns_name_fromtext(name, &source, origin, 0, NULL);
	return result == ISC_R_SUCCESS ? 0 : -1;
}

int
main(int argc, char **argv) {
	char line[8192];
	isc_result_t result;
	dns_fixedname_t f1, f2, forigin;
	dns_name_t *n1, *n2, *origin;
	isc_buffer_t source;
	int order;
	unsigned int nlabels;
	dns_namereln_t rel;
	int subdomain;
	int isequal;
	int rdcmp;

	UNUSED(argc);
	UNUSED(argv);

	isc_mem_create(&mctx);
	dns_fixedname_init(&f1);
	dns_fixedname_init(&f2);
	n1 = dns_fixedname_name(&f1);
	n2 = dns_fixedname_name(&f2);

	dns_fixedname_init(&forigin);
	origin = dns_fixedname_name(&forigin);
	isc_buffer_init(&source, ".", 1);
	isc_buffer_add(&source, 1);
	result = dns_name_fromtext(origin, &source, NULL, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return 1;
	}

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char *sep;
		size_t len = strlen(line);

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0) {
			continue;
		}
		sep = strchr(line, '|');
		if (sep == NULL) {
			printf("ERR bad input\n");
			continue;
		}
		*sep = '\0';

		if (build_name(line, n1, origin) != 0) {
			printf("ERR %s\n", isc_result_totext(result));
			continue;
		}
		if (build_name(sep + 1, n2, origin) != 0) {
			printf("ERR %s\n", isc_result_totext(result));
			continue;
		}

		order = dns_name_compare(n1, n2);
		rel = dns_name_fullcompare(n1, n2, &order, &nlabels);
		subdomain = dns_name_issubdomain(n1, n2) ? 1 : 0;
		isequal = dns_name_equal(n1, n2) ? 1 : 0;
		rdcmp = dns_name_rdatacompare(n1, n2);
		if (rdcmp < 0) {
			rdcmp = -1;
		} else if (rdcmp > 0) {
			rdcmp = 1;
		}
		printf("OK %d %d %u %d %d %d\n", order, (int)rel, nlabels,
		       subdomain, isequal, rdcmp);
	}

	isc_mem_destroy(&mctx);
	return 0;
}

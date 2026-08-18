/*
 * probe_tables.c — oracle probe for the rcode/tsigrcode/type/class tables
 * (the TABLES-0001 court).
 *
 * Reads one command per line from stdin: `<cmd> <arg>`.  Emits one result
 * line per command:
 *
 *   OK <value>
 *   ERR <result-text>
 *
 * Commands:
 *   rcode-totext <n>        dns_rcode_totext
 *   rcode-fromtext <tok>    dns_rcode_fromtext (value or error text)
 *   tsigrcode-totext <n>    dns_tsigrcode_totext
 *   tsigrcode-fromtext <tok>
 *   type-totext <n>         dns_rdatatype_totext
 *   type-fromtext <tok>     dns_rdatatype_fromtext
 *   type-ismeta <n>         dns_rdatatype_ismeta -> 0/1
 *   type-issingleton <n>    dns_rdatatype_issingleton -> 0/1
 *   type-isknown <n>        dns_rdatatype_isknown -> 0/1
 *   class-totext <n>        dns_rdataclass_totext
 *   class-fromtext <tok>    dns_rdataclass_fromtext
 *
 * Oracle-side tooling only (spec §2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/rcode.h>
#include <dns/rdataclass.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

/* Not in the public header (lib/dns/rdata.c 9.20.26). */
extern bool dns_rdatatype_ismeta(dns_rdatatype_t type);
extern bool dns_rdatatype_issingleton(dns_rdatatype_t type);
extern bool dns_rdatatype_isknown(dns_rdatatype_t type);

static isc_mem_t *mctx = NULL;

static void
print_totext(isc_result_t result, const char *buf, unsigned int len) {
	if (result != ISC_R_SUCCESS) {
		printf("ERR %s\n", isc_result_totext(result));
	} else {
		printf("OK %.*s\n", (int)len, buf);
	}
}

int
main(void) {
	char line[512];

	isc_mem_create(&mctx);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char cmd[64], arg[256];
		unsigned long n;
		isc_textregion_t tr;
		isc_buffer_t b;
		char buf[512];
		isc_result_t result;

		if (sscanf(line, "%63s %255s", cmd, arg) != 2) {
			if (sscanf(line, "%63s", cmd) != 1) {
				continue;
			}
			arg[0] = '\0';
		}

		tr.base = (unsigned char *)arg;
		tr.length = (unsigned int)strlen(arg);

		if (strcmp(cmd, "rcode-totext") == 0 ||
		    strcmp(cmd, "tsigrcode-totext") == 0 ||
		    strcmp(cmd, "type-totext") == 0 ||
		    strcmp(cmd, "class-totext") == 0 ||
		    strcmp(cmd, "type-ismeta") == 0 ||
		    strcmp(cmd, "type-issingleton") == 0 ||
		    strcmp(cmd, "type-isknown") == 0)
		{
			n = strtoul(arg, NULL, 10);
			isc_buffer_init(&b, buf, sizeof(buf));
			if (strcmp(cmd, "rcode-totext") == 0) {
				result = dns_rcode_totext((dns_rcode_t)n, &b);
				print_totext(result, buf, isc_buffer_usedlength(&b));
			} else if (strcmp(cmd, "tsigrcode-totext") == 0) {
				result = dns_tsigrcode_totext((dns_rcode_t)n, &b);
				print_totext(result, buf, isc_buffer_usedlength(&b));
			} else if (strcmp(cmd, "type-totext") == 0) {
				result = dns_rdatatype_totext((dns_rdatatype_t)n, &b);
				print_totext(result, buf, isc_buffer_usedlength(&b));
			} else if (strcmp(cmd, "class-totext") == 0) {
				result = dns_rdataclass_totext((dns_rdataclass_t)n, &b);
				print_totext(result, buf, isc_buffer_usedlength(&b));
			} else if (strcmp(cmd, "type-ismeta") == 0) {
				printf("OK %d\n", dns_rdatatype_ismeta((dns_rdatatype_t)n) ? 1 : 0);
			} else if (strcmp(cmd, "type-issingleton") == 0) {
				printf("OK %d\n", dns_rdatatype_issingleton((dns_rdatatype_t)n) ? 1 : 0);
			} else {
				printf("OK %d\n", dns_rdatatype_isknown((dns_rdatatype_t)n) ? 1 : 0);
			}
			continue;
		}

		if (strcmp(cmd, "rcode-fromtext") == 0 ||
		    strcmp(cmd, "tsigrcode-fromtext") == 0 ||
		    strcmp(cmd, "type-fromtext") == 0 ||
		    strcmp(cmd, "class-fromtext") == 0)
		{
			unsigned int value = 0;
			if (strcmp(cmd, "rcode-fromtext") == 0) {
				result = dns_rcode_fromtext((dns_rcode_t *)&value, &tr);
			} else if (strcmp(cmd, "tsigrcode-fromtext") == 0) {
				result = dns_tsigrcode_fromtext((dns_rcode_t *)&value, &tr);
			} else if (strcmp(cmd, "type-fromtext") == 0) {
				result = dns_rdatatype_fromtext((dns_rdatatype_t *)&value, &tr);
			} else {
				result = dns_rdataclass_fromtext((dns_rdataclass_t *)&value, &tr);
			}
			if (result != ISC_R_SUCCESS) {
				printf("ERR %s\n", isc_result_totext(result));
			} else {
				printf("OK %u\n", value);
			}
			continue;
		}

		printf("ERR unknown-command\n");
	}

	isc_mem_destroy(&mctx);
	return 0;
}

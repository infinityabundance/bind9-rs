/*
 * probe_message.c — oracle probe for dns_message_parse / dns_message_render
 * semantics (the WIRE-MESSAGE-* courts).
 *
 * Reads one test case per line from stdin.  Each line is a wire-format DNS
 * message in lowercase hex (no whitespace).  Emits:
 *
 *   PARSE <result-text>
 *   HEADER id=0x.... opcode=.. rcode=.. flags=0x.... qd=.. an=.. ns=.. ar=..
 *   QUESTION <name> <type> <class>          (per question rdataset)
 *   ANSWER <name> ttl=<n> <class> <type> <rdata-totext>   (per rdata)
 *   AUTHORITY ...                           (same layout)
 *   ADDITIONAL ...
 *   OPT udpsize=<n> extrcode=<n> version=<n> do=<n> z=0x....
 *        options=<code>:<len>:<hex>[, ...]
 *   TSIG <name>                             (when present)
 *   SIG0 <name>                             (when present)
 *   RENDER <hex>
 *   REPARSE <result-text>
 *   <full structure again>
 *
 * dns_message_parse runs with DNS_MESSAGEPARSE_BESTEFFORT; the render path
 * mirrors the fuzz harness (renderbegin + the four rendersections +
 * renderend), and the rendered bytes are parsed again with the same flow.
 *
 * rdata is rendered with a NULL origin (dns_rdata_totext(rdata, NULL, ..));
 * the corpus uses absolute names so no origin-dependent output is
 * observable.  ttl is the rdataset ttl (BIND minimizes it across the
 * rdata of an rrset).
 *
 * Oracle-side tooling only (spec §2).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/list.h>
#include <isc/mem.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/util.h>

#include <dns/compress.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdataclass.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatatype.h>
#include <dns/result.h>

static isc_mem_t *mctx = NULL;

static void
print_hex(const unsigned char *base, unsigned int len) {
	unsigned int i;
	for (i = 0; i < len; i++) {
		printf("%02x", base[i]);
	}
}

static void
name_text(const dns_name_t *name, char *buf, size_t buflen) {
	isc_buffer_t tb;
	isc_result_t result;

	isc_buffer_init(&tb, buf, (unsigned int)buflen);
	result = dns_name_totext(name, false, &tb);
	if (result != ISC_R_SUCCESS) {
		(void)snprintf(buf, buflen, "<NAME-ERR %s>",
			       isc_result_totext(result));
		return;
	}
	buf[isc_buffer_usedlength(&tb)] = '\0';
}

static void
rdata_text(const dns_rdata_t *rdata, char *buf, size_t buflen) {
	isc_buffer_t tb;
	isc_result_t result;
	dns_rdata_t r = *rdata;

	isc_buffer_init(&tb, buf, (unsigned int)buflen);
	result = dns_rdata_totext(&r, NULL, &tb);
	if (result != ISC_R_SUCCESS) {
		(void)snprintf(buf, buflen, "<RDATA-ERR %s>",
			       isc_result_totext(result));
		return;
	}
	buf[isc_buffer_usedlength(&tb)] = '\0';
}

static void
type_text(dns_rdatatype_t type, char *buf, size_t buflen) {
	isc_buffer_t tb;
	isc_result_t result;

	isc_buffer_init(&tb, buf, (unsigned int)buflen);
	result = dns_rdatatype_totext(type, &tb);
	if (result != ISC_R_SUCCESS) {
		(void)snprintf(buf, buflen, "TYPE%u", type);
		return;
	}
	buf[isc_buffer_usedlength(&tb)] = '\0';
}

static void
class_text(dns_rdataclass_t rdclass, char *buf, size_t buflen) {
	isc_buffer_t tb;
	isc_result_t result;

	isc_buffer_init(&tb, buf, (unsigned int)buflen);
	result = dns_rdataclass_totext(rdclass, &tb);
	if (result != ISC_R_SUCCESS) {
		(void)snprintf(buf, buflen, "CLASS%u", rdclass);
		return;
	}
	buf[isc_buffer_usedlength(&tb)] = '\0';
}

static void
print_section(dns_message_t *msg, dns_section_t section, const char *label) {
	dns_name_t *name = NULL;
	dns_rdataset_t *rdataset;
	isc_result_t res;
	char nbuf[1024], tbuf[64], cbuf[64], rbuf[65536];

	res = dns_message_firstname(msg, section);
	while (res == ISC_R_SUCCESS) {
		name = NULL;
		dns_message_currentname(msg, section, &name);
		name_text(name, nbuf, sizeof(nbuf));
		for (rdataset = ISC_LIST_HEAD(name->list); rdataset != NULL;
		     rdataset = ISC_LIST_NEXT(rdataset, link))
		{
			isc_result_t result;
			dns_rdata_t rdata;
			dns_ttl_t ttl = rdataset->ttl;

			if ((rdataset->attributes & DNS_RDATASETATTR_QUESTION) != 0) {
				type_text(rdataset->type, tbuf, sizeof(tbuf));
				class_text(rdataset->rdclass, cbuf, sizeof(cbuf));
				printf("QUESTION %s %s %s\n", nbuf, cbuf, tbuf);
				continue;
			}
			type_text(rdataset->type, tbuf, sizeof(tbuf));
			class_text(rdataset->rdclass, cbuf, sizeof(cbuf));
			result = dns_rdataset_first(rdataset);
			while (result == ISC_R_SUCCESS) {
				dns_rdata_t rdata;
				dns_rdata_init(&rdata);
				dns_rdataset_current(rdataset, &rdata);
				rdata_text(&rdata, rbuf, sizeof(rbuf));
				printf("%s %s ttl=%u %s %s %s\n", label, nbuf,
				       ttl, cbuf, tbuf, rbuf);
				result = dns_rdataset_next(rdataset);
			}
		}
		res = dns_message_nextname(msg, section);
	}
}

static void
print_opt(dns_message_t *msg) {
	dns_rdataset_t *opt = dns_message_getopt(msg);
	dns_rdata_t rdata;
	unsigned int i;

	if (opt == NULL) {
		return;
	}
	if (dns_rdataset_first(opt) != ISC_R_SUCCESS) {
		printf("OPT <EMPTY>\n");
		return;
	}
	dns_rdata_init(&rdata);
	dns_rdataset_current(opt, &rdata);
	printf("OPT udpsize=%u extrcode=%u version=%u do=%u z=0x%04x",
	       opt->rdclass, (opt->ttl >> 24) & 0xff,
	       (opt->ttl >> 16) & 0xff, (opt->ttl >> 15) & 1,
	       opt->ttl & 0x7fff);
	if (rdata.length != 0) {
		printf(" options=");
		for (i = 0; i + 4 <= rdata.length;) {
			unsigned int code =
				((unsigned int)rdata.data[i] << 8) |
				rdata.data[i + 1];
			unsigned int len =
				((unsigned int)rdata.data[i + 2] << 8) |
				rdata.data[i + 3];
			unsigned int j;
			if (i + 4 + len > rdata.length) {
				printf("TRUNC");
				break;
			}
			printf("%s%u:%u:", i == 0 ? "" : ",", code, len);
			for (j = 0; j < len; j++) {
				printf("%02x", rdata.data[i + 4 + j]);
			}
			i += 4 + len;
		}
	}
	printf("\n");
}

static void
print_message(dns_message_t *msg) {
	char nbuf[1024];

	printf("HEADER id=0x%04x opcode=%u rcode=%u flags=0x%04x "
	       "qd=%u an=%u ns=%u ar=%u\n",
	       msg->id, msg->opcode, msg->rcode, msg->flags,
	       msg->counts[DNS_SECTION_QUESTION],
	       msg->counts[DNS_SECTION_ANSWER],
	       msg->counts[DNS_SECTION_AUTHORITY],
	       msg->counts[DNS_SECTION_ADDITIONAL]);
	print_section(msg, DNS_SECTION_QUESTION, "QUESTION");
	print_section(msg, DNS_SECTION_ANSWER, "ANSWER");
	print_section(msg, DNS_SECTION_AUTHORITY, "AUTHORITY");
	print_section(msg, DNS_SECTION_ADDITIONAL, "ADDITIONAL");
	print_opt(msg);
	if (msg->tsig != NULL) {
		name_text(msg->tsigname, nbuf, sizeof(nbuf));
		printf("TSIG %s\n", nbuf);
	}
	if (msg->sig0 != NULL) {
		name_text(msg->sig0name, nbuf, sizeof(nbuf));
		printf("SIG0 %s\n", nbuf);
	}
}

static void
run_case(const unsigned char *wire, size_t len) {
	isc_buffer_t buf;
	isc_result_t result;
	dns_message_t *msg = NULL;

	isc_buffer_constinit(&buf, wire, (unsigned int)len);
	isc_buffer_add(&buf, (unsigned int)len);
	isc_buffer_setactive(&buf, (unsigned int)len);

	dns_message_create(mctx, NULL, NULL, DNS_MESSAGE_INTENTPARSE, &msg);

	result = dns_message_parse(msg, &buf, DNS_MESSAGEPARSE_BESTEFFORT);
	printf("PARSE %s\n", isc_result_totext(result));
	if (result != ISC_R_SUCCESS && result != DNS_R_RECOVERABLE) {
		dns_message_detach(&msg);
		return;
	}
	print_message(msg);

	/* Render the message back to wire. */
	{
		unsigned char render_buf[65535];
		isc_buffer_t rb;
		dns_compress_t cctx;

		isc_buffer_init(&rb, render_buf, sizeof(render_buf));
		msg->from_to_wire = DNS_MESSAGE_INTENTRENDER;
		for (int i = 0; i < DNS_SECTION_MAX; i++) {
			msg->counts[i] = 0;
		}
		dns_compress_init(&cctx, mctx, 0);
		result = dns_message_renderbegin(msg, &cctx, &rb);
		if (result == ISC_R_SUCCESS) {
			result = dns_message_rendersection(
				msg, DNS_SECTION_QUESTION, 0);
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_message_rendersection(
				msg, DNS_SECTION_ANSWER, 0);
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_message_rendersection(
				msg, DNS_SECTION_AUTHORITY, 0);
		}
		if (result == ISC_R_SUCCESS) {
			result = dns_message_rendersection(
				msg, DNS_SECTION_ADDITIONAL, 0);
		}
		dns_message_renderend(msg);
		dns_compress_invalidate(&cctx);

		if (result != ISC_R_SUCCESS) {
			printf("RENDER-ERR %s\n", isc_result_totext(result));
		} else {
			printf("RENDER ");
			print_hex(render_buf,
				  isc_buffer_usedlength(&rb));
			printf("\n");
		}

		msg->from_to_wire = DNS_MESSAGE_INTENTPARSE;

		/* Re-parse the rendered bytes. */
		{
			isc_buffer_t rbuf2;
			dns_message_t *msg2 = NULL;
			isc_result_t r2;

			isc_buffer_constinit(&rbuf2, render_buf,
					     isc_buffer_usedlength(&rb));
			isc_buffer_add(&rbuf2, isc_buffer_usedlength(&rb));
			isc_buffer_setactive(&rbuf2,
					     isc_buffer_usedlength(&rb));
			dns_message_create(mctx, NULL, NULL,
					   DNS_MESSAGE_INTENTPARSE, &msg2);
			r2 = dns_message_parse(msg2, &rbuf2,
					       DNS_MESSAGEPARSE_BESTEFFORT);
			printf("REPARSE %s\n", isc_result_totext(r2));
			if (r2 == ISC_R_SUCCESS || r2 == DNS_R_RECOVERABLE) {
				print_message(msg2);
			}
			dns_message_detach(&msg2);
		}
	}

	dns_message_detach(&msg);
}

int
main(int argc, char **argv) {
	char line[140000];
	unsigned char wire[65536];

	UNUSED(argc);
	UNUSED(argv);

	isc_mem_create(&mctx);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		size_t len = strlen(line);
		size_t i;
		size_t n = 0;

		while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
			line[--len] = '\0';
		}
		if (len == 0) {
			continue;
		}
		if (len % 2 != 0) {
			printf("BAD-INPUT odd-hex-length\n");
			continue;
		}
		for (i = 0; i < len; i += 2) {
			unsigned int hi, lo;
			char h = line[i], l = line[i + 1];
#define HEXDIG(c)                                                          \
	((c) >= '0' && (c) <= '9' ? (unsigned int)((c) - '0') :            \
	 (c) >= 'a' && (c) <= 'f' ? (unsigned int)((c) - 'a' + 10) :       \
	 (c) >= 'A' && (c) <= 'F' ? (unsigned int)((c) - 'A' + 10) : 99U)
			hi = HEXDIG(h);
			lo = HEXDIG(l);
			if (hi == 99U || lo == 99U) {
				printf("BAD-INPUT non-hex\n");
				n = 0;
				break;
			}
			wire[n++] = (unsigned char)((hi << 4) | lo);
		}
#undef HEXDIG
		if (n == 0) {
			continue;
		}
		run_case(wire, n);
	}

	isc_mem_destroy(&mctx);
	return 0;
}

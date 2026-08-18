/*
 * probe_lex.c — oracle probe for the masterfile lexer (the ISC-LEX-0001
 * court): isc_lex_gettoken / isc_lex_getmastertoken semantics with the
 * masterfile specials (`\0`, `(`, `)`, `"`) and DNSMASTERFILE comments.
 *
 * Reads one command per line from stdin:
 *
 *   lex <base64>       isc_lex_gettoken loop with
 *                      EOL|EOF|DNSMULTILINE|ESCAPE|STRING|QSTRING|NUMBER
 *   master <base64>    isc_lex_getmastertoken(STRING, eol=true) loop
 *
 * Prints one line per token:
 *
 *   STRING <raw> / QSTRING <raw> / NUMBER <n> / SPECIAL <c> /
 *   EOL / EOF / INITIALWS <c> / MASTER-* variants / END / ERR <result-text>
 *
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

static isc_mem_t *mctx = NULL;

static int
b64val(char c) {
	if (c >= 'A' && c <= 'Z') {
		return c - 'A';
	}
	if (c >= 'a' && c <= 'z') {
		return c - 'a' + 26;
	}
	if (c >= '0' && c <= '9') {
		return c - '0' + 52;
	}
	if (c == '+') {
		return 62;
	}
	if (c == '/') {
		return 63;
	}
	return -1;
}

static size_t
b64decode(const char *s, unsigned char *out, size_t outlen) {
	size_t o = 0;
	int buf = 0, bits = 0;
	for (; *s != '\0'; s++) {
		int v = b64val(*s);
		if (v < 0) {
			continue;
		}
		buf = (buf << 6) | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			if (o < outlen) {
				out[o++] = (unsigned char)((buf >> bits) & 0xff);
			}
		}
	}
	return o;
}

static void
print_token(const isc_token_t *token) {
	switch (token->type) {
	case isc_tokentype_string:
		printf("STRING %.*s\n",
		       (int)token->value.as_textregion.length,
		       (const char *)token->value.as_textregion.base);
		break;
	case isc_tokentype_qstring:
		printf("QSTRING %.*s\n",
		       (int)token->value.as_textregion.length,
		       (const char *)token->value.as_textregion.base);
		break;
	case isc_tokentype_number:
		printf("NUMBER %lu\n", token->value.as_ulong);
		break;
	case isc_tokentype_special:
		printf("SPECIAL %c\n", token->value.as_char);
		break;
	case isc_tokentype_eol:
		printf("EOL\n");
		break;
	case isc_tokentype_eof:
		printf("EOF\n");
		break;
	case isc_tokentype_initialws:
		printf("INITIALWS %c\n", token->value.as_char);
		break;
	default:
		printf("TOKENTYPE-%d\n", token->type);
		break;
	}
}

static void
run_lex(const unsigned char *data, size_t len, bool master) {
	isc_lex_t *lex = NULL;
	isc_buffer_t buf;
	isc_result_t result;
	unsigned int count = 0;

	isc_lex_create(mctx, 1024, &lex);
	{
		isc_lexspecials_t specials;
		memset(specials, 0, sizeof(specials));
		specials[0] = 1;
		specials['('] = 1;
		specials[')'] = 1;
		specials['"'] = 1;
		isc_lex_setspecials(lex, specials);
	}
	isc_lex_setcomments(lex, ISC_LEXCOMMENT_DNSMASTERFILE);

	isc_buffer_init(&buf, (void *)data, (unsigned int)len);
	isc_buffer_add(&buf, (unsigned int)len);
	isc_lex_openbuffer(lex, &buf);

	for (;;) {
		isc_token_t token;
		if (master) {
			result = isc_lex_getmastertoken(lex, &token,
							  isc_tokentype_string,
							  true);
		} else {
			result = isc_lex_gettoken(
				lex,
				ISC_LEXOPT_EOL | ISC_LEXOPT_EOF |
					ISC_LEXOPT_DNSMULTILINE |
					ISC_LEXOPT_ESCAPE | ISC_LEXOPT_QSTRING |
					ISC_LEXOPT_NUMBER,
				&token);
		}
		if (result != ISC_R_SUCCESS) {
			printf("ERR %s\n", isc_result_totext(result));
			break;
		}
		if (token.type == isc_tokentype_eof) {
			printf("EOF\n");
			break;
		}
		if (master) {
			printf("MASTER ");
		}
		print_token(&token);
		if (++count > 10000) {
			printf("ERR too-many-tokens\n");
			break;
		}
	}

	isc_lex_destroy(&lex);
}

int
main(void) {
	char line[4096];
	unsigned char data[2048];

	isc_mem_create(&mctx);

	while (fgets(line, sizeof(line), stdin) != NULL) {
		char cmd[16];
		char b64[2048];
		size_t len;
		if (sscanf(line, "%15s %2047s", cmd, b64) != 2) {
			continue;
		}
		len = b64decode(b64, data, sizeof(data));
		if (strcmp(cmd, "lex") == 0) {
			run_lex(data, len, false);
		} else if (strcmp(cmd, "master") == 0) {
			run_lex(data, len, true);
		} else {
			printf("ERR unknown-command\n");
		}
	}

	isc_mem_destroy(&mctx);
	return 0;
}

/* probe-libidn2-lz.c — libidn2 2.3.8 locale-layer + NO_TR46 probe (§28, §37).
 *
 * Exercises the Phase-1 conservation surface: the `_lz` locale layer
 * (idn2_to_ascii_lz = idn2_lookup_ul: locale-codeset → UTF-8 conversion with
 * the ICONV_FAIL taxonomy; idn2_to_unicode_8zlz: decode + UTF-8 → locale
 * conversion with the ENCODING_ERROR taxonomy) across the three pinned
 * locales (C.UTF-8, C, en_US.ISO-8859-1); the IDN2_NO_TR46 pure-IDNA2008
 * path (the reachable NO_TR46 flags — any TRANSITIONAL/NONTRANSITIONAL
 * combination is INVALID_FLAGS); the full flag-conflict taxonomy; and the
 * label-test corners (leading combining mark, 2-hyphen, hyphen-start/end
 * asymmetry between the TR46 and NO_TR46 test sets, unassigned, RFC 5893
 * bidi, the ZWNJ/ZWJ joining rules, the ContextO rules, STD3 disallowed
 * handling, and the length limits).
 *
 * The harness runs the probe once per locale (LANG set per run); the output
 * is printed with print_string-style escaping so every locale's bytes are
 * byte-exact.  Runs in the same oracle-libidn2-2.3.8 container as the Rust
 * mirror (bind9-rs-tools/src/bin/libidn2-lz-probe.rs); stdout must be
 * byte-identical.
 */
#include <idn2.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>

static void
print_string(const unsigned char *data, size_t len)
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

static const char *
rcname(int rc)
{
	switch (rc) {
	case IDN2_OK: return "OK";
	case IDN2_MALLOC: return "MALLOC";
	case IDN2_NO_CODESET: return "NO_CODESET";
	case IDN2_ICONV_FAIL: return "ICONV_FAIL";
	case IDN2_ENCODING_ERROR: return "ENCODING_ERROR";
	case IDN2_NFC: return "NFC";
	case IDN2_PUNYCODE_BAD_INPUT: return "PUNYCODE_BAD_INPUT";
	case IDN2_PUNYCODE_BIG_OUTPUT: return "PUNYCODE_BIG_OUTPUT";
	case IDN2_PUNYCODE_OVERFLOW: return "PUNYCODE_OVERFLOW";
	case IDN2_TOO_BIG_DOMAIN: return "TOO_BIG_DOMAIN";
	case IDN2_TOO_BIG_LABEL: return "TOO_BIG_LABEL";
	case IDN2_INVALID_ALABEL: return "INVALID_ALABEL";
	case IDN2_UALABEL_MISMATCH: return "UALABEL_MISMATCH";
	case IDN2_INVALID_FLAGS: return "INVALID_FLAGS";
	case IDN2_NOT_NFC: return "NOT_NFC";
	case IDN2_2HYPHEN: return "2HYPHEN";
	case IDN2_HYPHEN_STARTEND: return "HYPHEN_STARTEND";
	case IDN2_LEADING_COMBINING: return "LEADING_COMBINING";
	case IDN2_DISALLOWED: return "DISALLOWED";
	case IDN2_CONTEXTJ: return "CONTEXTJ";
	case IDN2_CONTEXTJ_NO_RULE: return "CONTEXTJ_NO_RULE";
	case IDN2_CONTEXTO: return "CONTEXTO";
	case IDN2_CONTEXTO_NO_RULE: return "CONTEXTO_NO_RULE";
	case IDN2_UNASSIGNED: return "UNASSIGNED";
	case IDN2_BIDI: return "BIDI";
	case IDN2_DOT_IN_LABEL: return "DOT_IN_LABEL";
	case IDN2_INVALID_TRANSITIONAL: return "INVALID_TRANSITIONAL";
	case IDN2_INVALID_NONTRANSITIONAL: return "INVALID_NONTRANSITIONAL";
	case IDN2_ALABEL_ROUNDTRIP_FAILED: return "ALABEL_ROUNDTRIP_FAILED";
	default: return "OTHER";
	}
}

static void
probe_lz(const char *label, const unsigned char *s, size_t len, int flags)
{
	char *out = NULL;
	int rc = idn2_to_ascii_lz((const char *) s, &out, flags);
	if (rc == IDN2_OK && out) {
		printf("  %-26s ", label);
		print_string(s, len);
		printf(" -> ");
		print_string((const unsigned char *) out, strlen(out));
		putchar('\n');
	} else {
		printf("  %-26s ", label);
		print_string(s, len);
		printf(" -> rc=%d (%s)\n", rc, rcname(rc));
	}
	if (out) idn2_free(out);
}

static void
probe_8zlz(const char *label, const char *s, int flags)
{
	char *out = NULL;
	int rc = idn2_to_unicode_8zlz(s, &out, flags);
	if (rc == IDN2_OK && out) {
		printf("  %-26s ", label);
		print_string((const unsigned char *) s, strlen(s));
		printf(" -> ");
		print_string((const unsigned char *) out, strlen(out));
		putchar('\n');
	} else {
		printf("  %-26s ", label);
		print_string((const unsigned char *) s, strlen(s));
		printf(" -> rc=%d (%s)\n", rc, rcname(rc));
	}
	if (out) idn2_free(out);
}

static void
probe_8z(const char *label, const char *s, int flags)
{
	char *out = NULL;
	int rc = idn2_to_ascii_8z(s, &out, flags);
	if (rc == IDN2_OK && out) {
		printf("  %-26s ", label);
		print_string((const unsigned char *) s, strlen(s));
		printf(" -> ");
		print_string((const unsigned char *) out, strlen(out));
		putchar('\n');
	} else {
		printf("  %-26s ", label);
		print_string((const unsigned char *) s, strlen(s));
		printf(" -> rc=%d (%s)\n", rc, rcname(rc));
	}
	if (out) idn2_free(out);
}

int
main(int argc, char **argv)
{
	(void) argc;
	setlocale(LC_ALL, "");

	if (argv[1] && strcmp(argv[1], "locale") == 0) {
		printf("== locale %s ==\n", nl_langinfo(CODESET));

		/* münchen.de and faß.de as UTF-8 and as ISO-8859-1 bytes.  The
		 * C API takes NUL-terminated strings, so each array carries a
		 * terminator and the probes pass sizeof-1. */
		static const unsigned char mue_utf8[] = {
			'm', 0xc3, 0xbc, 'n', 'c', 'h', 'e', 'n', '.', 'd', 'e', 0 };
		static const unsigned char mue_l1[] = {
			'm', 0xfc, 'n', 'c', 'h', 'e', 'n', '.', 'd', 'e', 0 };
		static const unsigned char fass_utf8[] = {
			'f', 'a', 0xc3, 0x9f, '.', 'd', 'e', 0 };
		static const unsigned char fass_l1[] = {
			'f', 'a', 0xdf, '.', 'd', 'e', 0 };
		static const unsigned char sigma_utf8[] = {
			0xcf, 0x82, '.', 'g', 'r', 0 };

		probe_lz("lz münchen.de", mue_utf8, sizeof(mue_utf8) - 1,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz faß.de", fass_utf8, sizeof(fass_utf8) - 1,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz ς.gr", sigma_utf8, sizeof(sigma_utf8) - 1,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz example.com", (const unsigned char *) "example.com",
			 11, IDN2_NONTRANSITIONAL);
		probe_lz("lz _tcp.example.com",
			 (const unsigned char *) "_tcp.example.com", 16,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz XN--MNCHEN-3YA.DE",
			 (const unsigned char *) "XN--MNCHEN-3YA.DE", 17,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz emoji.com", (const unsigned char *) "\xf0\x9f\x98\x80.com",
			 8, IDN2_NONTRANSITIONAL);
		probe_lz("lz münchen.de latin1", mue_l1, sizeof(mue_l1) - 1,
			 IDN2_NONTRANSITIONAL);
		probe_lz("lz faß.de latin1", fass_l1, sizeof(fass_l1) - 1,
			 IDN2_NONTRANSITIONAL);

		probe_8zlz("8zlz xn--mnchen-3ya.de", "xn--mnchen-3ya.de",
			   IDN2_NONTRANSITIONAL);
		probe_8zlz("8zlz XN--MNCHEN-3YA.DE", "XN--MNCHEN-3YA.DE",
			   IDN2_NONTRANSITIONAL);
		probe_8zlz("8zlz xn--e28h.com", "xn--e28h.com",
			   IDN2_NONTRANSITIONAL);
		probe_8zlz("8zlz example.com", "example.com",
			   IDN2_NONTRANSITIONAL);
		probe_8zlz("8zlz a..b", "a..b", IDN2_NONTRANSITIONAL);
		return 0;
	}

	if (argv[1] && strcmp(argv[1], "algo") == 0) {
		puts("== NO_TR46 (pure IDNA2008) ==");
		probe_8z("no46 münchen.de", "m\xc3\xbcnchen.de", IDN2_NO_TR46);
		probe_8z("no46 MÜNCHEN.de", "M\xc3\x9cNCHEN.de", IDN2_NO_TR46);
		probe_8z("no46 EXAMPLE.COM", "EXAMPLE.COM", IDN2_NO_TR46);
		probe_8z("no46 faß.de", "fa\xc3\x9f.de", IDN2_NO_TR46);
		probe_8z("no46 ς.gr", "\xcf\x82.gr", IDN2_NO_TR46);
		probe_8z("no46 βόλος.gr", "\xce\xb2\xcf\x8c\xce\xbb\xce\xbf\xcf\x82.gr",
			 IDN2_NO_TR46);
		probe_8z("no46 xn--mnchen-3ya.de", "xn--mnchen-3ya.de", IDN2_NO_TR46);
		probe_8z("no46 XN--MNCHEN-3YA.DE", "XN--MNCHEN-3YA.DE", IDN2_NO_TR46);
		probe_8z("no46 xn--0zwm56d.example", "xn--0zwm56d.example",
			 IDN2_NO_TR46);
		probe_8z("no46 a\\u00ADb.com", "a\xc2\xad" "b.com", IDN2_NO_TR46);
		probe_8z("no46 a\\u200Cb.com", "a\xe2\x80\x8c" "b.com", IDN2_NO_TR46);
		probe_8z("no46 a\\u200Db.com", "a\xe2\x80\x8d" "b.com", IDN2_NO_TR46);
		probe_8z("no46 emoji.com", "\xf0\x9f\x98\x80.com", IDN2_NO_TR46);
		probe_8z("no46 ßß.com", "\xc3\x9f\xc3\x9f.com", IDN2_NO_TR46);
		probe_8z("no46 _tcp.example.com", "_tcp.example.com", IDN2_NO_TR46);
		probe_8z("no46 1.2.3.4", "1.2.3.4", IDN2_NO_TR46);
		probe_8z("no46 a..b", "a..b", IDN2_NO_TR46);
		probe_8z("no46 .leading-dot", ".leading-dot", IDN2_NO_TR46);
		probe_8z("no46 trailing-dot.", "trailing-dot.", IDN2_NO_TR46);
		probe_8z("no46 www.xn--0.0.com", "www.xn--0.0.com", IDN2_NO_TR46);

		puts("== flag taxonomy ==");
		probe_8z("TR|NT", "example.com",
			 IDN2_TRANSITIONAL | IDN2_NONTRANSITIONAL);
		probe_8z("NT|NO_TR46", "example.com",
			 IDN2_NONTRANSITIONAL | IDN2_NO_TR46);
		probe_8z("TR|NO_TR46", "example.com",
			 IDN2_TRANSITIONAL | IDN2_NO_TR46);
		probe_8z("ALABEL|NO_ALABEL", "example.com",
			 IDN2_ALABEL_ROUNDTRIP | IDN2_NO_ALABEL_ROUNDTRIP);
		probe_8z("0 flags", "fa\xc3\x9f.de", 0);
		probe_8z("NO_ALABEL_ROUNDTRIP", "xn--mnchen-3ya.de",
			 IDN2_NO_ALABEL_ROUNDTRIP | IDN2_NONTRANSITIONAL);

		puts("== label tests ==");
		probe_8z("nt leading mark", "\xcc\x81" "a.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 leading mark", "\xcc\x81" "a.com", IDN2_NO_TR46);
		probe_8z("nt 2hyphen", "a\xc3\x9f--b.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 2hyphen", "a\xc3\x9f--b.com", IDN2_NO_TR46);
		probe_8z("nt hyphen-start", "-a\xc3\xa4.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 hyphen-start", "-a\xc3\xa4.com", IDN2_NO_TR46);
		probe_8z("nt hyphen-end", "a\xc3\xa4-.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 hyphen-end", "a\xc3\xa4-.com", IDN2_NO_TR46);
		probe_8z("nt unassigned", "\xcd\xb8.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 unassigned", "\xcd\xb8.com", IDN2_NO_TR46);
		probe_8z("nt bidi ok", "\xd7\x90\xd7\x91.com", IDN2_NONTRANSITIONAL);
		probe_8z("nt bidi bad", "a\xd7\x90" "b.com", IDN2_NONTRANSITIONAL);
		probe_8z("no46 bidi bad", "a\xd7\x90" "b.com", IDN2_NO_TR46);
		probe_8z("nt zwnj valid", "\xd8\xa8\xe2\x80\x8c\xd8\xa8.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt zwj invalid", "\xd8\xa8\xe2\x80\x8d\xd8\xa8.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt zwnj a-b", "a\xe2\x80\x8c" "b.com", IDN2_NONTRANSITIONAL);
		probe_8z("nt middot l·l", "l\xc2\xb7" "l.com", IDN2_NONTRANSITIONAL);
		probe_8z("nt middot a·b", "a\xc2\xb7" "b.com", IDN2_NONTRANSITIONAL);
		probe_8z("nt keraia greek", "\xce\xb1\xcd\xb5" "a.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt keraia not", "a\xcd\xb5" "b.com", IDN2_NONTRANSITIONAL);
		probe_8z("nt katakana dot", "\xe3\x83\xbb" "a.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt katakana dot kata", "\xe3\x82\xa2\xe3\x83\xbb" "a.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt std3 _ä", "_a\xc3\xa4.com",
			 IDN2_NONTRANSITIONAL | IDN2_USE_STD3_ASCII_RULES);
		probe_8z("no46 std3 _ä", "_a\xc3\xa4.com",
			 IDN2_NO_TR46 | IDN2_USE_STD3_ASCII_RULES);
		probe_8z("nt _tcp +std3", "_tcp.example.com",
			 IDN2_NONTRANSITIONAL | IDN2_USE_STD3_ASCII_RULES);
		probe_8z("nt longascii",
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("nt longlabel",
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc3\xa4.com",
			 IDN2_NONTRANSITIONAL);
		probe_8z("no46 longlabel",
			 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc3\xa4.com",
			 IDN2_NO_TR46);
		return 0;
	}

	return 1;
}

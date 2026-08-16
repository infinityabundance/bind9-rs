/* probe-libidn2.c — oracle probe for the dig-relevant libidn2 2.3.8 surface.
 *
 * Exercises the UTF-8 variants (8z8z, no locale dependency) for the IDNA
 * algorithm itself, plus the locale variants (lz) dig uses, under the exact
 * flag combinations BIND 9.20.26 dig uses (dighost.c idn_input/idn_filter):
 * NONTRANSITIONAL first, TRANSITIONAL fallback on IDN2_DISALLOWED.
 *
 * Build inside oracle-libidn2-2.3.8:
 *   gcc -o /tmp/probe /tmp/probe.c $(pkg-config --cflags --libs libidn2)
 */
#include <idn2.h>
#include <locale.h>
#include <stdio.h>

static const char *cases[] = {
    "münchen.de",
    "MÜNCHEN.de",
    "EXAMPLE.COM",
    "Example.com",
    "faß.de",
    "βόλος.gr",
    "ς.gr",
    "xn--mnchen-3ya.de",
    "xn--0zwm56d.example",
    "a\u00ADb.com",     /* soft hyphen U+00AD (ignored in TR46) */
    "a\u200Cb.com",     /* ZWNJ (deviation) */
    "a\u200Db.com",     /* ZWJ (deviation) */
    "\U0001F600.com",   /* emoji */
    "\u00DF\u00DF.com", /* double sharp s */
    "_tcp.example.com",
    "1.2.3.4",
    "www.xn--0.0.com",
    "a..b",
    ".leading-dot",
    "trailing-dot.",
    NULL,
};

static const char *
rcname(int rc)
{
    switch (rc) {
    case IDN2_OK: return "OK";
    case IDN2_ICONV_FAIL: return "ICONV_FAIL";
    case IDN2_ENCODING_ERROR: return "ENCODING_ERROR";
    case IDN2_PUNYCODE_BAD_INPUT: return "PUNYCODE_BAD_INPUT";
    case IDN2_DISALLOWED: return "DISALLOWED";
    case IDN2_CONTEXTJ: return "CONTEXTJ";
    case IDN2_2HYPHEN: return "2HYPHEN";
    case IDN2_HYPHEN_STARTEND: return "HYPHEN_STARTEND";
    case IDN2_TOO_BIG_LABEL: return "TOO_BIG_LABEL";
    case IDN2_TOO_BIG_DOMAIN: return "TOO_BIG_DOMAIN";
    case IDN2_BIDI: return "BIDI";
    case IDN2_UNASSIGNED: return "UNASSIGNED";
    case IDN2_LEADING_COMBINING: return "LEADING_COMBINING";
    case IDN2_UALABEL_MISMATCH: return "UALABEL_MISMATCH";
    case IDN2_INVALID_ALABEL: return "INVALID_ALABEL";
    default: return "OTHER";
    }
}

static void
probe(const char *label, const char *s, int flags, int loc)
{
    char *out = NULL;
    int rc;
    if (loc)
        rc = idn2_to_ascii_lz(s, &out, flags);
    else
        rc = idn2_to_ascii_8z(s, &out, flags);
    if (rc == IDN2_OK && out)
        printf("%-4s %-28s -> %s\n", label, s, out);
    else
        printf("%-4s %-28s -> rc=%d (%s)\n", label, s, rc, rcname(rc));
    if (out) idn2_free(out);
}

int
main(void)
{
    setlocale(LC_ALL, "");

    puts("== 8z NONTRANSITIONAL (UTF-8 locale)");
    for (int i = 0; cases[i]; i++)
        probe("nt", cases[i], IDN2_NONTRANSITIONAL, 0);

    puts("\n== 8z TRANSITIONAL (UTF-8 locale)");
    for (int i = 0; cases[i]; i++)
        probe("tr", cases[i], IDN2_TRANSITIONAL, 0);

    puts("\n== lz NONTRANSITIONAL (dig path, locale set)");
    for (int i = 0; cases[i]; i++)
        probe("ntl", cases[i], IDN2_NONTRANSITIONAL, 1);

    puts("\n== to_unicode_8z8z NONTRANSITIONAL");
    for (int i = 0; cases[i]; i++) {
        char *out = NULL;
        int rc = idn2_to_unicode_8z8z(cases[i], &out, IDN2_NONTRANSITIONAL);
        if (rc == IDN2_OK && out)
            printf("%-4s %-28s -> %s\n", "uni", cases[i], out);
        else
            printf("%-4s %-28s -> rc=%d (%s)\n", "uni", cases[i], rc,
                   rcname(rc));
        if (out) idn2_free(out);
    }

    puts("\n== to_unicode_8zlz NONTRANSITIONAL (dig path, locale set)");
    for (int i = 0; cases[i]; i++) {
        char *out = NULL;
        int rc = idn2_to_unicode_8zlz(cases[i], &out, IDN2_NONTRANSITIONAL);
        if (rc == IDN2_OK && out)
            printf("%-4s %-28s -> %s\n", "unil", cases[i], out);
        else
            printf("%-4s %-28s -> rc=%d (%s)\n", "unil", cases[i], rc,
                   rcname(rc));
        if (out) idn2_free(out);
    }

    /* Isolate the TR46 layer: IDN2_NO_TR46 runs pure IDNA2008 (no mapping). */
    puts("\n== NO_TR46 NONTRANSITIONAL (pure IDNA2008)");
    for (int i = 0; cases[i]; i++)
        probe("no46", cases[i], IDN2_NONTRANSITIONAL | IDN2_NO_TR46, 0);

    puts("\n== NO_TR46 TRANSITIONAL (pure IDNA2008)");
    for (int i = 0; cases[i]; i++)
        probe("no46t", cases[i], IDN2_TRANSITIONAL | IDN2_NO_TR46, 0);
    return 0;
}

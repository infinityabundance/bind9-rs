#!/usr/bin/env python3
"""generate-corpus.py — TABLES-0001 court corpus.

One `<cmd> <arg>` line per input line, covering the BIND 9.20.26
rcode/tsigrcode/type/class tables: `dns_rcode_totext/fromtext`,
`dns_tsigrcode_totext/fromtext`, `dns_rdatatype_totext/fromtext` with the
ismeta/issingleton/isknown predicates, and `dns_rdataclass_totext/fromtext`.

Deterministic.
"""

cases = []

# --- rcode-totext ----------------------------------------------------------
for n in list(range(0, 26)) + [30, 100, 255, 256, 4095, 65535]:
    cases.append(f"rcode-totext {n}")

# --- rcode-fromtext --------------------------------------------------------
for tok in [
    "NOERROR", "noerror", "NoError", "FORMERR", "SERVFAIL", "NXDOMAIN",
    "NOTIMP", "REFUSED", "YXDOMAIN", "YXRRSET", "NXRRSET", "NOTAUTH",
    "NOTZONE", "BADVERS", "badvers", "BADCOOKIE", "badcookie",
    "RESERVED11", "RESERVED12", "RESERVED15", "DSOTYPENI", "BADSIG",
    "BADKEY", "BADTIME", "NOSUCH", "",
    "0", "1", "12", "16", "17", "23", "65535", "65536", "9999999999999",
    "012", "12x", "+12", "-1", " 12", "1 2",
]:
    cases.append(f"rcode-fromtext {tok}")

# --- tsigrcode-totext ------------------------------------------------------
for n in list(range(0, 26)) + [30, 100, 65535]:
    cases.append(f"tsigrcode-totext {n}")

# --- tsigrcode-fromtext ----------------------------------------------------
for tok in [
    "NOERROR", "BADSIG", "badsig", "BADKEY", "BADTIME", "BADMODE", "BADNAME",
    "BADALG", "BADTRUNC", "BADVERS", "BADCOOKIE", "RESERVED11", "YXDOMAIN",
    "0", "16", "22", "23", "65535", "65536", "badjunk",
]:
    cases.append(f"tsigrcode-fromtext {tok}")

# --- type-totext -----------------------------------------------------------
types = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
         19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
         36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
         53, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68,
         99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109,
         128, 200, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259,
         260, 261, 262, 300, 1000, 32768, 32769, 65533, 65534, 65535]
for t in types:
    cases.append(f"type-totext {t}")

# --- type-fromtext ---------------------------------------------------------
for tok in [
    "A", "a", "NS", "ns", "MD", "MF", "CNAME", "cname", "SOA", "MB", "MG",
    "MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT", "RP",
    "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP-PTR", "SIG", "KEY", "PX",
    "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC", "SRV", "ATMA", "NAPTR",
    "KX", "CERT", "A6", "DNAME", "SINK", "OPT", "APL", "DS", "SSHFP",
    "IPSECKEY", "RRSIG", "NSEC", "DNSKEY", "DHCID", "NSEC3", "NSEC3PARAM",
    "TLSA", "SMIMEA", "HIP", "NINFO", "RKEY", "TALINK", "CDS", "CDNSKEY",
    "OPENPGPKEY", "CSYNC", "ZONEMD", "SVCB", "HTTPS", "DSYNC", "HHIT",
    "BRID", "SPF", "UINFO", "UID", "GID", "UNSPEC", "NID", "L32", "L64",
    "LP", "EUI48", "EUI64", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB",
    "MAILA", "ANY", "URI", "CAA", "AVC", "DOA", "AMTRELAY", "RESINFO",
    "WALLET", "TA", "DLV", "KEYDATA", "RESERVED0",
    "TYPE0", "TYPE1", "TYPE41", "TYPE255", "TYPE65533", "TYPE65535",
    "TYPE65536", "TYPEabc", "TYPE", "TYPE+1", "TYPE-1", "TYPE 1",
    "type12", "tYpE28", "12", "A1", "NOTHING", "",
]:
    cases.append(f"type-fromtext {tok}")

# --- predicates ------------------------------------------------------------
pred_types = types + [54, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80,
                      81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93,
                      94, 95, 96, 97, 98, 110, 111, 112, 113, 114, 115, 116,
                      117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
                      128, 129, 130, 200, 248, 249, 250, 251, 252, 253, 254,
                      255, 263, 264, 32770, 32771, 65532, 65534]
for t in pred_types:
    cases.append(f"type-ismeta {t}")
    cases.append(f"type-issingleton {t}")
    cases.append(f"type-isknown {t}")

# --- class-totext ----------------------------------------------------------
for n in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 254, 255, 1000, 65535]:
    cases.append(f"class-totext {n}")

# --- class-fromtext --------------------------------------------------------
for tok in [
    "IN", "in", "CH", "ch", "CHAOS", "chaos", "HS", "hs", "HESIOD", "hesiod",
    "NONE", "none", "ANY", "any", "RESERVED0", "reserved0",
    "CLASS0", "CLASS1", "CLASS254", "CLASS255", "CLASS65535", "CLASS65536",
    "CLASSabc", "CLASS", "CLASS+1", "CLASS-1", "CLASS 1", "class12",
    "INX", "NO", "",
]:
    cases.append(f"class-fromtext {tok}")

print("\n".join(cases))

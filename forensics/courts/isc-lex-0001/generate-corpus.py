#!/usr/bin/env python3
"""generate-corpus.py — ISC-LEX-0001 court corpus.

One `<cmd> <base64>` line per input, covering `isc_lex_gettoken` and
`isc_lex_getmastertoken` semantics with the masterfile specials and
DNSMASTERFILE comments: tokens, quoted strings, numbers (incl. overflow and
junk-suffix fallback), comments, parens/multiline, escapes, EOL/EOF,
unterminated quotes, unbalanced parens, trailing backslash, CRLF, NUL, and
empty input.  Deterministic.
"""

import base64

cases = []


def add(cmd, data):
    if isinstance(data, str):
        data = data.encode()
    cases.append(f"{cmd} {base64.b64encode(data).decode()}")


# --- lex mode: full tokenizer ----------------------------------------------
add("lex", "")
add("lex", " ")
add("lex", "\n")
add("lex", "www example.com 3600 IN A 192.0.2.1\n")
add("lex", "a\tb\n")
add("lex", "a\r\nb\r\n")
add("lex", "one 2 three 42x 123abc 99999999999999999\n")
add("lex", "4294967295 4294967296\n")
add("lex", 'a "quoted string" b\n')
add("lex", '"hello \\" world"\n')
add("lex", '"unterminated')
add("lex", "a\\;b c\\(d\\)e\n")
add("lex", "trailing\\")
add("lex", "a\\ b\n")
add("lex", "; only a comment\nnext\n")
add("lex", "before ; comment\n")
add("lex", "a (\n  b\n  c\n) d\n")
add("lex", "a (( b ) c ) d\n")
add("lex", "a ( b\n")
add("lex", "a ) b\n")
add("lex", "a (b)\n")
add("lex", 'a ("q") b\n')
add("lex", "(")
add("lex", ")")
add("lex", "x\x00y\n")
add("lex", '"a\x00b"\n')
add("lex", "\\\n")
add("lex", "a\\\nb\n")
add("lex", " a\n")
add("lex", "  leading spaces\n")
add("lex", "multi\nline\ninput\n")
add("lex", "token()parens\n")
add("lex", '"just-quote"')
add("lex", '""')
add("lex", '"a"b\n')
add("lex", "a\"b\n")
add("lex", "\\\"")
add("lex", "(a\nb)\n")
add("lex", "(\n\na\n\n)\n")
add("lex", "a(b)c\n")
add("lex", "1\n2\n3\n")
add("lex", "0123 007\n")
add("lex", "0x10\n")
add("lex", ";;; comment with ( parens ;;;\nz\n")
add("lex", "a ; comment \"quote\" (paren\nb\n")
add("lex", "\t\n")
add("lex", "\r\n")
add("lex", "\r")
add("lex", "a\rb\n")
add("lex", '"multi\nline\nstring"\n')
add("lex", 'q"uote "inside"\n')
add("lex", "\\\\n\\n\n")
add("lex", "space\\ end\n")
add("lex", "\n\n\n")
add("lex", ";;\n;;\n\n")
add("lex", "()")
add("lex", "((()))\n")
add("lex", "b\\)\n")
add("lex", "x\\ty\n")
add("lex", "\x01\x02\x03\n")

# --- master mode: getmastertoken(STRING, eol=true) -------------------------
add("master", "www example.com 3600 IN A\n")
add("master", "one\n")
add("master", "one two\n")
add("master", '"quoted" next\n')
add("master", "123 number-string\n")
add("master", "42x\n")
add("master", "; comment\n")
add("master", "a (\n  b\n) c\n")
add("master", "a ( b\n")
add("master", "a ) b\n")
add("master", "a\\(b\\) c\n")
add("master", "unterminated\\")
add("master", '"unterminated')
add("master", "a\nb\n")
add("master", "trailing comment ; x\n")
add("master", "")
add("master", "\n")
add("master", "   \n")
add("master", "a\r\nb\n")
add("master", "x\x00y\n")
add("master", "a\\;b\n")
add("master", "\"\"\n")
add("master", "\\\"")
add("master", "()")
add("master", "(\n)\n")
add("master", "a (\"q\")\nb\n")

print("\n".join(cases))

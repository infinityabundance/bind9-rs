#!/bin/sh
# build-utility-index.sh — generate the evidence-derived BIND 9 utility
# history (addendum §2, §8, §59; manifest.rs contract).
#
# For every BIND 9 release line, downloads the last release (plus the first
# releases of the earliest lines), records provenance (URL + sha256), extracts
# only the `bin/` tree, enumerates the shipped executables, and writes:
#
#   bind9-rs-tools/forensics/atlas/utility-history.json
#
# The utility set is derived from the build definitions (Makefile.in
# PROGRAMS/targets) and from every `main(` in bin/**/*.c — never from a
# hand-maintained list (addendum §59: "Generate a utility history rather than
# maintaining one manually").
#
# Usage: scripts/archaeology/build-utility-index.sh

set -eu

REPO_ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SRC="$REPO_ROOT/bind9-rs-tools/forensics/sources"
WORK="$REPO_ROOT/bind9-rs-tools/forensics/oracle/work/historical"
OUT="$REPO_ROOT/bind9-rs-tools/forensics/atlas/utility-history.json"
BASE="https://downloads.isc.org/isc/bind9"

mkdir -p "$SRC" "$WORK"

# Last release of every line (from the ISC index; 9.20.26 exists locally).
VERSIONS="9.0.1 9.1.3 9.2.9 9.3.6 9.4.3 9.5.2-P4 9.6.3 9.7.7 9.8.8 9.9.13 \
9.10.8 9.11.37 9.12.4 9.13.7 9.14.12 9.15.8 9.16.50 9.17.22 9.18.50 \
9.19.24 9.20.26 9.21.24"

HASHES="" # "version url sha256" triples
UTIL_JSON="{}" # version -> { url, sha256, utilities: [...] }

for v in $VERSIONS; do
    # Locate the local 9.20.26 tarball if requested.
    if [ "$v" = "9.20.26" ]; then
        local_tar="$REPO_ROOT/forensics/sources/bind-9.20.26.tar.xz"
        if [ -f "$local_tar" ]; then
            sha=$(sha256sum "$local_tar" | cut -d' ' -f1)
            url="$BASE/9.20.26/bind-9.20.26.tar.xz"
            echo "9.20.26: using local tarball ($sha)"
            # Extract bin/ from the local tarball into the historical workdir.
            mkdir -p "$WORK/9.20.26"
            tar -xf "$local_tar" -C "$WORK/9.20.26" --strip-components=1 \
                --wildcards '*/bin/*' '*/meson.build' 2>/dev/null || true
            HASHES="$HASHES
9.20.26 $url $sha"
            continue
        fi
    fi

    tar=""
    for ext in tar.xz tar.gz; do
        if [ -f "$SRC/bind-$v.$ext" ]; then
            tar="$SRC/bind-$v.$ext"
            break
        fi
    done
    if [ -z "$tar" ]; then
        # Try .tar.xz first, then .tar.gz (old releases are gzip).
        if curl -fsSL -o "$SRC/bind-$v.tar.xz" "$BASE/$v/bind-$v.tar.xz"; then
            tar="$SRC/bind-$v.tar.xz"
        elif curl -fsSL -o "$SRC/bind-$v.tar.gz" "$BASE/$v/bind-$v.tar.gz"; then
            tar="$SRC/bind-$v.tar.gz"
        else
            echo "warning: could not download $v" >&2
            continue
        fi
    fi
    sha=$(sha256sum "$tar" | cut -d' ' -f1)
    ext=$(basename "$tar" | sed 's/.*\.//')
    url="$BASE/$v/bind-$v.$ext"
    echo "$v: $tar ($sha)"

    rm -rf "$WORK/$v"
    mkdir -p "$WORK/$v"
    # Extract only bin/ plus the root meson.build (meson-era alias
    # `install_symlink` rules live at the root; source trees are small).
    tar -xf "$tar" -C "$WORK/$v" --strip-components=1 \
        --wildcards '*/bin/*' '*/meson.build' 2>/dev/null || true
    HASHES="$HASHES
$v $url $sha"
done

# --- enumerate binaries per release from the extracted bin/ trees ----------
python3 - "$WORK" "$HASHES" "$OUT" << 'PYEOF'
import json
import os
import re
import sys

work, hashes_text, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

releases = {}
for line in hashes_text.strip().splitlines():
    parts = line.split()
    if len(parts) == 3:
        releases[parts[0]] = {"url": parts[1], "sha256": parts[2]}

MAIN_RE = re.compile(r"\bmain\s*\(\s*(?:int\s+argc|void|int\s+argc)?")


def binaries_for(version):
    """Enumerate executable names shipped in bin/ of an extracted tree.

    Era-aware build-definition archaeology:
    - 9.0 .. 9.19: `TARGETS = a b \\` continuation lists (strip `@EXEEXT@`)
    - 9.17 .. 9.19: automake `bin_PROGRAMS`/`sbin_PROGRAMS`
    - 9.21+ (meson): `<name>_src`/`<name>_srcset` variable names in per-dir
      meson.build
    - aliases: `ln ... <alias>` in `install-exec-hook:` rules (e.g.
      `named-compilezone` is a hard link of `named-checkzone`)
    - fallback: a `main(` in any *.c inside the tool directory
    Excluded: bin/tests, bin/plugins (shared modules, not CLI tools),
    bin/include, Makefile*/meson plumbing, build/test targets.
    """
    root = os.path.join(work, version, "bin")
    if not os.path.isdir(root):
        return [], {}
    names = set()
    aliases = {}  # alias -> target
    for tool_dir in sorted(os.listdir(root)):
        d = os.path.join(root, tool_dir)
        if not os.path.isdir(d) or tool_dir in ("tests", "plugins", "include"):
            continue

        def read(name):
            try:
                return open(os.path.join(d, name), encoding="utf-8",
                            errors="replace").read()
            except OSError:
                return ""

        mf = read("Makefile.in") + "\n" + read("Makefile.am")
        dir_names = set()
        if mf.strip():
            text = mf
            # TARGETS / bin_PROGRAMS / sbin_PROGRAMS with backslash
            # continuations.
            for var in ("TARGETS", "bin_PROGRAMS", "sbin_PROGRAMS",
                        "libexec_PROGRAMS"):
                joined = ""
                for line in text.splitlines():
                    if joined:
                        joined += " " + line.lstrip()
                    elif re.match(rf"^{var}\s*=", line):
                        joined = line
                    if joined and joined.rstrip().endswith("\\"):
                        continue
                    if joined:
                        val = re.sub(rf"^{var}\s*=\s*", "", joined)
                        for tok in val.split():
                            tok = tok.replace("$(EXEEXT)", "").replace("@EXEEXT@", "")
                            if tok and not tok.startswith("$") and "@" not in tok:
                                dir_names.add(tok)
                        joined = ""
            # Aliases from install rules.  Three build eras with distinct
            # mechanisms (the direction can even flip between eras, e.g.
            # tsig-keygen was the link of ddns-confgen in 9.10..9.16 and the
            # target from 9.17 on):
            #
            # 1. automake install rule era (~9.4..9.16):
            #      (cd ${DESTDIR}${sbindir}; rm -f <alias>@EXEEXT@;
            #       ${LINK_PROGRAM} <target>@EXEEXT@ <alias>@EXEEXT@)
            #    i.e. `LINK_PROGRAM TARGET ALIAS` installs ALIAS as a link to
            #    TARGET; the man-page variant (name.8) is filtered below.
            # 2. automake install-exec-hook era (9.17..9.20):
            #      ln -f $(DESTDIR)$(bindir)/<target> \
            #            $(DESTDIR)$(bindir)/<alias>
            # 3. meson era (9.21+): `install_symlink('<alias>',
            #    pointing_to: '<target>', ...)` in the ROOT meson.build.
            linkprog_re = re.compile(
                r"rm -f\s+([A-Za-z0-9_.-]+)(?:@EXEEXT@|\$\(EXEEXT\))?\s*;\s*"
                r"\$\{LINK_PROGRAM\}\s+([A-Za-z0-9_.-]+)(?:@EXEEXT@|\$\(EXEEXT\))?\s+"
                r"([A-Za-z0-9_.-]+)(?:@EXEEXT@|\$\(EXEEXT\))?"
            )
            for m in linkprog_re.finditer(text):
                aliases[m.group(3)] = m.group(2)
            path_tok = re.compile(
                r"\$(?:\(DESTDIR\))?\$\{?\(?(?:bin|sbin)dir\)?\}?/([^\s\\$]+)"
            )
            lines = text.splitlines()
            for i, ln in enumerate(lines):
                if not re.match(r"^[ \t]*ln -f\b", ln):
                    continue
                block = ln
                j = i + 1
                while j < len(lines) and block.rstrip().endswith("\\"):
                    block += " " + lines[j].lstrip()
                    j += 1
                toks = [t.replace("$(EXEEXT)", "")
                        for t in path_tok.findall(block)]
                if len(toks) >= 2:
                    aliases[toks[-1]] = toks[0]
        else:
            # Meson era: `<name>_src += ...` / `<name>_srcset.add(...)`;
            # aliases via `install_symlink` in the ROOT meson.build.
            mb = read("meson.build")
            for m in re.finditer(
                r"^([a-zA-Z0-9_]+)_src(?:set)?\s*(?:\+?=|\.add\(|\+\.add\()",
                mb,
                re.M,
            ):
                dir_names.add(m.group(1).replace("_", "-"))
            root_mb = ""
            try:
                root_mb = open(
                    os.path.join(work, version, "meson.build"),
                    encoding="utf-8", errors="replace",
                ).read()
            except OSError:
                pass
            for m in re.finditer(
                r"install_symlink\(\s*'([^']+)'\s*,\s*pointing_to:\s*'([^']+)'",
                root_mb,
            ):
                aliases[m.group(1)] = m.group(2)

        names.update(dir_names)
        # The main() scan is a UNION, not a fallback: conditionally built
        # tools (guarded by @VAR@ in TARGETS, e.g. dnstap-read behind
        # @DNSTAP_TARGETS@, named-nzd2nzf behind LMDB) appear in the source
        # but not in the unconditional TARGETS list.
        for f in sorted(os.listdir(d)):
            if f.endswith(".c") and MAIN_RE.search(read(f)):
                names.add(f[: -2])

    junk = {"tests", "Makefile", "Makefile.in", "Makefile.am", "meson",
            "tags", "unit", "test", "install", "uninstall", "check",
            "clean", "all", "dist", "mostlyclean", "realclean", "main",
            "xsl.c", "manrst", "manrst_srcset", "named_srcset",
            "named_inc_p"}
    names = {n for n in names
             if n not in junk and "." not in n and "@" not in n and n != "\\"}
    aliases = {a: t for a, t in aliases.items()
               if a not in junk and "@" not in a and "." not in a
               and "@" not in t and "." not in t}
    return sorted(names), aliases


def vkey(s):
    """Version sort key; handles patch suffixes like 9.5.2-P4."""
    return [int(x) for x in s.split("-")[0].split(".")]


history = {}
for v in sorted(releases, key=vkey):
    bins, aliases = binaries_for(v)
    history[v] = {"utilities": bins, "aliases": aliases}
    releases[v]["utilities"] = bins
    releases[v]["aliases"] = aliases

# Per-utility first/last known across the sampled lines.
all_utils = sorted({u for r in releases.values() for u in r["utilities"]})
all_aliases = sorted({a for r in releases.values() for a in r.get("aliases", {})})
utilities = {}
for u in all_utils + all_aliases:
    present = [v for v in sorted(releases, key=vkey)
               if u in releases[v]["utilities"]]
    # Aliases count as present too (the name is observable on disk).
    for v in releases:
        if u in releases[v].get("aliases", {}) and v not in present:
            present.append(v)
    present.sort(key=vkey)
    utilities[u] = {
        "first_known": present[0] if present else None,
        "last_known": present[-1] if present else None,
        "sampled_present_in": present,
        "sampled_absent_in": [
            v for v in sorted(releases, key=vkey)
            if u not in present
        ],
        "alias_of": next(
            (releases[v]["aliases"][u] for v in releases if u in releases[v].get("aliases", {})),
            None,
        ),
        # Direction of the alias link can flip between eras (e.g.
        # tsig-keygen <=> ddns-confgen in 9.17).  Keep the per-version map
        # so the flip is evidence, not a contradiction.
        "alias_history": {
            v: releases[v]["aliases"][u]
            for v in sorted(releases, key=vkey)
            if u in releases[v].get("aliases", {})
        },
    }

doc = {
    "schema_version": 1,
    "generated_at": "2026-08-16T00:00:00Z",
    "method": "bin/ build-definition archaeology: Makefile.in PROGRAMS/targets + main() in bin/**/*.c + install-rule alias scan (${LINK_PROGRAM} ~9.4..9.16, ln -f 9.17..9.20, meson install_symlink 9.21+); one sample per release line (last of line) + 9.20.26 local",
    "sampled_releases": releases,
    "utilities": utilities,
}
with open(out_path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)

print(f"utility history: {len(all_utils)} utilities across {len(releases)} releases")
for u in sorted(utilities):
    print(f"  {u:<28} {utilities[u]['first_known'] or '-':<8} -> {utilities[u]['last_known'] or '-'}")
PYEOF

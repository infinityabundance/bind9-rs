#!/usr/bin/env python3
"""parse-doxygen-xml.py — turn the Doxygen XML of a pinned BIND tree into
per-library JSON inventories for the custodian archive (spec §70, §71).

Usage: parse-doxygen-xml.py <xml-dir> <out-dir> <version>

Each library/tool directory (lib/isc, lib/dns, lib/isccfg, lib/ns, lib/irs,
bin/*, fuzz/*) becomes one JSON inventory file:

    {
      "schema_version": 1,
      "version": "9.20.26",
      "library": "lib/dns",
      "sources_generated_at": "...",
      "files": { "<path>": {
           "functions": [ { "name": ..., "static": bool, "definition": "...",
                            "brief": "...", "detailed": "...", "params": [...] } ],
           "typedefs": [...],
           "enums": [...],
           "structs": [...],
           "macros": [...],
           "variables": [...]
      } }
    }

The inventory is the completeness checklist: the coverage ledger
(forensics/archaeology/api-atlas/COVERAGE.md and api-coverage.json) tracks
each surface to archaeology records, courts and Rust modules.

Only the Python standard library is used (xml.etree), so the parser has no
supply chain of its own.
"""

import json
import os
import sys
import xml.etree.ElementTree as ET

SCHEMA_VERSION = 1

# Doxygen >= 1.16 emits namespace-less XML; older versions use the manual
# namespace.  Strip any `{...}` prefix so both parse identically.


def tag(el):
    t = el.tag
    if isinstance(t, str) and t.startswith("{") and "}" in t:
        return t.split("}", 1)[1]
    return t


def children(el, name):
    return [c for c in el if tag(c) == name]


def child(el, name):
    for c in el:
        if tag(c) == name:
            return c
    return None


def text_of(el):
    if el is None:
        return ""
    parts = []
    for node in el.iter():
        t = tag(node)
        if t == "para":
            parts.append("".join(node.itertext()))
        elif t == "linebreak":
            parts.append("\n")
    if not parts:
        return "".join(el.itertext())
    return "\n".join(parts).strip()


def member_kind(el):
    return el.get("kind", "")


def def_of(el):
    for c in el:
        if tag(c) == "definition":
            return "".join(c.itertext()).strip()
    return ""


def args_of(el):
    for c in el:
        if tag(c) == "argsstring":
            return "".join(c.itertext()).strip()
    return ""


def is_static(el):
    return def_of(el).startswith("static")


def parse_compound(path):
    """Parse one compound XML file (a header/class/file)."""
    tree = ET.parse(path)
    root = tree.getroot()
    result = {
        "functions": [],
        "typedefs": [],
        "enums": [],
        "structs": [],
        "macros": [],
        "variables": [],
    }
    for member in root.iter():
        if tag(member) != "memberdef":
            continue
        kind = member_kind(member)
        name = ""
        for c in member:
            if tag(c) == "name":
                name = "".join(c.itertext()).strip()
        brief = text_of(child(member, "briefdescription"))
        detailed = text_of(child(member, "detaileddescription"))
        entry = {
            "name": name,
            "static": is_static(member),
            "definition": def_of(member),
            "args": args_of(member),
            "brief": brief,
            "detailed": detailed,
        }
        params = []
        for p in member.iter():
            if tag(p) == "param":
                pname = ""
                for c in p:
                    if tag(c) == "declname":
                        pname = "".join(c.itertext()).strip()
                params.append(pname)
        entry["params"] = params
        if kind == "function":
            result["functions"].append(entry)
        elif kind == "typedef":
            result["typedefs"].append(entry)
        elif kind == "enum":
            result["enums"].append(entry)
        elif kind in ("struct", "union"):
            result["structs"].append(entry)
        elif kind == "define":
            result["macros"].append(entry)
        elif kind == "variable":
            result["variables"].append(entry)
    return result


def library_of(path):
    """Map a source path to its library/tool unit."""
    for prefix in ("lib/", "bin/", "fuzz/"):
        if path.startswith(prefix):
            rest = path[len(prefix):]
            return prefix + rest.split("/")[0]
    return path.split("/")[0]


def main():
    if len(sys.argv) != 4:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    xml_dir, out_dir, version = sys.argv[1], sys.argv[2], sys.argv[3]

    inventories = {}
    for fname in sorted(os.listdir(xml_dir)):
        if not fname.endswith(".xml") or fname.startswith("dir_") or fname.startswith("globals"):
            continue
        path = os.path.join(xml_dir, fname)
        tree = ET.parse(path)
        root = tree.getroot()
        compound = None
        for c in root:
            if tag(c) == "compounddef":
                compound = c
                break
        if compound is None:
            continue
        kind = compound.get("kind")
        if kind not in ("file", "class", "struct", "union", "namespace"):
            continue
        location = child(compound, "location")
        if location is None:
            continue
        srcfile = location.get("file", "")
        if not srcfile.endswith((".c", ".h")):
            continue
        lib = library_of(srcfile)
        data = parse_compound(path)
        inv = inventories.setdefault(
            lib,
            {
                "schema_version": SCHEMA_VERSION,
                "version": version,
                "library": lib,
                "files": {},
            },
        )
        inv["files"][srcfile] = data

    os.makedirs(out_dir, exist_ok=True)
    for lib, inv in sorted(inventories.items()):
        safe = lib.replace("/", "_")
        out = os.path.join(out_dir, f"{safe}.json")
        with open(out, "w") as f:
            json.dump(inv, f, indent=2, sort_keys=True)
        nfiles = len(inv["files"])
        nfuncs = sum(len(f["functions"]) for f in inv["files"].values())
        print(f"{lib}: {nfiles} files, {nfuncs} functions -> {os.path.basename(out)}")

    # Totals manifest.
    totals = {
        "schema_version": SCHEMA_VERSION,
        "version": version,
        "libraries": sorted(inventories),
        "file_count": sum(len(i["files"]) for i in inventories.values()),
        "function_count": sum(
            len(f["functions"]) for i in inventories.values() for f in i["files"].values()
        ),
    }
    with open(os.path.join(out_dir, "totals.json"), "w") as f:
        json.dump(totals, f, indent=2, sort_keys=True)
    print(f"TOTAL: {totals['file_count']} files, {totals['function_count']} functions")


if __name__ == "__main__":
    main()

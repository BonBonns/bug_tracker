#!/usr/bin/env python3
"""R05 "New"-gate classification study: classifies every real `New`-named call in
`new_named_calls_extract.json` (extracted from a real c2cpg run over each package's own real
tarball -- see this study's own README.md for exactly how) by the same UNRESOLVED_MFN_PREFIX/
UNRESOLVED_SIG_MARKER shape check R05 itself uses, then by the literal qualifier text written
in the call's own real `code` field (the only way to classify an UNRESOLVED-shape call at all,
since c2cpg itself could not resolve its qualifier structurally).

Run: python3 classify.py   (reproduces every count in README.md's own tables)
"""
import json
import re
from collections import Counter

UNRESOLVED_PREFIX = "<unresolvedNamespace>."
UNRESOLVED_SIG = ":<unresolvedSignature>("
QUALIFIER_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_:<>,\s]*?)::New\s*[<(]")


def classify_package(rows):
    unresolved = [r for r in rows if r["mfn"].startswith(UNRESOLVED_PREFIX)
                  and UNRESOLVED_SIG in r["mfn"]]
    other = [r for r in rows if r not in unresolved]

    unresolved_classes = Counter()
    for r in unresolved:
        m = QUALIFIER_RE.search(r["code"])
        if m:
            q = re.sub(r"<[^>]*>", "<T>", m.group(1).strip())
        else:
            q = "UNPARSED"
        unresolved_classes[q] += 1

    other_classes = Counter()
    for r in other:
        base = re.sub(r":.*$", "", r["mfn"])
        other_classes[base] += 1

    return {"total": len(rows), "unresolved_shape": len(unresolved),
            "other_shape": len(other), "unresolved_classes": dict(unresolved_classes),
            "other_classes": dict(other_classes)}


def main():
    data = json.load(open("new_named_calls_extract.json"))
    for pkg, rows in data.items():
        print(f"\n=== {pkg} ({len(rows)} real 'New'-named calls) ===")
        result = classify_package(rows)
        print(f"  unresolved-shape (R05 recovery-attempted): {result['unresolved_shape']}")
        for cls, n in sorted(result["unresolved_classes"].items(), key=lambda x: -x[1]):
            print(f"    {cls}: {n}")
        print(f"  other/resolved shape (not even recovery-attempted): {result['other_shape']}")
        for cls, n in sorted(result["other_classes"].items(), key=lambda x: -x[1]):
            print(f"    {cls}: {n}")


if __name__ == "__main__":
    main()

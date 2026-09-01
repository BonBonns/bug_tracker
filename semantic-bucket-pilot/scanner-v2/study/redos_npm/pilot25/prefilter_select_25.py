#!/usr/bin/env python3
"""REDOS-PILOT25-R01: deterministic, pre-registered selection of 25 packages from the project's
own frozen corpus (npm_corpus/eligible_packages.tsv, 494 packages, its own row order) for the
ReDoS discovery pilot -- built and run BEFORE any package-level Joern scan, so selection cannot
be influenced by seeing results (the whole point of "freeze a deterministic npm discovery sample
before viewing results... don't continue selecting packages manually one at a time").

Cheap, source-text-only prefilter (no Joern, no CPG) per direct instruction, requiring ALL three:
  1. at least one exported-function-shaped statement (module.exports=/module.exports.NAME=/
     exports.NAME=/export function/export default/export const NAME = (...) =>)
  2. at least one regex literal
  3. among those regex literals, at least one matches the FROZEN Stage 2 classifier's own
     DANGEROUS structural shape -- reimplemented here in Python, function-for-function, from
     export_redos_npm_integ.sc's own frozen classifyPattern()/NESTED_QUANTIFIER/
     splitTopLevelAlternation/hasQuantifierFollowedByMoreContent, NEVER a separate or looser
     heuristic. This is a cheap TEXT-level proxy for what the real Joern-based Stage 1 (pattern
     resolution) + Stage 2 (classification) would confirm -- it can overcount (a regex literal
     that's actually dead code, or whose real resolved reachability turns out unreachable) but
     must never undercount a package the real pipeline would flag, so it deliberately treats
     ANY textually-DANGEROUS-shaped regex literal as a hit, with no reachability reasoning at
     this stage (that is what the real Joern pipeline, run only over the 25 SELECTED packages,
     is for).

Score = count of DANGEROUS-shaped regex literals ("supported-sink count", direct instruction's
own term) in that package's own .js/.ts source (excluding node_modules/, test/, .min.js). Ranks
descending by score; ties broken by eligible_packages.tsv's own row order (ascending row index --
"frozen corpus order"), never randomly and never by any later-known outcome.

Output: pilot25_selection.json, written and committed BEFORE any package in it is scanned by the
real Joern pipeline -- the pre-registration artifact.
"""
import io
import json
import os
import re
import sys
import tarfile
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ELIGIBLE_TSV = os.path.join(HERE, "..", "..", "..", "npm_corpus", "eligible_packages.tsv")
N_SELECT = 25
PER_PACKAGE_TIMEOUT = 30

EXPORT_PATTERNS = [
    re.compile(r"module\.exports\s*="),
    re.compile(r"module\.exports\.\w+\s*="),
    re.compile(r"exports\.\w+\s*="),
    re.compile(r"exports\[[\"']\w+[\"']\]\s*="),
    re.compile(r"\bexport\s+function\b"),
    re.compile(r"\bexport\s+default\b"),
    re.compile(r"\bexport\s+const\s+\w+\s*="),
    re.compile(r"\bexport\s*\{"),
]

# a regex-literal scanner tolerant of the common false-match risk (division) by requiring the
# literal to follow one of the syntactic positions a regex literal can actually appear in JS.
REGEX_LITERAL = re.compile(
    r"(?:^|[=(,:\[!&|?;]|\breturn\b|\btest\b|\bexec\b|\bmatch\b|\bsearch\b|\breplace\b)\s*"
    r"/((?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+)/([a-z]*)"
)

# ===== FAITHFUL reimplementation of the frozen Stage 2 classifier (export_redos_npm_integ.sc) =====
NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)[+*]")


def split_top_level_alternation(body):
    branches, current, depth, in_class, i = [], [], 0, False, 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            current.append(ch); current.append(body[i + 1]); i += 2; continue
        if ch == "[" and not in_class:
            in_class = True
        elif ch == "]" and in_class:
            in_class = False
        elif ch == "(" and not in_class:
            depth += 1
        elif ch == ")" and not in_class:
            depth -= 1
        if ch == "|" and depth == 0 and not in_class:
            branches.append("".join(current)); current = []
        else:
            current.append(ch)
        i += 1
    branches.append("".join(current))
    return branches


NEGATED_CLASS_THEN_EXCLUDED_LITERAL = re.compile(r"\[\^([^\]]+)\][+*](.)")
NEGATED_CLASS_THEN_NEGATED_CLASS = re.compile(r"\[\^[^\]]+\][+*]\[\^[^\]]+\][?+*]?")


def is_safe_negated_class_shape(branch):
    literal_matches = list(NEGATED_CLASS_THEN_EXCLUDED_LITERAL.finditer(branch))
    literal_case = bool(literal_matches) and all(m.group(2) in m.group(1) for m in literal_matches)
    consecutive_class_case = NEGATED_CLASS_THEN_NEGATED_CLASS.search(branch) is not None
    return literal_case or consecutive_class_case


def has_quantifier_followed_by_more_content(branch):
    stripped = branch[:-1] if branch.endswith("$") else branch
    has_shape = (re.search(r"[+*][^$]", stripped) is not None) and not re.match(r".*[+*]$", stripped)
    return has_shape and not is_safe_negated_class_shape(stripped)


DELIMITED_NESTED_GROUP = re.compile(r"\(\\(.)([^()]*)\)[+*]")


def is_safe_prefix_delimited_nested_quantifier(text):
    ms = list(DELIMITED_NESTED_GROUP.finditer(text))
    return bool(ms) and all(m.group(1) not in m.group(2) for m in ms)


SUFFIX_DELIMITED_GROUP = re.compile(r"\(\??:?\[([^\]]+)\][+*]\\(.)\)[+*]")


def is_safe_suffix_delimited_nested_quantifier(text):
    ms = list(SUFFIX_DELIMITED_GROUP.finditer(text))
    return bool(ms) and all(m.group(2) not in m.group(1) for m in ms)


def is_safe_delimited_nested_quantifier(text):
    return (is_safe_prefix_delimited_nested_quantifier(text) or
            is_safe_suffix_delimited_nested_quantifier(text))


def classify_dangerous(body):
    """Returns True iff this pattern BODY (no delimiters/flags) matches the frozen classifier's
    own DANGEROUS shape. Anchored-SAFE/UNKNOWN distinction is irrelevant to the prefilter -- only
    DANGEROUS drives the score, exactly matching what the real pipeline promotes to a candidate."""
    if NESTED_QUANTIFIER.search(body) and not is_safe_delimited_nested_quantifier(body):
        return True
    branches = split_top_level_alternation(body)
    if len(branches) > 1:
        if any(has_quantifier_followed_by_more_content(b) for b in branches):
            return True
    return False


def score_source_text(text):
    has_export = any(p.search(text) for p in EXPORT_PATTERNS)
    n_regex_literals = 0
    n_dangerous = 0
    for m in REGEX_LITERAL.finditer(text):
        n_regex_literals += 1
        body = m.group(1)
        if classify_dangerous(body):
            n_dangerous += 1
    return has_export, n_regex_literals, n_dangerous


def iter_js_ts_members(tarball_bytes):
    with tarfile.open(fileobj=io.BytesIO(tarball_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if not (name.endswith(".js") or name.endswith(".ts") or name.endswith(".mjs") or
                     name.endswith(".cjs")):
                continue
            if "node_modules/" in name or "/test/" in name or "/tests/" in name or \
                    name.endswith(".min.js") or "/dist/" in name and name.endswith(".min.js"):
                continue
            if member.size > 2_000_000:  # skip pathological single files, cheap prefilter only
                continue
            f = tf.extractfile(member)
            if f is None:
                continue
            try:
                yield f.read().decode("utf-8", errors="replace")
            except Exception:
                continue


def load_eligible():
    rows = []
    with open(ELIGIBLE_TSV) as f:
        header = f.readline().rstrip("\n").split("\t")
        idx = {name: i for i, name in enumerate(header)}
        for row_index, line in enumerate(f):
            parts = line.rstrip("\n").split("\t")
            if len(parts) <= max(idx.values()):
                continue
            if parts[idx["status"]] != "ANALYZED":
                continue
            rows.append({
                "row_index": row_index,
                "package_name": parts[idx["package_name"]],
                "version": parts[idx["version"]],
                "tarball_url": parts[idx["tarball_url"]],
                "n_js_ts_files": parts[idx["n_js_ts_files"]],
            })
    return rows


def main():
    rows = load_eligible()
    limit = int(os.environ.get("PILOT25_SMOKE_LIMIT", "0"))
    if limit:
        rows = rows[:limit]
    print(f"eligible corpus rows (frozen order): {len(rows)}", file=sys.stderr)
    results = []
    for i, r in enumerate(rows):
        try:
            req = urllib.request.Request(r["tarball_url"], headers={"User-Agent": "redos-pilot25/1.0"})
            with urllib.request.urlopen(req, timeout=PER_PACKAGE_TIMEOUT) as resp:
                data = resp.read()
        except Exception as e:
            print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: FETCH_FAILED ({e})",
                  file=sys.stderr)
            continue
        has_export_any = False
        total_regex_literals = 0
        total_dangerous = 0
        try:
            for text in iter_js_ts_members(data):
                he, nr, nd = score_source_text(text)
                has_export_any = has_export_any or he
                total_regex_literals += nr
                total_dangerous += nd
        except Exception as e:
            print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: EXTRACT_FAILED ({e})",
                  file=sys.stderr)
            continue
        qualifies = has_export_any and total_regex_literals > 0 and total_dangerous > 0
        print(f"[{i+1}/{len(rows)}] {r['package_name']}@{r['version']}: "
              f"export={has_export_any} regex_literals={total_regex_literals} "
              f"dangerous={total_dangerous} qualifies={qualifies}", file=sys.stderr)
        if qualifies:
            results.append({
                "row_index": r["row_index"],
                "package_name": r["package_name"],
                "version": r["version"],
                "tarball_url": r["tarball_url"],
                "supported_sink_count": total_dangerous,
                "regex_literals_seen": total_regex_literals,
            })

    # Rank: descending supported_sink_count; ties broken by ascending row_index (frozen corpus
    # order) -- never randomly, never by any later-known outcome.
    results.sort(key=lambda x: (-x["supported_sink_count"], x["row_index"]))
    selected = results[:N_SELECT]

    out = {
        "schema": "redos-pilot25-selection/1.0",
        "corpus_source": "npm_corpus/eligible_packages.tsv (frozen, 494-package corpus, ANALYZED rows only)",
        "n_eligible_rows_scanned": len(rows),
        "n_qualifying_packages": len(results),
        "n_selected": len(selected),
        "selection_rule": "descending supported_sink_count (cheap text-level proxy for the frozen "
                           "Stage 2 DANGEROUS shape), ties by ascending row_index in "
                           "eligible_packages.tsv",
        "selected": selected,
    }
    out_path = os.path.join(HERE, "pilot25_selection.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()

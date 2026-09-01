# Hypothesis: a top-level alternation branch's "quantifier followed by more content" shape is
# only a REAL risk when the quantified portion is UNGATED -- i.e. it is the branch's own first
# matchable element (no required, non-quantified literal precedes it within the same branch).
# When a required literal DOES precede it, the quantifier's own backtracking can only start at
# positions where that leading literal occurs, not at every position of the quantified char
# itself -- this is what actually distinguishes CVE-2025-5892's real quadratic case from
# phplike's confirmed-linear case (see timing_measurement_output.txt).
import re

def leading_literal_before_first_quantifier(branch):
    """Returns True iff there's at least one required (non-optional, non-quantifier-adjacent)
    literal/char-class BEFORE the branch's own first quantifier occurrence. Simple, conservative
    text-level check: find the first [+*] in the branch; look at everything before it; strip
    anchors (^); if what remains before the quantifier's own preceding atom is non-empty AND
    that quantifier is not glued directly to the branch's own start, treat as gated."""
    m = re.search(r'[+*]', branch)
    if not m:
        return False  # no quantifier at all -- not the shape this rule is even about
    prefix = branch[:m.start()]
    prefix_stripped = prefix.lstrip('^')  # anchors are zero-width, don't gate anything
    # the character(s) immediately before the quantifier are the quantified atom itself
    # (e.g. "\d" before "+", or "]" closing a class before "+") -- we need content BEFORE that
    # atom. Find the atom's own start (a class [...], an escape \X, or a single char).
    if not prefix_stripped:
        return False
    # walk backward from the quantifier to find the atom's own start
    i = len(prefix_stripped)
    if prefix_stripped.endswith(']'):
        depth = 0
        j = i - 1
        while j >= 0:
            if prefix_stripped[j] == ']': depth += 1
            elif prefix_stripped[j] == '[': depth -= 1
            j -= 1
            if depth == 0: break
        atom_start = j + 1
    elif len(prefix_stripped) >= 2 and prefix_stripped[-2] == '\\':
        atom_start = i - 2
    else:
        atom_start = i - 1
    before_atom = prefix_stripped[:atom_start]
    return len(before_atom) > 0

tests = [
    (r'\s+:', False, 'CVE-2025-5892 branch: quantifier is the branch\'s own first element -> UNGATED, must stay flagged'),
    (r'^\s*<p>', False, 'autotranslate.ts branch: only a zero-width anchor before the quantifier -> UNGATED, must stay flagged'),
    (r'%(\d+\$)?([-+\'#0 ]*)(\*\d+\$|\*|\d+)?(\.(\*\d+\$|\*|\d+))?([scboxXuidfegEG])', True, 'phplike branch: literal % precedes the first quantifier -> GATED, should become SAFE-from-this-rule'),
]
for branch, expect_gated, label in tests:
    got = leading_literal_before_first_quantifier(branch)
    status = 'OK' if got == expect_gated else 'MISMATCH'
    print(f'{status}: {label}\n    branch={branch!r}\n    gated={got} (expected {expect_gated})')

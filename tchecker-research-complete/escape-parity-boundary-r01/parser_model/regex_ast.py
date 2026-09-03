#!/usr/bin/env python3
"""Shared regex representation and the shared escape-run parity rule.

DIALECT BOUNDARY. This module defines the representation and the parity rule ONLY. It
contains no grammar. Each regex dialect has its own adapter (dialect_ecmascript.py,
dialect_pcre.py) which accepts exactly that dialect's syntax and produces nodes from
this module. Parsing a pattern under one dialect therefore says nothing whatsoever
about whether it is valid, or means the same thing, under another.

The parity rule, stated structurally and once:

    A quote is escaped when preceded by an ODD-length consecutive escape run.
    A quote terminates the string when preceded by an EVEN-length escape run.

    A boundary rule establishes that parity if and only if every escape character it
    can consume is consumed as part of an escape PAIR. A rule that inspects a fixed
    single preceding position cannot establish it, however that inspection is spelled.
"""

# ---------------------------------------------------------------------------
# shared node types
# ---------------------------------------------------------------------------


class Node:
    __slots__ = ()


class Char(Node):
    __slots__ = ("c",)

    def __init__(self, c): self.c = c
    def __repr__(self): return "Char(%r)" % self.c


class EscapedChar(Node):
    """A backslash-escaped atom: `\\\\` (a literal escape char), `\\.`, `\\d`, ..."""
    __slots__ = ("c",)

    def __init__(self, c): self.c = c
    def __repr__(self): return "Esc(%r)" % self.c


class Dot(Node):
    __slots__ = ()
    def __repr__(self): return "Dot"


class Anchor(Node):
    __slots__ = ("c",)

    def __init__(self, c): self.c = c
    def __repr__(self): return "Anchor(%r)" % self.c


class CharClass(Node):
    __slots__ = ("negated", "members", "ranges")

    def __init__(self, negated, members, ranges):
        self.negated, self.members, self.ranges = negated, members, ranges

    def __repr__(self): return "Class(neg=%s,%r)" % (self.negated, self.members)


class Group(Node):
    """kind: cap | noncap | atomic | look_ahead_pos | look_ahead_neg |
              look_behind_pos | look_behind_neg | named"""
    __slots__ = ("kind", "body")

    def __init__(self, kind, body): self.kind, self.body = kind, body
    def __repr__(self): return "Group(%s,%r)" % (self.kind, self.body)


class Alternation(Node):
    __slots__ = ("branches",)

    def __init__(self, branches): self.branches = branches
    def __repr__(self): return "Alt(%r)" % (self.branches,)


class Repeat(Node):
    """mode: greedy | lazy | possessive"""
    __slots__ = ("node", "lo", "hi", "mode")

    def __init__(self, node, lo, hi, mode):
        self.node, self.lo, self.hi, self.mode = node, lo, hi, mode

    def __repr__(self): return "Rep(%r,%s,%s,%s)" % (self.node, self.lo, self.hi, self.mode)


class ParseError(Exception):
    """The pattern is malformed for the dialect that was asked to parse it."""


class DialectError(ParseError):
    """The pattern uses a construct that does not exist in the requested dialect.

    Raised, never silently tolerated: accepting another dialect's syntax would let a
    pattern that cannot exist in the analysed language be reported as if it could.
    """


# ---------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------

PARITY_ESTABLISHED = "PARITY_ESTABLISHED"
SINGLE_CHAR_LOOKBEHIND = "SINGLE_CHAR_LOOKBEHIND"
NEGATED_CLASS_ONE_CHAR = "NEGATED_CLASS_ONE_CHAR"
NO_ESCAPE_AWARENESS = "NO_ESCAPE_AWARENESS"
ESCAPE_IMPOSSIBLE_IN_BODY = "ESCAPE_IMPOSSIBLE_IN_BODY"
UNCLASSIFIED_BOUNDARY_SHAPE = "UNCLASSIFIED_BOUNDARY_SHAPE"
NO_QUOTED_STRING_CONSTRUCT = "NO_QUOTED_STRING_CONSTRUCT"

INCOMPLETE_VERDICTS = (SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR)
NEGATIVE_VERDICTS = (PARITY_ESTABLISHED, ESCAPE_IMPOSSIBLE_IN_BODY,
                     NO_ESCAPE_AWARENESS, NO_QUOTED_STRING_CONSTRUCT)

QUOTE_CHARS = ("'", '"', "`")


# ---------------------------------------------------------------------------
# the shared parity rule
# ---------------------------------------------------------------------------


def _is_quote_atom(node, q=None):
    if isinstance(node, (Char, EscapedChar)) and node.c in QUOTE_CHARS:
        return node.c if q is None or node.c == q else None
    return None


def _is_escape_atom(node, esc):
    return isinstance(node, EscapedChar) and node.c == esc


def _class_excludes_escape(node, esc):
    return (isinstance(node, CharClass) and node.negated
            and any(_is_escape_atom(m, esc) for m in node.members))


def _can_match_escape(node, esc):
    """True if `node` can match a single bare escape character."""
    if isinstance(node, EscapedChar):
        return node.c == esc
    if isinstance(node, Char):
        return node.c == esc
    if isinstance(node, Dot):
        return True
    if isinstance(node, CharClass):
        present = any(_is_escape_atom(m, esc) or (isinstance(m, Char) and m.c == esc)
                      for m in node.members)
        return (not present) if node.negated else present
    if isinstance(node, Repeat):
        return _can_match_escape(node.node, esc)
    if isinstance(node, Group):
        body = node.body
        if isinstance(body, Alternation):
            return any(any(_can_match_escape(a, esc) for a in br) for br in body.branches)
        return False
    if isinstance(node, Alternation):
        return any(any(_can_match_escape(a, esc) for a in br) for br in node.branches)
    return False


def _subsequences(node):
    """The inner branch sequences of a group/alternation, seeing through quantifiers.

    Returns None for anything that is not a container, so the caller falls back to the
    atom-level escape test.
    """
    if isinstance(node, Repeat):
        return _subsequences(node.node)
    if isinstance(node, Alternation):
        return node.branches
    if isinstance(node, Group):
        if isinstance(node.body, Alternation):
            return node.body.branches
        return [[node.body]]
    return None


def _branch_pairs_escapes(branch, esc):
    """Every escape character the branch consumes must be consumed as an escape PAIR.

    Groups are recursed into: an escape pair written as `(?:\\.)` pairs exactly as one
    written as a bare `\\.`, and a rule must not be judged non-parity merely because its
    pair is parenthesised. Lookaround consumes nothing and is skipped.
    """
    i, saw_pair = 0, False
    while i < len(branch):
        node = branch[i]
        if _is_escape_atom(node, esc):
            if i + 1 >= len(branch):
                return False, saw_pair
            saw_pair = True
            i += 2
            continue
        if isinstance(node, Group) and node.kind.startswith("look_"):
            i += 1
            continue
        subs = _subsequences(node)
        if subs is not None:
            for br in subs:
                ok, sp = _branch_pairs_escapes(br, esc)
                if not ok:
                    return False, saw_pair
                saw_pair = saw_pair or sp
            i += 1
            continue
        if _can_match_escape(node, esc):
            return False, saw_pair
        i += 1
    return True, saw_pair


def _unwrap_alternation(node):
    if isinstance(node, Alternation):
        return node.branches
    if isinstance(node, Group) and isinstance(node.body, Alternation):
        return node.body.branches
    return None


def _establishes_parity(node, esc):
    """True when `node` consumes escape characters ONLY in pairs."""
    if not isinstance(node, Repeat):
        if isinstance(node, Group):
            branches = _unwrap_alternation(node)
            if branches and len(branches) == 1:
                return any(_establishes_parity(a, esc) for a in branches[0])
        return False
    branches = _unwrap_alternation(node.node)
    if branches is None:
        branches = [[node.node]]
    any_pair = False
    for br in branches:
        ok, saw_pair = _branch_pairs_escapes(br, esc)
        if not ok:
            return False
        any_pair = any_pair or saw_pair
    return any_pair


def _mentions_escape(nodes, esc):
    for n in nodes:
        if _is_escape_atom(n, esc):
            return True
        if isinstance(n, CharClass) and any(_is_escape_atom(m, esc) for m in n.members):
            return True
        if isinstance(n, Repeat) and _mentions_escape([n.node], esc):
            return True
        if isinstance(n, Group) and isinstance(n.body, Alternation):
            if any(_mentions_escape(br, esc) for br in n.body.branches):
                return True
        if isinstance(n, Alternation) and any(_mentions_escape(br, esc) for br in n.branches):
            return True
    return False


def _classify_body(body, esc, quote):
    if not body:
        return NO_QUOTED_STRING_CONSTRUCT
    last = body[-1]

    # 1. a negative lookbehind immediately before the closing quote whose entire body
    #    is a single escape-character atom: it inspects exactly one position.
    if isinstance(last, Group) and last.kind == "look_behind_neg":
        inner = last.body
        if isinstance(inner, Alternation) and len(inner.branches) == 1:
            b = inner.branches[0]
            if len(b) == 1 and _is_escape_atom(b[0], esc):
                if any(_establishes_parity(n, esc) for n in body[:-1]):
                    return PARITY_ESTABLISHED
                return SINGLE_CHAR_LOOKBEHIND
        return UNCLASSIFIED_BOUNDARY_SHAPE

    # 2. an unquantified negated class excluding the escape char, consuming exactly one
    #    character immediately before the closing quote.
    if _class_excludes_escape(last, esc):
        if any(_establishes_parity(n, esc) for n in body[:-1]):
            return PARITY_ESTABLISHED
        return NEGATED_CLASS_ONE_CHAR

    # 3. any parity-establishing construct anywhere in the body.
    for n in body:
        if _establishes_parity(n, esc):
            return PARITY_ESTABLISHED

    # 4. the body structurally cannot contain an escape character, so no escape run can
    #    ever precede the closing quote: trivially correct, a negative not an abstention.
    if not any(_can_match_escape(n, esc) for n in body):
        return ESCAPE_IMPOSSIBLE_IN_BODY

    # 5. the body never refers to the escape character: a rule that does not attempt
    #    escape awareness is a DIFFERENT correctness shape, not this property's target.
    if not _mentions_escape(body, esc):
        return NO_ESCAPE_AWARENESS

    return UNCLASSIFIED_BOUNDARY_SHAPE


def _classify_sequence(seq, esc):
    open_idx, quote = None, None
    for idx, node in enumerate(seq):
        q = _is_quote_atom(node)
        if q is None:
            continue
        if open_idx is None:
            open_idx, quote = idx, q
            continue
        if q == quote:
            return _classify_body(seq[open_idx + 1:idx], esc, quote)
    return None


def classify_ast(ast, esc="\\"):
    """Classify the quote-boundary rule of an already-parsed pattern.

    `ast` must be an Alternation produced by a dialect adapter. This function is the
    single shared parity rule: both dialects reach the same verdict vocabulary through
    it, but only ever after their own grammar accepted the pattern.
    """
    verdicts = []
    for branch in ast.branches:
        v = _classify_sequence(branch, esc)
        if v is not None:
            verdicts.append(v)
        for node in branch:
            if isinstance(node, Group) and isinstance(node.body, Alternation):
                for sub in node.body.branches:
                    sv = _classify_sequence(sub, esc)
                    if sv is not None:
                        verdicts.append(sv)
    if not verdicts:
        return NO_QUOTED_STRING_CONSTRUCT
    for v in INCOMPLETE_VERDICTS:
        if v in verdicts:
            return v
    for v in (PARITY_ESTABLISHED, ESCAPE_IMPOSSIBLE_IN_BODY):
        if v in verdicts:
            return v
    if UNCLASSIFIED_BOUNDARY_SHAPE in verdicts:
        return UNCLASSIFIED_BOUNDARY_SHAPE
    return verdicts[0]

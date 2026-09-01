#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY-R01 -- structural model of a regex quote-boundary rule.

This module NEVER substring-matches a pattern. It parses the pattern into a regex
AST (typed atoms, groups, quantifiers, alternations, char classes) and derives the
quote-boundary verdict from that AST's structure alone. The pattern text itself
always arrives from a CPG-resolved node (a regex literal node, or a statically
resolved RegExp/constructor argument) -- never from scanning file text.

The correctness rule this models:

    A quote is escaped when preceded by an ODD-length consecutive escape run.
    A quote terminates the string when preceded by an EVEN-length consecutive
    escape run.

A boundary rule is COMPLETE only if its structure establishes the parity of the whole
consecutive escape run. A rule that inspects a fixed single preceding position cannot
do this, whatever that inspection is spelled like.
"""

# ---------------------------------------------------------------------------
# regex AST node types
# ---------------------------------------------------------------------------


class Node:
    __slots__ = ()


class Char(Node):
    """A literal character atom."""
    __slots__ = ("c",)

    def __init__(self, c):
        self.c = c

    def __repr__(self):
        return "Char(%r)" % self.c


class EscapedChar(Node):
    """A backslash-escaped atom: `\\\\` (a literal escape char), `\\.`, `\\d`, ..."""
    __slots__ = ("c",)

    def __init__(self, c):
        self.c = c

    def __repr__(self):
        return "Esc(%r)" % self.c


class Dot(Node):
    __slots__ = ()

    def __repr__(self):
        return "Dot"


class Anchor(Node):
    __slots__ = ("c",)

    def __init__(self, c):
        self.c = c

    def __repr__(self):
        return "Anchor(%r)" % self.c


class CharClass(Node):
    """[...] / [^...]; `members` holds Char/EscapedChar atoms, `ranges` holds pairs."""
    __slots__ = ("negated", "members", "ranges")

    def __init__(self, negated, members, ranges):
        self.negated = negated
        self.members = members
        self.ranges = ranges

    def __repr__(self):
        return "Class(neg=%s,%r)" % (self.negated, self.members)


class Group(Node):
    """kind: cap | noncap | atomic | look_ahead_pos | look_ahead_neg |
              look_behind_pos | look_behind_neg | named"""
    __slots__ = ("kind", "body")

    def __init__(self, kind, body):
        self.kind = kind
        self.body = body

    def __repr__(self):
        return "Group(%s,%r)" % (self.kind, self.body)


class Alternation(Node):
    __slots__ = ("branches",)

    def __init__(self, branches):
        self.branches = branches

    def __repr__(self):
        return "Alt(%r)" % (self.branches,)


class Repeat(Node):
    """mode: greedy | lazy | possessive"""
    __slots__ = ("node", "lo", "hi", "mode")

    def __init__(self, node, lo, hi, mode):
        self.node = node
        self.lo = lo
        self.hi = hi
        self.mode = mode

    def __repr__(self):
        return "Rep(%r,%s,%s,%s)" % (self.node, self.lo, self.hi, self.mode)


class ParseError(Exception):
    pass


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

_GROUP_PREFIX = (
    ("?<=", "look_behind_pos"),
    ("?<!", "look_behind_neg"),
    ("?=", "look_ahead_pos"),
    ("?!", "look_ahead_neg"),
    ("?>", "atomic"),
    ("?:", "noncap"),
)


def parse(pattern):
    """Parse a regex pattern BODY (delimiters and flags already striped off).

    Returns an Alternation of branches; each branch is a list of Nodes.
    Raises ParseError on anything this model does not understand -- callers must
    treat that as an abstention, never as a negative.
    """
    p = _Parser(pattern)
    node = p.parse_alternation()
    if p.i != len(p.s):
        raise ParseError("trailing input at %d" % p.i)
    return node


class _Parser:
    def __init__(self, s):
        self.s = s
        self.i = 0

    def eof(self):
        return self.i >= len(self.s)

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else ""

    def parse_alternation(self):
        branches = [self.parse_sequence()]
        while not self.eof() and self.peek() == "|":
            self.i += 1
            branches.append(self.parse_sequence())
        return Alternation(branches)

    def parse_sequence(self):
        seq = []
        while not self.eof() and self.peek() not in ("|", ")"):
            atom = self.parse_atom()
            atom = self.parse_quantifier(atom)
            seq.append(atom)
        return seq

    def parse_atom(self):
        c = self.peek()
        if c == "(":
            return self.parse_group()
        if c == "[":
            return self.parse_class()
        if c == "\\":
            self.i += 1
            if self.eof():
                raise ParseError("dangling backslash")
            e = self.s[self.i]
            self.i += 1
            return EscapedChar(e)
        if c == ".":
            self.i += 1
            return Dot()
        if c in ("^", "$"):
            self.i += 1
            return Anchor(c)
        if c in ("*", "+", "?"):
            raise ParseError("quantifier with no atom at %d" % self.i)
        self.i += 1
        return Char(c)

    def parse_group(self):
        assert self.peek() == "("
        self.i += 1
        kind = "cap"
        for prefix, k in _GROUP_PREFIX:
            if self.s.startswith(prefix, self.i):
                self.i += len(prefix)
                kind = k
                break
        else:
            if self.s.startswith("?P<", self.i) or self.s.startswith("?<", self.i):
                # named capture -- consume up to '>'
                j = self.s.find(">", self.i)
                if j < 0:
                    raise ParseError("unterminated group name")
                self.i = j + 1
                kind = "named"
            elif self.s.startswith("?", self.i):
                raise ParseError("unsupported group construct at %d" % self.i)
        body = self.parse_alternation()
        if self.eof() or self.peek() != ")":
            raise ParseError("unterminated group")
        self.i += 1
        return Group(kind, body)

    def parse_class(self):
        assert self.peek() == "["
        self.i += 1
        negated = False
        if self.peek() == "^":
            negated = True
            self.i += 1
        members, ranges = [], []
        first = True
        while True:
            if self.eof():
                raise ParseError("unterminated class")
            c = self.peek()
            if c == "]" and not first:
                self.i += 1
                break
            first = False
            if c == "\\":
                self.i += 1
                if self.eof():
                    raise ParseError("dangling backslash in class")
                atom = EscapedChar(self.s[self.i])
                self.i += 1
            else:
                atom = Char(c)
                self.i += 1
            # range?
            if self.peek() == "-" and self.i + 1 < len(self.s) and self.s[self.i + 1] != "]":
                self.i += 1
                if self.peek() == "\\":
                    self.i += 1
                    hi = EscapedChar(self.s[self.i])
                    self.i += 1
                else:
                    hi = Char(self.peek())
                    self.i += 1
                ranges.append((atom, hi))
            else:
                members.append(atom)
        return CharClass(negated, members, ranges)

    def parse_quantifier(self, atom):
        c = self.peek()
        if c == "*":
            self.i += 1
            lo, hi = 0, None
        elif c == "+":
            self.i += 1
            lo, hi = 1, None
        elif c == "?":
            self.i += 1
            lo, hi = 0, 1
        elif c == "{":
            j = self.s.find("}", self.i)
            if j < 0:
                return atom
            inner = self.s[self.i + 1:j]
            if not inner or not all(ch.isdigit() or ch == "," for ch in inner):
                return atom  # a literal '{'
            self.i = j + 1
            if "," in inner:
                a, _, b = inner.partition(",")
                lo = int(a) if a else 0
                hi = int(b) if b else None
            else:
                lo = hi = int(inner)
        else:
            return atom
        mode = "greedy"
        if self.peek() == "?":
            self.i += 1
            mode = "lazy"
        elif self.peek() == "+":
            self.i += 1
            mode = "possessive"
        return Repeat(atom, lo, hi, mode)


# ---------------------------------------------------------------------------
# structural boundary-rule classification
# ---------------------------------------------------------------------------

QUOTE_CHARS = ("'", '"', "`")

# verdicts
PARITY_ESTABLISHED = "PARITY_ESTABLISHED"
SINGLE_CHAR_LOOKBEHIND = "SINGLE_CHAR_LOOKBEHIND"
NEGATED_CLASS_ONE_CHAR = "NEGATED_CLASS_ONE_CHAR"
NO_ESCAPE_AWARENESS = "NO_ESCAPE_AWARENESS"
ESCAPE_IMPOSSIBLE_IN_BODY = "ESCAPE_IMPOSSIBLE_IN_BODY"
UNCLASSIFIED_BOUNDARY_SHAPE = "UNCLASSIFIED_BOUNDARY_SHAPE"
NO_QUOTED_STRING_CONSTRUCT = "NO_QUOTED_STRING_CONSTRUCT"

INCOMPLETE_VERDICTS = (SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR)


def _is_quote_atom(node, q=None):
    if isinstance(node, Char) and node.c in QUOTE_CHARS:
        return node.c if q is None or node.c == q else None
    if isinstance(node, EscapedChar) and node.c in QUOTE_CHARS:
        return node.c if q is None or node.c == q else None
    return None


def _is_escape_atom(node, esc):
    """True for the atom denoting a literal escape character (regex `\\\\`)."""
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
        if node.negated:
            return not any(_is_escape_atom(m, esc) or (isinstance(m, Char) and m.c == esc)
                           for m in node.members)
        return any(_is_escape_atom(m, esc) or (isinstance(m, Char) and m.c == esc)
                   for m in node.members)
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


def _branch_pairs_escapes(branch, esc):
    """Scan a branch: every escape character it consumes must be consumed as an
    escape-pair (escape + exactly one following atom).

    Returns (ok, saw_pair). `ok` is False when the branch can consume a lone,
    unpaired escape character -- such a branch cannot establish run parity.
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
        if _can_match_escape(node, esc):
            return False, saw_pair
        i += 1
    return True, saw_pair


def _unwrap_alternation(node):
    """Return the list of branches if `node` is (or wraps) an Alternation."""
    if isinstance(node, Alternation):
        return node.branches
    if isinstance(node, Group) and isinstance(node.body, Alternation):
        return node.body.branches
    return None


def _establishes_parity(node, esc):
    """True when `node` consumes escape characters ONLY in pairs.

    This is the structural statement of the correctness rule: if every escape
    character is consumed together with exactly one following character, then the
    parity of any consecutive escape run is established by construction, and a
    quote can only be reached at an even-parity position.
    """
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
        if isinstance(n, CharClass):
            if any(_is_escape_atom(m, esc) for m in n.members):
                return True
        if isinstance(n, Repeat):
            if _mentions_escape([n.node], esc):
                return True
        if isinstance(n, Group):
            if isinstance(n.body, Alternation):
                for br in n.body.branches:
                    if _mentions_escape(br, esc):
                        return True
        if isinstance(n, Alternation):
            for br in n.branches:
                if _mentions_escape(br, esc):
                    return True
    return False


def _classify_sequence(seq, esc):
    """Classify the quote-boundary rule of one flat sequence of nodes."""
    # locate a quoted-string construct: an opening quote atom and a later closing
    # quote atom of the same character.
    open_idx = None
    quote = None
    for idx, node in enumerate(seq):
        q = _is_quote_atom(node)
        if q is None:
            continue
        if open_idx is None:
            open_idx, quote = idx, q
            continue
        if q == quote:
            close_idx = idx
            body = seq[open_idx + 1:close_idx]
            return _classify_body(body, esc, quote)
    return None


def _classify_body(body, esc, quote):
    if not body:
        return NO_QUOTED_STRING_CONSTRUCT
    last = body[-1]

    # 1. negative lookbehind immediately before the closing quote whose whole body
    #    is a single escape-character atom -> inspects exactly one position.
    if isinstance(last, Group) and last.kind == "look_behind_neg":
        inner = last.body
        if isinstance(inner, Alternation) and len(inner.branches) == 1:
            b = inner.branches[0]
            if len(b) == 1 and _is_escape_atom(b[0], esc):
                # a preceding parity construct would still rescue it
                if any(_establishes_parity(n, esc) for n in body[:-1]):
                    return PARITY_ESTABLISHED
                return SINGLE_CHAR_LOOKBEHIND
        return UNCLASSIFIED_BOUNDARY_SHAPE

    # 2. an unquantified negated class excluding the escape char, consuming exactly
    #    one character immediately before the closing quote.
    if _class_excludes_escape(last, esc):
        if any(_establishes_parity(n, esc) for n in body[:-1]):
            return PARITY_ESTABLISHED
        return NEGATED_CLASS_ONE_CHAR

    # 3. any parity-establishing construct anywhere in the body.
    for n in body:
        if _establishes_parity(n, esc):
            return PARITY_ESTABLISHED

    # 4. the body structurally cannot contain an escape character at all, so no
    #    escape run can ever precede the closing quote: the boundary rule is
    #    trivially correct and this is a negative, not an abstention.
    if not any(_can_match_escape(n, esc) for n in body):
        return ESCAPE_IMPOSSIBLE_IN_BODY

    # 5. body never refers to the escape character at all -- a rule that does not
    #    attempt escape awareness is NOT the shape this property targets.
    if not _mentions_escape(body, esc):
        return NO_ESCAPE_AWARENESS

    return UNCLASSIFIED_BOUNDARY_SHAPE


def classify_pattern(pattern, esc="\\"):
    """Structurally classify the quote-boundary rule of a regex pattern body.

    Returns (verdict, detail). Any parse failure yields
    UNCLASSIFIED_BOUNDARY_SHAPE with the reason -- callers abstain on it.
    """
    try:
        ast = parse(pattern)
    except ParseError as e:
        return UNCLASSIFIED_BOUNDARY_SHAPE, "parse_error:%s" % e
    except Exception as e:  # defensive: never let a malformed pattern crash a run
        return UNCLASSIFIED_BOUNDARY_SHAPE, "parse_exception:%s" % type(e).__name__

    verdicts = []
    for branch in ast.branches:
        v = _classify_sequence(branch, esc)
        if v is not None:
            verdicts.append(v)
        # also look inside capturing/non-capturing groups of this branch
        for node in branch:
            if isinstance(node, Group) and isinstance(node.body, Alternation):
                for sub in node.body.branches:
                    sv = _classify_sequence(sub, esc)
                    if sv is not None:
                        verdicts.append(sv)
    if not verdicts:
        return NO_QUOTED_STRING_CONSTRUCT, ""
    for v in (SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR):
        if v in verdicts:
            return v, ""
    for v in (PARITY_ESTABLISHED, ESCAPE_IMPOSSIBLE_IN_BODY):
        if v in verdicts:
            return v, ""
    if UNCLASSIFIED_BOUNDARY_SHAPE in verdicts:
        return UNCLASSIFIED_BOUNDARY_SHAPE, "shape_not_modelled"
    return verdicts[0], ""

#!/usr/bin/env python3
"""Grammar core shared by the dialect adapters.

Every construct that DIFFERS between dialects is gated behind a feature flag. A dialect
adapter declares its own feature set; anything not in that set raises DialectError rather
than being parsed. There is deliberately no "permissive" mode: a pattern is parsed as
exactly one dialect or not at all.
"""
from regex_ast import (Alternation, Anchor, Char, CharClass, DialectError, Dot,
                       EscapedChar, Group, ParseError, Repeat)

# group prefixes that exist in both dialects
COMMON_GROUP_PREFIX = (
    ("?<=", "look_behind_pos"),
    ("?<!", "look_behind_neg"),
    ("?=", "look_ahead_pos"),
    ("?!", "look_ahead_neg"),
    ("?:", "noncap"),
)


class Parser:
    # --- dialect feature switches (overridden by adapters) -------------------
    NAME = "abstract"
    POSSESSIVE_QUANTIFIERS = False   # a*+ a++ a?+ a{n,m}+
    ATOMIC_GROUPS = False            # (?>...)
    INLINE_MODIFIERS = False         # (?i) (?im-sx:...)
    COMMENT_GROUPS = False           # (?#...)
    RECURSION_AND_CONDITIONALS = False   # (?R) (?1) (?&n) (?(1)...)
    PYTHON_NAMED_GROUPS = False      # (?P<n>...) (?P=n)
    ANGLE_NAMED_GROUPS = True        # (?<name>...)
    DIALECT_ONLY_ESCAPES = frozenset()   # escape letters unique to this dialect
    FOREIGN_ESCAPES = frozenset()        # escape letters that belong to ANOTHER dialect

    def __init__(self, s):
        self.s = s
        self.i = 0

    # --- helpers ------------------------------------------------------------
    def eof(self): return self.i >= len(self.s)
    def peek(self): return self.s[self.i] if self.i < len(self.s) else ""

    def _dialect_error(self, what):
        raise DialectError("%s is not valid in %s (at offset %d)" % (what, self.NAME, self.i))

    # --- entry point --------------------------------------------------------
    def parse(self):
        node = self.parse_alternation()
        if self.i != len(self.s):
            raise ParseError("trailing input at %d" % self.i)
        return node

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
            if atom is not None:                 # comment groups produce no atom
                seq.append(self.parse_quantifier(atom))
        return seq

    def parse_atom(self):
        c = self.peek()
        if c == "(":
            return self.parse_group()
        if c == "[":
            return self.parse_class()
        if c == "\\":
            return self.parse_escape()
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

    def parse_escape(self):
        self.i += 1
        if self.eof():
            raise ParseError("dangling backslash")
        e = self.s[self.i]
        if e in self.FOREIGN_ESCAPES:
            self._dialect_error("escape \\%s" % e)
        self.i += 1
        return EscapedChar(e)

    def parse_group(self):
        assert self.peek() == "("
        start = self.i
        self.i += 1
        kind = "cap"
        if self.s.startswith("?", self.i):
            if self.s.startswith("?>", self.i):
                if not self.ATOMIC_GROUPS:
                    self.i = start
                    self._dialect_error("atomic group (?>...)")
                self.i += 2
                kind = "atomic"
            elif self.s.startswith("?#", self.i):
                if not self.COMMENT_GROUPS:
                    self.i = start
                    self._dialect_error("comment group (?#...)")
                j = self.s.find(")", self.i)
                if j < 0:
                    raise ParseError("unterminated comment group")
                self.i = j + 1
                return None
            elif self.s.startswith("?P", self.i):
                if not self.PYTHON_NAMED_GROUPS:
                    self.i = start
                    self._dialect_error("named group (?P<...>)")
                j = self.s.find(">", self.i)
                if j < 0:
                    raise ParseError("unterminated group name")
                self.i = j + 1
                kind = "named"
            elif self.s.startswith("?R", self.i) or self.s.startswith("?&", self.i) or \
                    self.s.startswith("?(", self.i):
                if not self.RECURSION_AND_CONDITIONALS:
                    self.i = start
                    self._dialect_error("recursion/conditional group")
                j = self.s.find(")", self.i)
                if j < 0:
                    raise ParseError("unterminated group")
                self.i = j + 1
                return None
            else:
                for prefix, k in COMMON_GROUP_PREFIX:
                    if self.s.startswith(prefix, self.i):
                        self.i += len(prefix)
                        kind = k
                        break
                else:
                    if self.s.startswith("?<", self.i):
                        if not self.ANGLE_NAMED_GROUPS:
                            self.i = start
                            self._dialect_error("named group (?<name>...)")
                        j = self.s.find(">", self.i)
                        if j < 0:
                            raise ParseError("unterminated group name")
                        self.i = j + 1
                        kind = "named"
                    else:
                        # (?i) / (?im-sx:...) style inline modifiers
                        j = self.s.find(")", self.i)
                        colon = self.s.find(":", self.i)
                        end = min(x for x in (j, colon) if x >= 0) if (j >= 0 or colon >= 0) else -1
                        body = self.s[self.i + 1:end] if end >= 0 else ""
                        if end >= 0 and body and all(ch in "imsxuUXAJnrdgl-" for ch in body):
                            if not self.INLINE_MODIFIERS:
                                self.i = start
                                self._dialect_error("inline modifier group (?%s)" % body)
                            if end == colon:
                                self.i = colon + 1
                                kind = "noncap"
                            else:
                                self.i = j + 1
                                return None
                        else:
                            self.i = start
                            raise ParseError("unsupported group construct at %d" % start)
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
        members, ranges, first = [], [], True
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
                e = self.s[self.i]
                if e in self.FOREIGN_ESCAPES:
                    self._dialect_error("escape \\%s in class" % e)
                atom = EscapedChar(e)
                self.i += 1
            else:
                atom = Char(c)
                self.i += 1
            if self.peek() == "-" and self.i + 1 < len(self.s) and self.s[self.i + 1] != "]":
                self.i += 1
                if self.peek() == "\\":
                    self.i += 1
                    hi = EscapedChar(self.peek())
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
            self.i += 1; lo, hi = 0, None
        elif c == "+":
            self.i += 1; lo, hi = 1, None
        elif c == "?":
            self.i += 1; lo, hi = 0, 1
        elif c == "{":
            j = self.s.find("}", self.i)
            if j < 0:
                return atom
            inner = self.s[self.i + 1:j]
            if not inner or not all(ch.isdigit() or ch == "," for ch in inner):
                return atom                       # a literal '{'
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
            if not self.POSSESSIVE_QUANTIFIERS:
                self._dialect_error("possessive quantifier")
            self.i += 1
            mode = "possessive"
        return Repeat(atom, lo, hi, mode)

#!/usr/bin/env python3
"""PCRE regex dialect adapter.

Accepts PCRE syntax, including the constructs ECMAScript does not have: possessive
quantifiers, atomic groups, inline modifier groups, comment groups, recursion and
conditionals, (?P<>) named groups, and PCRE-only escapes.

This adapter exists for the HISTORICAL DESIGN DIFFERENTIAL only. Patterns parsed here
are evidence about a PHP/PCRE parser; they are never evidence about the ECMAScript
corpus, and a verdict reached here is tagged regex_dialect=PCRE so the two can never be
tallied together.
"""
from _grammar import Parser

DIALECT = "PCRE"
VALID_FLAGS = set("imsxuUXAJnDSeg")


class PcreParser(Parser):
    NAME = "PCRE"
    POSSESSIVE_QUANTIFIERS = True
    ATOMIC_GROUPS = True
    INLINE_MODIFIERS = True
    COMMENT_GROUPS = True
    RECURSION_AND_CONDITIONALS = True
    PYTHON_NAMED_GROUPS = True
    ANGLE_NAMED_GROUPS = True
    FOREIGN_ESCAPES = frozenset()


def parse(pattern):
    return PcreParser(pattern).parse()

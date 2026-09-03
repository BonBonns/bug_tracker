#!/usr/bin/env python3
"""ECMAScript regex dialect adapter.

Accepts ECMAScript regular-expression syntax and NOTHING else. PCRE-only constructs --
possessive quantifiers, atomic groups, inline modifier groups, comment groups,
recursion/conditionals, (?P<>) named groups and PCRE-only escapes -- raise DialectError.
They are not "unsupported"; they cannot occur in a valid ECMAScript pattern, and silently
parsing them would let a pattern that could never exist in JavaScript be reported as a
JavaScript finding.
"""
from _grammar import Parser
from regex_ast import DialectError, ParseError  # noqa: F401  (re-exported)

DIALECT = "ECMASCRIPT"
# ECMAScript regex flags (ES2024 incl. v). Recorded as evidence; see boundary_model.
VALID_FLAGS = set("dgimsuvy")


class EcmascriptParser(Parser):
    NAME = "ECMASCRIPT"
    POSSESSIVE_QUANTIFIERS = False
    ATOMIC_GROUPS = False
    INLINE_MODIFIERS = False
    COMMENT_GROUPS = False
    RECURSION_AND_CONDITIONALS = False
    PYTHON_NAMED_GROUPS = False
    ANGLE_NAMED_GROUPS = True
    # escapes that exist in PCRE but not in ECMAScript
    FOREIGN_ESCAPES = frozenset("AZzGKhRNCXeGQE")


def parse(pattern):
    return EcmascriptParser(pattern).parse()

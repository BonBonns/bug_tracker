#!/usr/bin/env python3
"""ESCAPE-PARITY-BOUNDARY -- parser-only layer, dialect-aware.

Public entry point for classifying ONE quote-boundary rule. Every result carries the
dialect it was parsed under and the evidence role it may be used for:

    regex_dialect  ECMASCRIPT | PCRE
    evidence_role  CORPUS_ANALYSIS | HISTORICAL_DESIGN_DIFFERENTIAL

These are not decoration. A PCRE result may never be tallied with, or used as validation
for, ECMAScript corpus analysis: the two dialects have different grammars, and a pattern
valid in one can be a syntax error in the other. `classify` refuses to guess a dialect.

The pattern BODY handed in here must already have been recovered from a resolved
AST/CPG node (a regex literal node, or a uniquely resolved RegExp constructor argument).
This layer parses pattern bodies; it never discovers regexes by searching source text.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import dialect_ecmascript  # noqa: E402
import dialect_pcre  # noqa: E402
from regex_ast import (  # noqa: E402
    DialectError, ParseError, classify_ast,
    PARITY_ESTABLISHED, SINGLE_CHAR_LOOKBEHIND, NEGATED_CLASS_ONE_CHAR,
    NO_ESCAPE_AWARENESS, ESCAPE_IMPOSSIBLE_IN_BODY, UNCLASSIFIED_BOUNDARY_SHAPE,
    NO_QUOTED_STRING_CONSTRUCT, INCOMPLETE_VERDICTS, NEGATIVE_VERDICTS,
)

ECMASCRIPT = "ECMASCRIPT"
PCRE = "PCRE"
CORPUS_ANALYSIS = "CORPUS_ANALYSIS"
HISTORICAL_DESIGN_DIFFERENTIAL = "HISTORICAL_DESIGN_DIFFERENTIAL"

_ADAPTERS = {ECMASCRIPT: dialect_ecmascript, PCRE: dialect_pcre}

# The evidence role a dialect is allowed to serve. The ECMAScript corpus is analysed with
# the ECMAScript adapter; the historical PHP/PCRE differential is the only PCRE consumer.
_ALLOWED_ROLES = {
    ECMASCRIPT: {CORPUS_ANALYSIS},
    PCRE: {HISTORICAL_DESIGN_DIFFERENTIAL},
}

# Abstention reasons specific to this layer
FOREIGN_DIALECT_SYNTAX = "FOREIGN_DIALECT_SYNTAX"
UNMODELLED_BOUNDARY_SHAPE = "UNMODELLED_BOUNDARY_SHAPE"
MALFORMED_PATTERN = "MALFORMED_PATTERN"


def classify(pattern, dialect, evidence_role, flags="", escape_char="\\"):
    """Classify one quote-boundary rule.

    Returns a dict with the verdict plus the dialect/role provenance. Any construct the
    requested dialect does not have, and any pattern this model does not cover, produces
    an abstention -- never a negative.
    """
    if dialect not in _ADAPTERS:
        raise ValueError("unknown dialect %r" % dialect)
    if evidence_role not in _ALLOWED_ROLES[dialect]:
        raise ValueError(
            "evidence_role %r is not permitted for dialect %r (permitted: %s). "
            "PCRE evidence is historical-differential only and must never be tallied "
            "with ECMAScript corpus analysis."
            % (evidence_role, dialect, sorted(_ALLOWED_ROLES[dialect])))

    adapter = _ADAPTERS[dialect]
    rec = {"regex_dialect": dialect, "evidence_role": evidence_role,
           "pattern": pattern, "flags": flags, "escape_char": escape_char,
           # Flags are recorded as EVIDENCE. The parity verdict is a property of the
           # pattern's structure and is deliberately flag-independent; no flag changes
           # it without an explicit modelled reason, and none is modelled here.
           "flags_affect_verdict": False,
           "unknown_flags": sorted(set(flags) - adapter.VALID_FLAGS)}
    try:
        ast = adapter.parse(pattern)
    except DialectError as e:
        rec.update(verdict=None, abstained=True, abstention_reason=FOREIGN_DIALECT_SYNTAX,
                   detail=str(e))
        return rec
    except ParseError as e:
        rec.update(verdict=None, abstained=True, abstention_reason=MALFORMED_PATTERN,
                   detail=str(e))
        return rec
    except Exception as e:  # defensive: a malformed pattern must never crash a run
        rec.update(verdict=None, abstained=True, abstention_reason=MALFORMED_PATTERN,
                   detail="%s: %s" % (type(e).__name__, e))
        return rec

    verdict = classify_ast(ast, escape_char)
    rec["verdict"] = verdict
    if verdict == UNCLASSIFIED_BOUNDARY_SHAPE:
        rec.update(abstained=True, abstention_reason=UNMODELLED_BOUNDARY_SHAPE, detail="")
    else:
        rec.update(abstained=False, abstention_reason=None, detail="")
    rec["is_candidate"] = verdict in INCOMPLETE_VERDICTS
    return rec


def classify_ecmascript(pattern, flags=""):
    """Corpus path: an ECMAScript pattern recovered from a JS AST/CPG node."""
    return classify(pattern, ECMASCRIPT, CORPUS_ANALYSIS, flags)


def classify_pcre_historical(pattern, flags=""):
    """Historical path: a PCRE pattern from the published design differential."""
    return classify(pattern, PCRE, HISTORICAL_DESIGN_DIFFERENTIAL, flags)

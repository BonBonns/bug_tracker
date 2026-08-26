package portable.graph;

/**
 * One SEMANTIC value contribution to a local binding.
 *
 * A single source statement can produce SEVERAL semantic defs: `x += y` contributes
 * both the rhs value (y -> x) AND the prior-value contribution (UNKNOWN(old x) -> x).
 * They share one CFG anchor — the `x += y` statement. Reaching-definition analysis
 * therefore operates on STATEMENT ANCHORS, and every semantic def anchored to a
 * reaching statement is retained. Filtering by CFG-visible defs alone would drop
 * derived contributions that own no CFG node of their own and make the analyzer
 * falsely more confident (measured on utf8PrevCharLen).
 *
 * cfgAnchor == 0 means "no anchor recorded"; such a def is NEVER removed by
 * reaching-def filtering, because absence of an anchor is not evidence of
 * unreachability.
 */
public record AssignmentFact(
    long id,
    long functionId,
    long targetLocalId,
    ValueRef value,
    Integer line,
    long cfgAnchor
) {
    /** Compat: pre-anchor shape (anchor unknown => never filtered out). */
    public AssignmentFact(long id, long functionId, long targetLocalId, ValueRef value, Integer line) {
        this(id, functionId, targetLocalId, value, line, 0L);
    }
}

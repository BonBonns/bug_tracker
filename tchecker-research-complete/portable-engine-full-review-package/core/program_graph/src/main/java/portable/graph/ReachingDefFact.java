package portable.graph;

import java.util.List;

/** Which SEMANTIC definitions can reach a given use, per a frontend CFG analysis.
 *
 *  CRITICAL CONTRACT: defIds are semantic definitions, NOT CFG nodes. A single
 *  statement can carry several semantic defs — `x += y` contributes both the rhs
 *  (y -> x) and the prior-value contribution (UNKNOWN(old x) -> x), sharing one
 *  CFG anchor. The frontend runs reaching definitions over STATEMENT ANCHORS and
 *  then expands every reaching anchor to ALL semantic defs anchored there, so a
 *  derived contribution that owns no CFG node of its own can never be dropped for
 *  being invisible to the CFG (measured hazard on utf8PrevCharLen: 5 of its 11
 *  defs are synthetic prior-value contributions).
 *
 *  Narrowing may only REMOVE possibilities the CFG proves unreachable; it can
 *  never add a proven origin, so it cannot manufacture an EXACT claim by itself. */
public record ReachingDefFact(
    long useId,
    long functionId,
    long localId,
    List<Long> defIds,
    Resolution resolution,
    FactDerivation derivation
) {
    public ReachingDefFact {
        defIds = List.copyOf(defIds);
        if (derivation == null)
            throw new IllegalArgumentException("reaching-def facts must carry their derivation");
        if (defIds.isEmpty())
            throw new IllegalArgumentException("an empty reaching set proves nothing; omit the fact instead");
    }
}

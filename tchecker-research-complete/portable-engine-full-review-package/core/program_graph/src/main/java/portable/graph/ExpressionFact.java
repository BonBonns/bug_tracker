package portable.graph;

import java.util.List;

/** A value computed by combining operands (binary/ternary/logical expressions).
 *  Frontends decide WHICH constructs qualify (operator naming is frontend-specific);
 *  the core supplies the neutral semantics: the result carries every operand's
 *  origins as POSSIBILITIES, never as proof — an expression can never yield EXACT. */
public record ExpressionFact(
    long id,
    long functionId,
    String operator,
    List<ValueRef> operands,
    Resolution resolution,
    FactDerivation derivation
) {
    public ExpressionFact {
        operands = List.copyOf(operands);
        if (operands.size() < 2)
            throw new IllegalArgumentException("expression fact requires >=2 operands");
        if (resolution == Resolution.EXACT)
            throw new IllegalArgumentException("a combined expression can never be EXACT");
        if (derivation == null)
            throw new IllegalArgumentException("expression facts must carry their derivation");
    }
}

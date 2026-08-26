package portable.effects;

import java.util.*;

/**
 * Language-neutral structured value/effect expression.
 *
 * The tree preserves enclosure and branch structure.  It intentionally does not expose
 * source-language AST node kinds; frontends translate their syntax into these semantic nodes.
 */
public sealed interface EffectExpr permits EffectExpr.Source, EffectExpr.Apply, EffectExpr.Branch, EffectExpr.ContextBoundary {
    record Source(String label) implements EffectExpr {
        public Source { label = Objects.requireNonNull(label).trim(); if (label.isEmpty()) throw new IllegalArgumentException("source label must be non-empty"); }
    }

    record Apply(String operation, EffectExpr input) implements EffectExpr {
        public Apply {
            operation = Objects.requireNonNull(operation).trim();
            input = Objects.requireNonNull(input);
            if (operation.isEmpty()) throw new IllegalArgumentException("operation must be non-empty");
        }
    }

    record Branch(List<EffectExpr> alternatives) implements EffectExpr {
        public Branch {
            Objects.requireNonNull(alternatives);
            alternatives = List.copyOf(alternatives);
            if (alternatives.isEmpty()) throw new IllegalArgumentException("branch must contain alternatives");
            if (alternatives.stream().anyMatch(Objects::isNull)) throw new IllegalArgumentException("branch alternative cannot be null");
        }
    }

    /** Marks the point where a value is interpreted/consumed under one semantic context. */
    record ContextBoundary(EffectRequirement requirement, EffectExpr input) implements EffectExpr {
        public ContextBoundary {
            requirement = Objects.requireNonNull(requirement);
            input = Objects.requireNonNull(input);
        }
    }

    static Source source(String label) { return new Source(label); }
    static Apply apply(String operation, EffectExpr input) { return new Apply(operation, input); }
    static Branch branch(EffectExpr... alternatives) { return new Branch(List.of(alternatives)); }
    static ContextBoundary at(EffectRequirement requirement, EffectExpr input) { return new ContextBoundary(requirement, input); }
}

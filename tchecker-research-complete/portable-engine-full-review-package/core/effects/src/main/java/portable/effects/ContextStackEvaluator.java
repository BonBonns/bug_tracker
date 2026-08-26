package portable.effects;

import java.util.*;

/**
 * Evaluates an explicitly declared parser/use-context stack.
 *
 * The caller supplies transformations segmented by the context boundary they
 * precede.  This is intentionally independent of any source-language AST.
 * A missing segment is an explicit incomplete/unknown condition, never an
 * implicit success.
 */
public final class ContextStackEvaluator {
    private final TransformationRegistry registry;

    public ContextStackEvaluator(TransformationRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    /**
     * transformationsByLayer[i] are the operations applied after the prior
     * context boundary and before crossing stack.layers()[i].
     */
    public ContextStackAssessment assess(
            ContextStack stack,
            List<List<String>> transformationsByLayer) {
        Objects.requireNonNull(stack);
        Objects.requireNonNull(transformationsByLayer);

        List<ContextLayerAssessment> out = new ArrayList<>();
        boolean complete = transformationsByLayer.size() == stack.size();

        for (int i = 0; i < stack.size(); i++) {
            EffectRequirement req = stack.layers().get(i);
            if (i >= transformationsByLayer.size()) {
                out.add(new ContextLayerAssessment(req, List.of(), Adequacy.UNKNOWN,
                        "context layer has no supplied structural segment"));
                continue;
            }
            List<String> ops = List.copyOf(transformationsByLayer.get(i));
            out.add(assessLayer(req, ops));
        }

        // Extra structural segments mean the declaration and observed path do
        // not line up.  Preserve the mismatch as incomplete rather than trying
        // to guess which parser layer they belong to.
        if (transformationsByLayer.size() != stack.size()) complete = false;

        Adequacy overall = combine(out.stream().map(ContextLayerAssessment::adequacy).toList());
        if (!complete && overall == Adequacy.GUARANTEED) overall = Adequacy.UNKNOWN;
        return new ContextStackAssessment(stack, out, overall, complete);
    }

    private ContextLayerAssessment assessLayer(EffectRequirement req, List<String> operations) {
        if (operations.isEmpty()) {
            return new ContextLayerAssessment(req, operations, Adequacy.INADEQUATE,
                    "required context crossed with no transformation in this structural segment");
        }

        boolean guaranteed=false, conditional=false, unknown=false, inadequate=false;
        List<String> reasons = new ArrayList<>();
        for (String op : operations) {
            TransformationAssessment a = registry.assess(op, req.effectClass(), req.context());
            reasons.add(op + "=" + a.adequacy());
            switch (a.adequacy()) {
                case GUARANTEED -> guaranteed=true;
                case CONDITIONAL -> conditional=true;
                case UNKNOWN -> unknown=true;
                case INADEQUATE -> inadequate=true;
            }
        }

        Adequacy result;
        if (guaranteed) result = Adequacy.GUARANTEED;
        else if (conditional) result = Adequacy.CONDITIONAL;
        else if (unknown) result = Adequacy.UNKNOWN;
        else if (inadequate) result = Adequacy.INADEQUATE;
        else result = Adequacy.UNKNOWN;

        return new ContextLayerAssessment(req, operations, result, String.join(", ", reasons));
    }

    private static Adequacy combine(List<Adequacy> layers) {
        if (layers.isEmpty()) return Adequacy.UNKNOWN;
        if (layers.stream().anyMatch(a -> a == Adequacy.INADEQUATE)) return Adequacy.INADEQUATE;
        if (layers.stream().anyMatch(a -> a == Adequacy.UNKNOWN)) return Adequacy.UNKNOWN;
        if (layers.stream().anyMatch(a -> a == Adequacy.CONDITIONAL)) return Adequacy.CONDITIONAL;
        return Adequacy.GUARANTEED;
    }
}

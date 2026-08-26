package portable.effects;

import java.util.*;

/**
 * Evaluates transformations by their structural position between context boundaries.
 *
 * Important invariants:
 *  - An operation can satisfy only a context boundary that occurs AFTER it on the source->sink path.
 *  - Crossing a boundary resets the candidate operation segment; a later operation cannot
 *    retroactively satisfy an earlier parser/use context.
 *  - Branches are assessed independently and conservatively merged.
 *  - No AST-subtree membership or flattened "contains transformer" predicate is used.
 */
public final class StructureAwareTransformationEvaluator {
    private final TransformationRegistry registry;

    public StructureAwareTransformationEvaluator(TransformationRegistry registry) {
        this.registry = Objects.requireNonNull(registry);
    }

    private sealed interface Step permits ApplyStep, BoundaryStep {}
    private record ApplyStep(String operation) implements Step {}
    private record BoundaryStep(EffectRequirement requirement) implements Step {}

    public StructuredEffectAssessment assess(EffectExpr expression) {
        Objects.requireNonNull(expression);
        List<List<Step>> paths = expand(expression);
        List<PathEffectAssessment> assessed = new ArrayList<>();
        for (List<Step> path : paths) assessed.add(assessPath(path));
        Adequacy overall = BranchEffectSummary.combine(assessed.stream().map(PathEffectAssessment::adequacy).toList());
        return new StructuredEffectAssessment(assessed, overall);
    }

    private List<List<Step>> expand(EffectExpr expression) {
        if (expression instanceof EffectExpr.Source) return List.of(new ArrayList<>());
        if (expression instanceof EffectExpr.Apply a) {
            List<List<Step>> out = copyPaths(expand(a.input()));
            out.forEach(p -> p.add(new ApplyStep(a.operation())));
            return out;
        }
        if (expression instanceof EffectExpr.ContextBoundary c) {
            List<List<Step>> out = copyPaths(expand(c.input()));
            out.forEach(p -> p.add(new BoundaryStep(c.requirement())));
            return out;
        }
        EffectExpr.Branch b = (EffectExpr.Branch) expression;
        List<List<Step>> out = new ArrayList<>();
        for (EffectExpr alt : b.alternatives()) out.addAll(copyPaths(expand(alt)));
        return out;
    }

    private static List<List<Step>> copyPaths(List<List<Step>> input) {
        List<List<Step>> out = new ArrayList<>();
        for (List<Step> p : input) out.add(new ArrayList<>(p));
        return out;
    }

    private PathEffectAssessment assessPath(List<Step> path) {
        List<String> ops = new ArrayList<>();
        List<ContextLayerAssessment> layers = new ArrayList<>();
        List<String> rendered = new ArrayList<>();

        for (Step step : path) {
            if (step instanceof ApplyStep a) {
                ops.add(a.operation());
                rendered.add("APPLY:" + a.operation());
            } else {
                BoundaryStep b = (BoundaryStep) step;
                rendered.add("CONTEXT:" + b.requirement().context().domain() + "/" + b.requirement().context().context());
                ContextLayerAssessment layer = assessLayer(b.requirement(), ops);
                layers.add(layer);
                ops = new ArrayList<>(); // context stack boundary: later operations cannot satisfy this layer
            }
        }

        // A transformation chain with no explicit interpretation/use context cannot be declared adequate.
        if (layers.isEmpty()) return new PathEffectAssessment(rendered, layers, Adequacy.UNKNOWN);

        Adequacy pathAdequacy = combineSequential(layers.stream().map(ContextLayerAssessment::adequacy).toList());
        return new PathEffectAssessment(rendered, layers, pathAdequacy);
    }

    private ContextLayerAssessment assessLayer(EffectRequirement req, List<String> operations) {
        if (operations.isEmpty()) {
            return new ContextLayerAssessment(req, List.of(), Adequacy.INADEQUATE,
                    "required context crossed with no transformation in this structural segment");
        }

        boolean guaranteed = false, conditional = false, unknown = false, explicitInadequate = false;
        List<String> details = new ArrayList<>();
        for (String op : operations) {
            TransformationAssessment a = registry.assess(op, req.effectClass(), req.context());
            details.add(op + "=" + a.adequacy());
            switch (a.adequacy()) {
                case GUARANTEED -> guaranteed = true;
                case CONDITIONAL -> conditional = true;
                case UNKNOWN -> unknown = true;
                case INADEQUATE -> explicitInadequate = true;
            }
        }

        // One demonstrated guarantee in the segment is enough. Other operations are not assumed to
        // destroy that effect unless a future model explicitly represents an invalidating transition.
        Adequacy adequacy;
        if (guaranteed) adequacy = Adequacy.GUARANTEED;
        else if (conditional) adequacy = Adequacy.CONDITIONAL;
        else if (unknown) adequacy = Adequacy.UNKNOWN;
        else if (explicitInadequate) adequacy = Adequacy.INADEQUATE;
        else adequacy = Adequacy.UNKNOWN;

        return new ContextLayerAssessment(req, List.copyOf(operations), adequacy, String.join(", ", details));
    }

    /** Sequential parser/use layers are all mandatory; one failed layer fails the path. */
    private static Adequacy combineSequential(List<Adequacy> layers) {
        if (layers.isEmpty()) return Adequacy.UNKNOWN;
        if (layers.stream().anyMatch(a -> a == Adequacy.INADEQUATE)) return Adequacy.INADEQUATE;
        if (layers.stream().anyMatch(a -> a == Adequacy.UNKNOWN)) return Adequacy.UNKNOWN;
        if (layers.stream().anyMatch(a -> a == Adequacy.CONDITIONAL)) return Adequacy.CONDITIONAL;
        return Adequacy.GUARANTEED;
    }
}

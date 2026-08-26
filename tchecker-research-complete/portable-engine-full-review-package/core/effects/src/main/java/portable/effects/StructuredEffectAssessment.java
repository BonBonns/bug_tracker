package portable.effects;

import java.util.*;

/** Conservative assessment across all structural/control-flow alternatives. */
public record StructuredEffectAssessment(List<PathEffectAssessment> paths, Adequacy adequacy) {
    public StructuredEffectAssessment {
        paths = List.copyOf(Objects.requireNonNull(paths));
        adequacy = Objects.requireNonNull(adequacy);
    }
    public boolean guaranteed() { return adequacy == Adequacy.GUARANTEED; }
}

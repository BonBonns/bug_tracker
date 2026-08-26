package portable.effects;

import java.util.*;

/** Conservative merge across alternative return/control-flow branches. */
public final class BranchEffectSummary {
    private BranchEffectSummary() {}

    public static Adequacy combine(Collection<Adequacy> branches) {
        Objects.requireNonNull(branches);
        if (branches.isEmpty()) return Adequacy.UNKNOWN;
        if (branches.stream().allMatch(a -> a == Adequacy.GUARANTEED)) return Adequacy.GUARANTEED;
        if (branches.stream().allMatch(a -> a == Adequacy.INADEQUATE)) return Adequacy.INADEQUATE;
        if (branches.stream().anyMatch(a -> a == Adequacy.UNKNOWN)) return Adequacy.UNKNOWN;
        // Mixed guaranteed/inadequate or an explicitly conditional branch: never promote to guaranteed.
        return Adequacy.CONDITIONAL;
    }
}

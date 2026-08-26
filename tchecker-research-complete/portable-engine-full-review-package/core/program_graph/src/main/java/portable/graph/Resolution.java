package portable.graph;

public enum Resolution {
    EXACT,
    HEURISTIC,
    AMBIGUOUS,
    /** A contribution is POSITIVELY KNOWN but the target/path relation cannot be
     *  bounded (e.g. `buf[i] = input; return buf[0];`). Strictly weaker than
     *  AMBIGUOUS and strictly stronger than UNRESOLVED, which must continue to
     *  mean "not enough evidence to say anything".
     *  NOTE: there is deliberately NO PROVEN_ABSENCE value. Measured 0/263
     *  actionable rows across two corpora support establishing absence from the
     *  current fact model; adding the name would invite the false-completeness
     *  failure this project has repeatedly had to remove. */
    POSSIBLE_UNBOUNDED,
    UNRESOLVED;

    public static Resolution weakest(Resolution a, Resolution b) {
        return rank(a) >= rank(b) ? a : b;
    }

    private static int rank(Resolution r) {
        return switch (r) {
            case EXACT -> 0;
            case HEURISTIC -> 1;
            case AMBIGUOUS -> 2;
            case POSSIBLE_UNBOUNDED -> 3;
            case UNRESOLVED -> 4;
        };
    }
}

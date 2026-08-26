package portable.graph;

import java.util.List;

/**
 * A read from a persistence/state channel. Candidate writes are supplied by the
 * frontend/profile/state model; the provenance core never guesses by key name.
 */
public record PersistenceReadFact(
    long id,
    long functionId,
    PersistenceLocation location,
    List<Long> candidateWriteIds,
    Resolution resolution,
    Integer line
) {
    public PersistenceReadFact {
        candidateWriteIds = List.copyOf(candidateWriteIds);
        int n = candidateWriteIds.size();
        switch (resolution) {
            case EXACT -> { if (n != 1) throw new IllegalArgumentException("EXACT persistence read requires one write"); }
            case AMBIGUOUS -> { if (n < 2) throw new IllegalArgumentException("AMBIGUOUS persistence read requires >=2 writes"); }
            case HEURISTIC -> { if (n < 1) throw new IllegalArgumentException("HEURISTIC persistence read requires >=1 write"); }
            case UNRESOLVED -> { if (n != 0) throw new IllegalArgumentException("UNRESOLVED persistence read requires zero writes"); }
        }
    }
}

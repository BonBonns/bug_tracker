package portable.graph;

import java.util.List;

/**
 * A read from request/session/environment/process state.
 * The frontend/profile must say whether the channel is an external source,
 * linked to demonstrated writes, or currently unmodeled. The provenance core never guesses.
 */
public record StateChannelReadFact(
    long id,
    long functionId,
    StateChannelLocation location,
    StateChannelSourceMode sourceMode,
    List<Long> candidateWriteIds,
    Resolution resolution,
    Integer line
) {
    public StateChannelReadFact {
        candidateWriteIds = List.copyOf(candidateWriteIds);
        int n = candidateWriteIds.size();
        switch (sourceMode) {
            case EXTERNAL_SOURCE -> {
                if (n != 0) throw new IllegalArgumentException("EXTERNAL_SOURCE state read cannot also carry write candidates");
                if (resolution == Resolution.AMBIGUOUS) throw new IllegalArgumentException("EXTERNAL_SOURCE state read cannot be AMBIGUOUS without candidates");
            }
            case WRITE_LINKED -> {
                switch (resolution) {
                    case EXACT -> { if (n != 1) throw new IllegalArgumentException("EXACT state read requires one write"); }
                    case AMBIGUOUS -> { if (n < 2) throw new IllegalArgumentException("AMBIGUOUS state read requires >=2 writes"); }
                    case HEURISTIC -> { if (n < 1) throw new IllegalArgumentException("HEURISTIC state read requires >=1 write"); }
                    case UNRESOLVED -> { if (n != 0) throw new IllegalArgumentException("UNRESOLVED state read requires zero writes"); }
                }
            }
            case UNMODELED -> {
                if (n != 0 || resolution != Resolution.UNRESOLVED)
                    throw new IllegalArgumentException("UNMODELED state read must have no candidates and UNRESOLVED resolution");
            }
        }
    }
}

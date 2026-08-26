package portable.graph;

import java.util.List;

public record CallFact(
    long id,
    long enclosingFunctionId,
    String name,
    String methodFullName,
    String dispatchType,
    String typeFullName,
    String code,
    String file,
    Integer line,
    List<Long> candidateTargetIds,
    List<String> candidateTargetFullNames,
    Resolution resolution,
    List<ArgumentFact> arguments,
    String receiverName
) {
    /** Compat: pre-S02 shape (no receiver binding reference). */
    public CallFact(long id, long enclosingFunctionId, String name, String methodFullName,
                    String dispatchType, String typeFullName, String code, String file, Integer line,
                    List<Long> candidateTargetIds, List<String> candidateTargetFullNames,
                    Resolution resolution, List<ArgumentFact> arguments) {
        this(id, enclosingFunctionId, name, methodFullName, dispatchType, typeFullName, code, file, line,
             candidateTargetIds, candidateTargetFullNames, resolution, arguments, null);
    }
    public CallFact {
        candidateTargetIds = List.copyOf(candidateTargetIds);
        candidateTargetFullNames = List.copyOf(candidateTargetFullNames);
        arguments = List.copyOf(arguments);
        validateResolution(candidateTargetIds.size(), resolution);
    }

    private static void validateResolution(int n, Resolution resolution) {
        switch (resolution) {
            case EXACT -> {
                if (n != 1) throw new IllegalArgumentException("EXACT requires exactly one target, got " + n);
            }
            case AMBIGUOUS -> {
                if (n < 2) throw new IllegalArgumentException("AMBIGUOUS requires >=2 targets, got " + n);
            }
            case UNRESOLVED -> {
                if (n != 0) throw new IllegalArgumentException("UNRESOLVED requires zero targets, got " + n);
            }
            case HEURISTIC -> {
                if (n < 1) throw new IllegalArgumentException("HEURISTIC requires >=1 candidate, got " + n);
            }
        }
    }
}

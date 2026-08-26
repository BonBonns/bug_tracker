package portable.runtime;

import java.util.*;

public record AnalysisRun(
    String schema,
    String engineVersion,
    AnalysisStatus status,
    List<FeatureRegistry.Feature> features,
    Map<String,Long> counters,
    List<AnalysisResultRecord> results,
    List<String> abstentions,
    List<String> truncations,
    String failure
) {
    public AnalysisRun {
        schema = schema == null ? "portable-analysis-run/0.1" : schema;
        engineVersion = Objects.requireNonNullElse(engineVersion, "unknown");
        status = Objects.requireNonNull(status, "status");
        features = List.copyOf(features == null ? List.of() : features);
        counters = Collections.unmodifiableMap(new TreeMap<>(counters == null ? Map.of() : counters));
        results = List.copyOf(results == null ? List.of() : results);
        abstentions = List.copyOf(abstentions == null ? List.of() : abstentions);
        truncations = List.copyOf(truncations == null ? List.of() : truncations);
        failure = Objects.requireNonNullElse(failure, "");
        if (status == AnalysisStatus.COMPLETE && !failure.isBlank())
            throw new IllegalArgumentException("COMPLETE run cannot have failure");
    }
    public boolean complete() { return status == AnalysisStatus.COMPLETE; }
}

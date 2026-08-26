package portable.runtime;

import java.util.*;

/** Machine-diffable analysis result independent of security verdicts. */
public record AnalysisResultRecord(
    String stableId,
    String subject,
    String relationKind,
    String identityPrecision,
    String originStatus,
    String resolution,
    String completeness,
    List<String> provenOrigins,
    List<String> mayOrigins
) {
    public AnalysisResultRecord {
        if (stableId == null || stableId.isBlank()) throw new IllegalArgumentException("stableId required");
        subject = Objects.requireNonNullElse(subject, "");
        relationKind = Objects.requireNonNullElse(relationKind, "");
        identityPrecision = Objects.requireNonNullElse(identityPrecision, "");
        originStatus = Objects.requireNonNullElse(originStatus, "");
        resolution = Objects.requireNonNullElse(resolution, "");
        completeness = Objects.requireNonNullElse(completeness, "");
        provenOrigins = List.copyOf(provenOrigins == null ? List.of() : provenOrigins);
        mayOrigins = List.copyOf(mayOrigins == null ? List.of() : mayOrigins);
    }
}

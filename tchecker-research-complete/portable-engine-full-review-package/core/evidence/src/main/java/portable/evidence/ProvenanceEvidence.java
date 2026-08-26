package portable.evidence;

import portable.graph.Resolution;
import portable.provenance.AnalysisCompleteness;
import portable.provenance.OriginRef;
import portable.provenance.TruncationEvent;

import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * Typed, read-only engine evidence. Identity precision, origin status, path
 * resolution, and analysis completeness are intentionally independent fields.
 */
public record ProvenanceEvidence(
    EvidenceSubject subject,
    RelationKind relationKind,
    IdentityPrecision identityPrecision,
    OriginStatus originStatus,
    Resolution resolution,
    AnalysisCompleteness completeness,
    Set<Integer> provenParameterPositions,
    Set<Integer> mayParameterPositions,
    Set<OriginRef> provenOrigins,
    Set<OriginRef> mayOrigins,
    List<ContextFrame> contextStack,
    List<TruncationEvent> truncations
) {
    public ProvenanceEvidence {
        provenParameterPositions = Set.copyOf(new TreeSet<>(provenParameterPositions));
        TreeSet<Integer> may = new TreeSet<>(mayParameterPositions);
        may.removeAll(provenParameterPositions);
        mayParameterPositions = Set.copyOf(may);
        provenOrigins = Set.copyOf(provenOrigins);
        java.util.HashSet<OriginRef> mo = new java.util.HashSet<>(mayOrigins);
        mo.removeAll(provenOrigins);
        mayOrigins = Set.copyOf(mo);
        contextStack = List.copyOf(contextStack);
        truncations = List.copyOf(truncations);

        if (!truncations.isEmpty() && completeness != AnalysisCompleteness.PARTIAL)
            throw new IllegalArgumentException("truncations require PARTIAL completeness");
        if (originStatus == OriginStatus.PARTIAL && completeness != AnalysisCompleteness.PARTIAL)
            throw new IllegalArgumentException("PARTIAL origin status requires PARTIAL completeness");
        if (originStatus == OriginStatus.ESTABLISHED && provenParameterPositions.isEmpty() && provenOrigins.isEmpty())
            throw new IllegalArgumentException("ESTABLISHED requires a proven origin");
        if (originStatus == OriginStatus.POSSIBLE && mayParameterPositions.isEmpty() && mayOrigins.isEmpty())
            throw new IllegalArgumentException("POSSIBLE requires a may origin");
    }

    /** A proven origin exists independently of whether the exact path/target is resolved. */
    public boolean originEstablished() {
        return originStatus == OriginStatus.ESTABLISHED;
    }

    /**
     * Strict projection for consumers that require an exact hard path. This is
     * deliberately stronger than originEstablished().
     */
    public boolean hardPathEligible() {
        return originStatus == OriginStatus.ESTABLISHED
            && identityPrecision == IdentityPrecision.VALUE_SPECIFIC
            && resolution == Resolution.EXACT
            && completeness == AnalysisCompleteness.COMPLETE;
    }

    /** Evidence is not a security verdict and cannot self-upgrade into one. */
    public boolean hasSecurityVerdict() { return false; }
}

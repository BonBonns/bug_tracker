package portable.consumer;

import java.util.List;

/**
 * Read-only deterministic projection of typed engine evidence.
 * No vulnerability/safety verdict is encoded here: provenance, relation quality,
 * and context-specific effect adequacy remain independent axes.
 */
public record DeterministicEvidenceDecision(
        ProvenanceDisposition provenance,
        RelationDisposition relations,
        EffectDisposition effect,
        boolean hardPathEligible,
        boolean contextEffectGuaranteed,
        List<String> reasons) {
    public DeterministicEvidenceDecision {
        reasons = List.copyOf(reasons);
    }

    public boolean hasSecurityVerdict() { return false; }
}

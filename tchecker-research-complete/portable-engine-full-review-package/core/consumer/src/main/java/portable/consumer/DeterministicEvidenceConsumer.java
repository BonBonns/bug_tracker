package portable.consumer;

import portable.evidence.*;
import portable.effects.*;
import portable.graph.Resolution;
import portable.provenance.AnalysisCompleteness;

import java.util.*;

/**
 * Deterministic consumer for the portable typed evidence contract.
 *
 * Design constraints inherited from the measured legacy-engine failures:
 * - identity precision != origin establishment;
 * - established origin != exact hard path;
 * - NOT_ESTABLISHED/PARTIAL are not equivalent to NO_ORIGIN;
 * - explicit abstentions stay visible;
 * - effect adequacy is evaluated only for the supplied context stack and never
 *   upgrades/downgrades provenance.
 */
public final class DeterministicEvidenceConsumer {

    public DeterministicEvidenceDecision evaluate(ProvenanceEvidence evidence) {
        return evaluate(evidence, List.of(), null);
    }

    public DeterministicEvidenceDecision evaluate(
            ProvenanceEvidence evidence,
            List<EvidenceRelation> relations,
            ContextStackAssessment effectAssessment) {
        Objects.requireNonNull(evidence, "evidence");
        relations = relations == null ? List.of() : List.copyOf(relations);

        List<String> reasons = new ArrayList<>();
        ProvenanceDisposition p = provenanceDisposition(evidence, reasons);
        RelationDisposition r = relationDisposition(relations, reasons);
        EffectDisposition e = effectDisposition(evidence, effectAssessment, reasons);

        boolean hard = evidence.hardPathEligible()
                && p == ProvenanceDisposition.HARD_PATH
                && (r == RelationDisposition.ALL_ESTABLISHED || r == RelationDisposition.NO_RELATIONS);
        boolean effectGuaranteed = e == EffectDisposition.GUARANTEED_FOR_CONTEXT;

        return new DeterministicEvidenceDecision(p, r, e, hard, effectGuaranteed, reasons);
    }

    private ProvenanceDisposition provenanceDisposition(ProvenanceEvidence e, List<String> reasons) {
        // Consume completeness/truncation before origin absence: a stopped analysis
        // must never become "no origin".
        if (e.completeness() == AnalysisCompleteness.PARTIAL || !e.truncations().isEmpty() || e.originStatus() == OriginStatus.PARTIAL) {
            reasons.add("analysis partial/truncated");
            e.truncations().forEach(t -> reasons.add("truncation:" + t.kind()));
            return ProvenanceDisposition.PARTIAL;
        }

        return switch (e.originStatus()) {
            case NONE -> {
                reasons.add("complete analysis demonstrated no origin");
                yield ProvenanceDisposition.NO_ORIGIN;
            }
            case NOT_ESTABLISHED -> {
                reasons.add("origin not established");
                yield ProvenanceDisposition.NOT_ESTABLISHED;
            }
            case POSSIBLE -> {
                reasons.add("origin possible but not proven");
                yield ProvenanceDisposition.POSSIBLE_ORIGIN;
            }
            case ESTABLISHED -> {
                // Explicitly consume identity + resolution + completeness, rather
                // than using ESTABLISHED as a proxy for an exact path.
                if (e.identityPrecision() == IdentityPrecision.VALUE_SPECIFIC
                        && e.resolution() == Resolution.EXACT
                        && e.completeness() == AnalysisCompleteness.COMPLETE) {
                    reasons.add("value-specific exact complete origin path");
                    yield ProvenanceDisposition.HARD_PATH;
                }
                reasons.add("origin established but exact hard path not established");
                if (e.identityPrecision() != IdentityPrecision.VALUE_SPECIFIC)
                    reasons.add("identity_precision:" + e.identityPrecision());
                if (e.resolution() != Resolution.EXACT)
                    reasons.add("resolution:" + e.resolution());
                yield ProvenanceDisposition.ESTABLISHED_ORIGIN_UNCERTAIN_PATH;
            }
            case PARTIAL -> ProvenanceDisposition.PARTIAL; // handled above; keeps switch exhaustive
        };
    }

    private RelationDisposition relationDisposition(List<EvidenceRelation> relations, List<String> reasons) {
        if (relations.isEmpty()) return RelationDisposition.NO_RELATIONS;
        boolean possible = false;
        for (EvidenceRelation rel : relations) {
            // Consume relation kind/status and preserve explicit abstention.
            if (rel.kind() == RelationKind.ABSTENTION || rel.status() == RelationStatus.ABSTAINED) {
                reasons.add("relation abstained:" + rel.abstentionReason());
                return RelationDisposition.ABSTAINED_RELATION;
            }
            if (rel.status() == RelationStatus.POSSIBLE || rel.resolution() != Resolution.EXACT) {
                possible = true;
                reasons.add("non-exact relation:" + rel.kind() + ":" + rel.resolution());
            }
        }
        return possible ? RelationDisposition.POSSIBLE_RELATION : RelationDisposition.ALL_ESTABLISHED;
    }

    private EffectDisposition effectDisposition(
            ProvenanceEvidence evidence,
            ContextStackAssessment assessment,
            List<String> reasons) {
        if (assessment == null) return EffectDisposition.NOT_EVALUATED;

        // The evidence and effect evaluator must be talking about the same number
        // of parser/use-context layers. A mismatch is an explicit unknown, not a
        // guessed guarantee.
        int evidenceLayers = evidence.contextStack().size();
        int assessedLayers = assessment.stack().size();
        if (evidenceLayers != assessedLayers) {
            reasons.add("context stack mismatch:evidence=" + evidenceLayers + ",assessment=" + assessedLayers);
            return EffectDisposition.UNKNOWN_FOR_CONTEXT;
        }
        if (!assessment.complete()) {
            reasons.add("context assessment incomplete");
            return EffectDisposition.UNKNOWN_FOR_CONTEXT;
        }
        return switch (assessment.adequacy()) {
            case GUARANTEED -> {
                reasons.add("effect demonstrated for exact supplied context stack");
                yield EffectDisposition.GUARANTEED_FOR_CONTEXT;
            }
            case CONDITIONAL -> {
                reasons.add("effect only conditional for supplied context stack");
                yield EffectDisposition.CONDITIONAL_FOR_CONTEXT;
            }
            case INADEQUATE -> {
                reasons.add("effect inadequate for supplied context stack");
                yield EffectDisposition.INADEQUATE_FOR_CONTEXT;
            }
            case UNKNOWN -> {
                reasons.add("effect unknown for supplied context stack");
                yield EffectDisposition.UNKNOWN_FOR_CONTEXT;
            }
        };
    }
}

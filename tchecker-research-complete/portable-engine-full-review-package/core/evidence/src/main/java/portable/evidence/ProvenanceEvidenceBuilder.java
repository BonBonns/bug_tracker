package portable.evidence;

import portable.graph.*;
import portable.provenance.*;

import java.util.List;
import java.util.Objects;

/** Read-only projection from neutral provenance summaries to typed evidence. */
public final class ProvenanceEvidenceBuilder {
    private final ProgramGraph graph;
    private final PortableProvenanceEngine engine;

    public ProvenanceEvidenceBuilder(ProgramGraph graph, PortableProvenanceEngine engine) {
        this.graph = Objects.requireNonNull(graph);
        this.engine = Objects.requireNonNull(engine);
    }

    public ProvenanceEvidence functionReturn(long functionId) {
        return functionReturn(functionId, List.of());
    }

    public ProvenanceEvidence functionReturn(long functionId, List<ContextFrame> contextStack) {
        FunctionFact f = graph.function(functionId).orElseThrow();
        ProvenanceSummary summary = engine.summarize(functionId);
        List<ReturnFact> returns = graph.returnsIn(functionId);

        IdentityPrecision identity = returns.size() == 1
            ? IdentityPrecision.VALUE_SPECIFIC
            : returns.isEmpty() ? IdentityPrecision.FUNCTION_LEVEL : IdentityPrecision.MULTI_VALUE;

        OriginStatus origin = originStatus(summary);
        return new ProvenanceEvidence(
            new EvidenceSubject(f.id(), f.name(), "FUNCTION_RETURN"),
            RelationKind.RETURN_PROVENANCE,
            identity,
            origin,
            summary.resolution(),
            summary.completeness(),
            summary.provenPositions(),
            summary.mayPositions(),
            summary.provenOrigins(),
            summary.mayOrigins(),
            contextStack,
            summary.truncations()
        );
    }

    static OriginStatus originStatus(ProvenanceSummary s) {
        if (s.completeness() == AnalysisCompleteness.PARTIAL) return OriginStatus.PARTIAL;
        if (!s.provenPositions().isEmpty() || !s.provenOrigins().isEmpty()) return OriginStatus.ESTABLISHED;
        if (!s.mayPositions().isEmpty() || !s.mayOrigins().isEmpty()) return OriginStatus.POSSIBLE;
        if (s.unknown() || s.completeness() == AnalysisCompleteness.UNKNOWN) return OriginStatus.NOT_ESTABLISHED;
        return OriginStatus.NONE;
    }
}

import portable.graph.*;
import portable.provenance.*;
import portable.evidence.*;
import java.nio.file.Path;

/** JSTS-R05: real TS -> jssrc2cpg -> neutral facts -> loader -> PortableProvenanceEngine -> evidence. */
public final class EndToEndRunner {
    public static void main(String[] args) throws Exception {
        // Schema ROUTER: every extra document is dispatched by its own declared
        // schema, order-independent (state/identity/capture/crosslang/memory).
        java.util.List<Path> extras = new java.util.ArrayList<>();
        for (int i = 1; i < args.length; i++) extras.add(Path.of(args[i]));
        ProgramGraph g = ProgramGraphLoader.loadAll(Path.of(args[0]), extras);
        if (!g.crossLangLinks().isEmpty()) System.out.println("CROSSLANG_LINKS edges=" + g.crossLangLinks().size());
        if (!g.reachingDefs().isEmpty()) System.out.println("REACHING_DEFS narrowed_uses=" + g.reachingDefs().size());
        if (!g.expressionFacts().isEmpty()) System.out.println("EXPRESSION_FACTS combined=" + g.expressionFacts().size());
        if (!g.memoryLocations().isEmpty()) System.out.println("MEMORY_FACTS locations=" + g.memoryLocations().size() + " points_to=" + g.pointsTo().size());
        if (!g.captureFacts().isEmpty()) System.out.println("CAPTURE_FACTS chains=" + g.captureFacts().size());
        if (!g.identityFacts().isEmpty()) System.out.println("IDENTITY_FACTS bindings=" + g.identityFacts().size());
        if (args.length > 1) {
            java.util.Map<String, Integer> rules = new java.util.TreeMap<>();
            for (StateWriteFact w : g.stateWrites()) rules.merge(w.derivation().rule(), 1, Integer::sum);
            for (StateReadFact r : g.stateReads()) rules.merge(r.derivation().rule(), 1, Integer::sum);
            System.out.println("STATE_FACTS writes=" + g.stateWrites().size()
                + " reads=" + g.stateReads().size() + " derivation=" + rules);
        }
        System.out.println("LOADED frontend=" + g.frontend()
            + " functions=" + g.functions().size()
            + " calls=" + g.calls().size()
            + " returns=" + g.returns().size());
        PortableProvenanceEngine engine = new PortableProvenanceEngine(g);
        ProvenanceEvidenceBuilder evidence = new ProvenanceEvidenceBuilder(g, engine);
        for (FunctionFact f : g.functions()) {
            // Skip only true non-user-code noise: external (unresolved) stubs, the
            // module top-level wrapper (":program"), and Joern operator pseudo-methods
            // (e.g. "<operator>.assignment"). Named lambdas ("<lambda>N") and
            // constructors ("<init>") ARE real user code and must be reported —
            // hiding them was a demo-script bug, not an engine limitation.
            if (f.external() || f.name().isEmpty() || f.name().equals(":program")
                || f.name().startsWith("<operator>")) continue;
            ProvenanceSummary s = engine.summarize(f.id());
            System.out.println("SUMMARY " + f.name()
                + " resolution=" + s.resolution()
                + " proven=" + s.provenPositions()
                + " may=" + s.mayPositions()
                + " unknown=" + s.unknown()
                + " completeness=" + s.completeness());
            ProvenanceEvidence e = evidence.functionReturn(f.id());
            System.out.println("EVIDENCE " + f.name()
                + " identity=" + e.identityPrecision()
                + " origin=" + e.originStatus()
                + " resolution=" + e.resolution()
                + " completeness=" + e.completeness());
        }
        // SINK-R01: observe provenance at call-argument positions named by
        // SINKS=name:argIndex[,name:argIndex...]. Reporting only; the engine's
        // semantics are identical to the return query.
        String sinks = System.getenv("SINKS");
        if (sinks != null && !sinks.isBlank()) {
            for (String spec : sinks.split(",")) {
                String[] parts = spec.trim().split(":");
                String nm = parts[0];
                int ai = parts.length > 1 ? Integer.parseInt(parts[1]) : 0;
                for (CallFact c : g.calls()) {
                    if (!nm.equals(c.name())) continue;
                    var fn = g.function(c.enclosingFunctionId()).map(FunctionFact::name).orElse("?");
                    var sm = engine.summarizeSinkArgument(c.id(), ai);
                    System.out.println("SINK " + fn + " " + nm + "#" + ai
                        + " resolution=" + sm.resolution()
                        + " proven=" + sm.provenPositions()
                        + " may=" + sm.mayPositions()
                        + " unknown=" + sm.unknown()
                        + " origins=" + sm.provenOrigins().stream()
                            .map(o -> o.kind() + "@" + o.channelLocation()).sorted().toList()
                        + " mayOrigins=" + sm.mayOrigins().stream()
                            .map(o -> o.kind() + "@" + o.channelLocation()).sorted().toList());
                }
            }
        }
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

import portable.graph.*;
import portable.provenance.*;
import java.nio.file.*;
import java.util.*;

/** CORE-S05: parameter-targeted source origins and origin-kind separation. */
public final class CoreS05Test {
    static int pass = 0, total = 0;
    static void ck(String name, boolean value, Object detail) {
        total++; if (value) pass++;
        System.out.println((value ? "PASS " : "FAIL ") + name + (value ? "" : " - " + detail));
    }
    static FactDerivation d() {
        return new FactDerivation("FRONTEND_COMPOSED", "JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE", List.of(20L));
    }
    static ProgramGraph graph(boolean withSource, String originKind) {
        long fid = 10, pid = 11;
        FunctionFact fn = new FunctionFact(fid, "handler", "x.js::program:handler", "", "x.js",
            1, 3, false, List.of(new ParameterFact(pid, fid, 0, "message", "message", "ANY", 1)), "");
        List<SourceOriginFact> sources = withSource
            ? List.of(new SourceOriginFact(20, fid, pid, SourceOriginFact.TargetKind.PARAMETER,
                originKind, "runtime.onMessageExternal", d()))
            : List.of();
        return new IndexedProgramGraph(new InMemoryProgramGraph("test", List.of(fn), List.of(), List.of(),
            List.of(new ReturnFact(30, fid, ValueRef.parameter(pid, "message"), 2)),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(),
            List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), sources));
    }
    public static void main(String[] args) throws Exception {
        ProvenanceSummary webext = new PortableProvenanceEngine(
            graph(true, "WEBEXT_EXTERNAL_MESSAGE_INPUT")).summarize(10);
        ck("registered callback source is MAY, never fabricated EXACT",
            webext.resolution() == Resolution.AMBIGUOUS && webext.provenOrigins().isEmpty(), webext);
        ck("ordinary caller parameter alternative is retained",
            webext.mayPositions().equals(new TreeSet<>(Set.of(0))), webext);
        ck("WebExtension origin kind survives without FILE_INPUT collapse",
            webext.mayOrigins().stream().anyMatch(o -> o.kind() == OriginRef.Kind.WEBEXT_EXTERNAL_MESSAGE_INPUT)
                && webext.mayOrigins().stream().noneMatch(o -> o.kind() == OriginRef.Kind.FILE_INPUT), webext);

        ProvenanceSummary ordinary = new PortableProvenanceEngine(graph(false, "unused")).summarize(10);
        ck("class separation: unregistered parameter remains ordinary exact input",
            ordinary.resolution() == Resolution.EXACT
                && ordinary.provenPositions().equals(new TreeSet<>(Set.of(0)))
                && ordinary.provenOrigins().isEmpty() && ordinary.mayOrigins().isEmpty(), ordinary);

        Path good = Files.createTempFile("source-param", ".json");
        Files.writeString(good, """
          {"schema":"portable-source-facts/0.1","source_origins":[{
            "id":20,"function_id":10,"target_local_id":11,"target_kind":"PARAMETER",
            "origin_kind":"WEBEXT_EXTERNAL_MESSAGE_INPUT","location":"runtime.onMessageExternal",
            "derivation":{"origin":"FRONTEND_COMPOSED","rule":"TEST","source_node_ids":[20]}
          }]}
          """);
        var loaded = ProgramGraphLoader.loadSourceOriginFacts(good);
        ck("loader consumes explicit PARAMETER target kind",
            loaded.size() == 1 && loaded.get(0).targetKind() == SourceOriginFact.TargetKind.PARAMETER,
            loaded);

        Path missing = Files.createTempFile("source-missing-kind", ".json");
        Files.writeString(missing, """
          {"schema":"portable-source-facts/0.1","source_origins":[{
            "id":20,"function_id":10,"target_local_id":11,
            "origin_kind":"WEBEXT_EXTERNAL_MESSAGE_INPUT",
            "derivation":{"origin":"FRONTEND_COMPOSED","rule":"TEST","source_node_ids":[20]}
          }]}
          """);
        boolean rejected = false;
        try { ProgramGraphLoader.loadSourceOriginFacts(missing); }
        catch (IllegalArgumentException ex) { rejected = ex.getMessage().contains("target_kind"); }
        ck("loader rejects source facts missing target class", rejected, "accepted");

        boolean unknownRejected = false;
        try { new PortableProvenanceEngine(graph(true, "GENERIC_EXTERNAL")).summarize(10); }
        catch (IllegalArgumentException ex) { unknownRejected = ex.getMessage().contains("unsupported source origin kind"); }
        ck("unknown origin kinds fail closed instead of collapsing to FILE_INPUT", unknownRejected, "accepted");

        System.out.println("CORE_S05=" + pass + "/" + total);
        System.exit(pass == total ? 0 : 1);
    }
}

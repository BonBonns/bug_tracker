package portable.graph;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Strict, boring loader: portable-program-facts JSON -> ProgramGraph.
 *
 * Boundary contract (deliberate):
 *  - NO semantic inference. All language/frontend interpretation (dispatch
 *    correction, this-normalization, value-ref resolution, stub handling) happened
 *    in the frontend extraction layer. This class only validates and deserializes.
 *  - Unknown schema, unknown resolution, unknown value_ref kind, or arity-invalid
 *    calls fail loudly (CallFact's own validation enforces per-resolution arity).
 *  - Zero dependencies: a minimal strict JSON parser is embedded so the neutral
 *    core stays dependency-free.
 */
public final class ProgramGraphLoader {

    /** Explicitly enumerable schema support. A KNOWN fact family this loader version
     *  does not consume fails with UNSUPPORTED_FACT_FAMILY — never silently ignored —
     *  so "no state facts" can never be confused with "loader skipped state facts". */
    public static final Set<String> ACCEPTED_SCHEMAS = Set.of("portable-program-facts/0.3");
    public static final String STATE_SCHEMA = "portable-state-facts/0.4";
    public static final String LEGACY_STATE_SCHEMA = "portable-state-facts/0.3";
    public static final String IDENTITY_SCHEMA = "portable-identity-facts/0.2";
    public static final String CAPTURE_SCHEMA = "portable-capture-facts/0.2";
    public static final String CROSSLANG_SCHEMA = "portable-crosslang-facts/0.1";
    public static final String MEMORY_SCHEMA = "portable-memory-facts/0.1";
    public static final String EXPRESSION_SCHEMA = "portable-expression-facts/0.1";
    public static final String REACHINGDEF_SCHEMA = "portable-reachingdef-facts/0.1";
    public static final String SOURCE_SCHEMA = "portable-source-facts/0.1";
    public static final Set<String> KNOWN_UNCONSUMED_FAMILIES = Set.of(
        "portable-state-facts/0.2",     // superseded; lacks receiver_ref/value_ref/location
        // portable-identity-facts/0.2 is consumed since CORE-S02 (loadIdentityFacts)
        "portable-capture-facts/0.1");  // superseded by 0.2 (0.1 lacks node ids)

    public static ProgramGraph load(Path jsonFile) throws Exception {
        Object root = Json.parse(Files.readString(jsonFile));
        Map<String, Object> doc = obj(root, "document");

        String schema = str(doc.get("schema"), "schema");
        if (KNOWN_UNCONSUMED_FAMILIES.contains(schema)) {
            throw new IllegalArgumentException(
                "UNSUPPORTED_FACT_FAMILY: " + schema + " is a known neutral fact family, but this"
                + " loader version consumes only " + ACCEPTED_SCHEMAS
                + " (phase 1: program facts). Ingest it with the fact-family loader once the"
                + " corresponding CORE gate adds its ProgramGraph vocabulary.");
        }
        if (!ACCEPTED_SCHEMAS.contains(schema)) {
            throw new IllegalArgumentException("unsupported schema: " + schema + " (accepted: " + ACCEPTED_SCHEMAS + ")");
        }
        String frontend = doc.containsKey("frontend") ? str(doc.get("frontend"), "frontend") : "unknown";

        List<FunctionFact> functions = new ArrayList<>();
        for (Object o : arr(doc.get("functions"), "functions")) {
            Map<String, Object> f = obj(o, "function");
            List<ParameterFact> params = new ArrayList<>();
            for (Object po : arr(f.getOrDefault("parameters", List.of()), "parameters")) {
                Map<String, Object> p = obj(po, "parameter");
                params.add(new ParameterFact(
                    lng(p.get("id"), "param.id"), lng(f.get("id"), "function.id"),
                    (int) lng(p.get("index"), "param.index"),
                    str(p.getOrDefault("name", ""), "param.name"),
                    str(p.getOrDefault("code", ""), "param.code"),
                    str(p.getOrDefault("type_full_name", ""), "param.type"),
                    intOrNull(p.get("line"))));
            }
            functions.add(new FunctionFact(
                lng(f.get("id"), "function.id"),
                str(f.getOrDefault("name", ""), "function.name"),
                str(f.getOrDefault("full_name", ""), "function.full_name"),
                str(f.getOrDefault("signature", ""), "function.signature"),
                str(f.getOrDefault("file", ""), "function.file"),
                intOrNull(f.get("line")), intOrNull(f.get("line_end")),
                bool(f.getOrDefault("is_external", Boolean.FALSE)),
                params,
                str(f.getOrDefault("return_type_full_name", ""), "function.return_type")));
        }

        List<TypeDeclFact> typeDecls = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("type_decls", List.of()), "type_decls")) {
            Map<String, Object> t = obj(o, "type_decl");
            List<String> inherits = new ArrayList<>();
            for (Object io : arr(t.getOrDefault("inherits_from", List.of()), "inherits_from")) inherits.add(str(io, "inherits"));
            typeDecls.add(new TypeDeclFact(
                lng(t.get("id"), "type.id"), str(t.getOrDefault("name", ""), "type.name"),
                str(t.getOrDefault("full_name", ""), "type.full_name"),
                str(t.getOrDefault("file", ""), "type.file"), intOrNull(t.get("line")),
                bool(t.getOrDefault("is_external", Boolean.FALSE)), inherits));
        }

        List<CallFact> calls = new ArrayList<>();
        for (Object o : arr(doc.get("calls"), "calls")) {
            Map<String, Object> c = obj(o, "call");
            List<Long> targetIds = new ArrayList<>();
            for (Object t : arr(c.getOrDefault("candidate_target_ids", List.of()), "candidate_target_ids")) targetIds.add(lng(t, "target_id"));
            List<String> targetNames = new ArrayList<>();
            for (Object t : arr(c.getOrDefault("candidate_target_full_names", List.of()), "target_names")) targetNames.add(str(t, "target_name"));
            List<ArgumentFact> arguments = new ArrayList<>();
            for (Object ao : arr(c.getOrDefault("arguments", List.of()), "arguments")) {
                Map<String, Object> a = obj(ao, "argument");
                arguments.add(new ArgumentFact(
                    lng(a.get("id"), "arg.id"), (int) lng(a.get("index"), "arg.index"),
                    str(a.getOrDefault("kind", ""), "arg.kind"),
                    str(a.getOrDefault("code", ""), "arg.code"),
                    str(a.getOrDefault("name", ""), "arg.name"),
                    str(a.getOrDefault("type_full_name", ""), "arg.type"),
                    intOrNull(a.get("line")),
                    valueRef(a.get("value_ref"), "arg.value_ref")));
            }
            calls.add(new CallFact(
                lng(c.get("id"), "call.id"), lng(c.get("enclosing_function_id"), "call.enclosing"),
                str(c.getOrDefault("name", ""), "call.name"),
                str(c.getOrDefault("method_full_name", ""), "call.mfn"),
                str(c.getOrDefault("dispatch_type", ""), "call.dispatch"),
                str(c.getOrDefault("type_full_name", ""), "call.type"),
                str(c.getOrDefault("code", ""), "call.code"),
                str(c.getOrDefault("file", ""), "call.file"),
                intOrNull(c.get("line")),
                targetIds, targetNames,
                resolution(c.get("resolution")),
                arguments,
                c.containsKey("receiver_name") ? str(c.get("receiver_name"), "call.receiver_name") : null));
        }

        List<ReturnFact> returns = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("returns", List.of()), "returns")) {
            Map<String, Object> r = obj(o, "return");
            returns.add(new ReturnFact(
                lng(r.get("id"), "return.id"), lng(r.get("function_id"), "return.function_id"),
                valueRef(r.get("value_ref"), "return.value_ref"), intOrNull(r.get("line"))));
        }

        List<LocalFact> locals = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("locals", List.of()), "locals")) {
            Map<String, Object> l = obj(o, "local");
            locals.add(new LocalFact(
                lng(l.get("id"), "local.id"), lng(l.get("method_id"), "local.method_id"),
                str(l.getOrDefault("name", ""), "local.name"),
                str(l.getOrDefault("type_full_name", ""), "local.type"), intOrNull(l.get("line"))));
        }

        List<AssignmentFact> assignments = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("assignments", List.of()), "assignments")) {
            Map<String, Object> a = obj(o, "assignment");
            assignments.add(new AssignmentFact(
                lng(a.get("id"), "assignment.id"), lng(a.get("function_id"), "assignment.function_id"),
                lng(a.get("target_local_id"), "assignment.target_local_id"),
                valueRef(a.get("value_ref"), "assignment.value_ref"), intOrNull(a.get("line"))));
        }

        return new InMemoryProgramGraph(frontend, functions, typeDecls, calls, returns, locals, assignments);
    }

    /** Combined load: program facts + keyed-state facts (0.4, with 0.3 compatibility). */
    public static ProgramGraph load(Path programJson, Path stateJson) throws Exception {
        InMemoryProgramGraph base = (InMemoryProgramGraph) load(programJson);
        StateFacts st = loadStateFacts(stateJson);
        return new InMemoryProgramGraph(base.frontend(), base.functions(), base.typeDecls(), base.calls(),
            base.returns(), base.locals(), base.assignments(), base.persistenceWrites(), base.persistenceReads(),
            base.stateChannelWrites(), base.stateChannelReads(), st.writes(), st.reads());
    }

    public record StateFacts(List<StateWriteFact> writes, List<StateReadFact> reads) {}

    /** Combined load: program + state + identity facts. */
    public static ProgramGraph load(Path programJson, Path stateJson, Path identityJson) throws Exception {
        InMemoryProgramGraph base = (InMemoryProgramGraph) load(programJson, stateJson);
        List<IdentityFact> ids = loadIdentityFacts(identityJson);
        return new InMemoryProgramGraph(base.frontend(), base.functions(), base.typeDecls(), base.calls(),
            base.returns(), base.locals(), base.assignments(), base.persistenceWrites(), base.persistenceReads(),
            base.stateChannelWrites(), base.stateChannelReads(), base.stateWrites(), base.stateReads(), ids);
    }

    /** Combined load: program + state + identity + capture facts. */
    public static ProgramGraph load(Path programJson, Path stateJson, Path identityJson, Path captureJson) throws Exception {
        InMemoryProgramGraph base = (InMemoryProgramGraph) load(programJson, stateJson, identityJson);
        List<CaptureFact> caps = loadCaptureFacts(captureJson);
        return new InMemoryProgramGraph(base.frontend(), base.functions(), base.typeDecls(), base.calls(),
            base.returns(), base.locals(), base.assignments(), base.persistenceWrites(), base.persistenceReads(),
            base.stateChannelWrites(), base.stateChannelReads(), base.stateWrites(), base.stateReads(),
            base.identityFacts(), caps);
    }

    /** Combined load: program + state + identity + capture + crosslang facts. */
    public static ProgramGraph load(Path programJson, Path stateJson, Path identityJson, Path captureJson, Path crossLangJson) throws Exception {
        InMemoryProgramGraph base = (InMemoryProgramGraph) load(programJson, stateJson, identityJson, captureJson);
        List<CrossLangLinkFact> links = loadCrossLangFacts(crossLangJson);
        return new InMemoryProgramGraph(base.frontend(), base.functions(), base.typeDecls(), base.calls(),
            base.returns(), base.locals(), base.assignments(), base.persistenceWrites(), base.persistenceReads(),
            base.stateChannelWrites(), base.stateChannelReads(), base.stateWrites(), base.stateReads(),
            base.identityFacts(), base.captureFacts(), links);
    }

    /** Schema ROUTER: load a program doc plus any set of extra fact documents,
     *  dispatched by each document's own declared schema (order-independent).
     *  Unknown schemas fail loudly; a family supplied twice fails loudly. */
    public static ProgramGraph loadAll(Path programJson, List<Path> extraDocs) throws Exception {
        InMemoryProgramGraph base = (InMemoryProgramGraph) load(programJson);
        List<StateWriteFact> sw = base.stateWrites(); List<StateReadFact> sr = base.stateReads();
        List<IdentityFact> ids = base.identityFacts(); List<CaptureFact> caps = base.captureFacts();
        List<CrossLangLinkFact> links = base.crossLangLinks();
        List<MemoryLocationFact> mem = base.memoryLocations(); List<PointsToFact> pts = base.pointsTo();
        List<ExpressionFact> exprs = base.expressionFacts();
        List<ReachingDefFact> rdefs = base.reachingDefs();
        List<SourceOriginFact> srcs = base.sourceOrigins();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (Path doc : extraDocs) {
            String schema = str(obj(Json.parse(Files.readString(doc)), "fact document").get("schema"), "schema");
            String family = LEGACY_STATE_SCHEMA.equals(schema) ? STATE_SCHEMA : schema;
            if (!seen.add(family))
                throw new IllegalArgumentException("fact family supplied twice: " + schema);
            switch (schema) {
                case STATE_SCHEMA, LEGACY_STATE_SCHEMA -> {
                    StateFacts st = loadStateFacts(doc); sw = st.writes(); sr = st.reads();
                }
                case IDENTITY_SCHEMA -> ids = loadIdentityFacts(doc);
                case CAPTURE_SCHEMA -> caps = loadCaptureFacts(doc);
                case CROSSLANG_SCHEMA -> links = loadCrossLangFacts(doc);
                case MEMORY_SCHEMA -> { MemoryFacts mf = loadMemoryFacts(doc); mem = mf.locations(); pts = mf.pointsTo(); }
                case EXPRESSION_SCHEMA -> exprs = loadExpressionFacts(doc);
                case REACHINGDEF_SCHEMA -> rdefs = loadReachingDefFacts(doc);
                case SOURCE_SCHEMA -> srcs = loadSourceOriginFacts(doc);
                default -> throw new IllegalArgumentException("unsupported fact document schema: " + schema);
            }
        }
        return new IndexedProgramGraph(new InMemoryProgramGraph(base.frontend(), base.functions(), base.typeDecls(),
            base.calls(), base.returns(), base.locals(), base.assignments(), base.persistenceWrites(),
            base.persistenceReads(), base.stateChannelWrites(), base.stateChannelReads(), sw, sr, ids, caps, links, mem, pts, exprs, rdefs, srcs));
    }

    public record MemoryFacts(List<MemoryLocationFact> locations, List<PointsToFact> pointsTo) {}

    /** Strict deserialization of portable-source-facts/0.1. */
    public static List<SourceOriginFact> loadSourceOriginFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "source document");
        String schema = str(doc.get("schema"), "schema");
        if (!SOURCE_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported source schema: " + schema);
        List<SourceOriginFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("source_origins", List.of()), "source_origins")) {
            Map<String, Object> r = obj(o, "source_origin");
            out.add(new SourceOriginFact(
                lng(r.get("id"), "source.id"),
                lng(r.get("function_id"), "source.function_id"),
                lng(r.get("target_local_id"), "source.target_local_id"),
                SourceOriginFact.TargetKind.valueOf(str(r.get("target_kind"), "source.target_kind")),
                str(r.get("origin_kind"), "source.origin_kind"),
                r.get("location") == null ? "" : String.valueOf(r.get("location")),
                derivation(r.get("derivation"), "source.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-reachingdef-facts/0.1. */
    public static List<ReachingDefFact> loadReachingDefFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "reaching-def document");
        String schema = str(doc.get("schema"), "schema");
        if (!REACHINGDEF_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported reaching-def schema: " + schema + " (accepted: " + REACHINGDEF_SCHEMA + ")");
        List<ReachingDefFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("reaching_defs", List.of()), "reaching_defs")) {
            Map<String, Object> r = obj(o, "reaching_def");
            List<Long> defs = new ArrayList<>();
            for (Object x : arr(r.get("def_ids"), "def_ids")) defs.add(lng(x, "def_id"));
            out.add(new ReachingDefFact(
                lng(r.get("use_id"), "reaching_def.use_id"),
                lng(r.get("function_id"), "reaching_def.function_id"),
                lng(r.get("local_id"), "reaching_def.local_id"),
                defs,
                resolution(r.get("resolution")),
                derivation(r.get("derivation"), "reaching_def.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-expression-facts/0.1. */
    public static List<ExpressionFact> loadExpressionFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "expression document");
        String schema = str(doc.get("schema"), "schema");
        if (!EXPRESSION_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported expression schema: " + schema + " (accepted: " + EXPRESSION_SCHEMA + ")");
        List<ExpressionFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("expressions", List.of()), "expressions")) {
            Map<String, Object> e = obj(o, "expression");
            List<ValueRef> ops = new ArrayList<>();
            for (Object v : arr(e.get("operands"), "operands")) ops.add(valueRef(v, "expression.operand"));
            out.add(new ExpressionFact(
                lng(e.get("id"), "expression.id"),
                lng(e.get("function_id"), "expression.function_id"),
                str(e.get("operator"), "expression.operator"),
                ops,
                resolution(e.get("resolution")),
                derivation(e.get("derivation"), "expression.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-memory-facts/0.1. */
    public static MemoryFacts loadMemoryFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "memory document");
        String schema = str(doc.get("schema"), "schema");
        if (!MEMORY_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported memory schema: " + schema + " (accepted: " + MEMORY_SCHEMA + ")");
        List<MemoryLocationFact> locs = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("memory_locations", List.of()), "memory_locations")) {
            Map<String, Object> m = obj(o, "memory_location");
            String kind = str(m.get("kind"), "memory_location.kind");
            locs.add(new MemoryLocationFact(
                lng(m.get("id"), "memory_location.id"),
                lng(m.get("function_id"), "memory_location.function_id"),
                switch (kind) {
                    case "FIELD" -> MemoryLocationFact.Kind.FIELD;
                    case "INDEX" -> MemoryLocationFact.Kind.INDEX;
                    default -> throw new IllegalArgumentException("unknown memory location kind: " + kind);
                },
                lng(m.get("base_id"), "memory_location.base_id"),
                str(m.get("selector"), "memory_location.selector"),
                str(m.get("name"), "memory_location.name"),
                resolution(m.get("resolution")),
                derivation(m.get("derivation"), "memory_location.derivation")));
        }
        List<PointsToFact> pts = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("points_to", List.of()), "points_to")) {
            Map<String, Object> m = obj(o, "points_to");
            List<Long> targets = new ArrayList<>();
            for (Object t : arr(m.get("target_ids"), "target_ids")) targets.add(lng(t, "target"));
            pts.add(new PointsToFact(
                lng(m.get("function_id"), "points_to.function_id"),
                lng(m.get("pointer_binding_id"), "points_to.pointer_binding_id"),
                str(m.get("pointer_binding"), "points_to.pointer_binding"),
                targets,
                bool(m.get("must")),
                resolution(m.get("resolution")),
                derivation(m.get("derivation"), "points_to.derivation")));
        }
        return new MemoryFacts(locs, pts);
    }

    /** Strict deserialization of portable-crosslang-facts/0.1. */
    public static List<CrossLangLinkFact> loadCrossLangFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "crosslang document");
        String schema = str(doc.get("schema"), "schema");
        if (!CROSSLANG_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported crosslang schema: " + schema + " (accepted: " + CROSSLANG_SCHEMA + ")");
        List<CrossLangLinkFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("links", List.of()), "links")) {
            Map<String, Object> l = obj(o, "link");
            out.add(new CrossLangLinkFact(
                lng(l.get("js_call_id"), "link.js_call_id"),
                lng(l.get("callee_function_id"), "link.callee_function_id"),
                str(l.get("export_name"), "link.export_name"),
                resolution(l.get("resolution")),
                derivation(l.get("derivation"), "link.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-capture-facts/0.2. */
    public static List<CaptureFact> loadCaptureFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "capture document");
        String schema = str(doc.get("schema"), "schema");
        if (!CAPTURE_SCHEMA.equals(schema)) {
            if (KNOWN_UNCONSUMED_FAMILIES.contains(schema))
                throw new IllegalArgumentException("UNSUPPORTED_FACT_FAMILY: " + schema + " (capture loader consumes " + CAPTURE_SCHEMA + ")");
            throw new IllegalArgumentException("unsupported capture schema: " + schema + " (accepted: " + CAPTURE_SCHEMA + ")");
        }
        List<CaptureFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("captures", List.of()), "captures")) {
            Map<String, Object> c = obj(o, "capture");
            String kind = str(c.get("outer_kind"), "capture.outer_kind");
            out.add(new CaptureFact(
                lng(c.get("inner_function"), "capture.inner_function"),
                lng(c.get("inner_local_id"), "capture.inner_local_id"),
                str(c.get("inner_binding"), "capture.inner_binding"),
                lng(c.get("outer_function"), "capture.outer_function"),
                lng(c.get("outer_node_id"), "capture.outer_node_id"),
                str(c.get("outer_binding"), "capture.outer_binding"),
                switch (kind) {
                    case "LOCAL" -> CaptureFact.OuterKind.LOCAL;
                    case "PARAMETER" -> CaptureFact.OuterKind.PARAMETER;
                    default -> throw new IllegalArgumentException("unknown outer_kind: " + kind);
                },
                resolution(c.get("resolution")),
                derivation(c.get("derivation"), "capture.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-identity-facts/0.2. */
    public static List<IdentityFact> loadIdentityFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "identity document");
        String schema = str(doc.get("schema"), "schema");
        if (!IDENTITY_SCHEMA.equals(schema))
            throw new IllegalArgumentException("unsupported identity schema: " + schema + " (accepted: " + IDENTITY_SCHEMA + ")");
        List<IdentityFact> out = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("bindings", List.of()), "bindings")) {
            Map<String, Object> b = obj(o, "binding");
            List<String> ids = new ArrayList<>();
            for (Object x : arr(b.get("identities"), "identities")) ids.add(str(x, "identity"));
            out.add(new IdentityFact(
                lng(b.get("function_id"), "identity.function_id"),
                str(b.get("binding"), "identity.binding"),
                ids,
                bool(b.get("must")),
                resolution(b.get("resolution")),
                derivation(b.get("derivation"), "identity.derivation")));
        }
        return out;
    }

    /** Strict deserialization of portable-state-facts/0.4. Version 0.4 requires a
     *  canonical receiver_location. Version 0.3 remains loadable with the exact
     *  historical direct-receiver interpretation; no path is inferred there. */
    public static StateFacts loadStateFacts(Path jsonFile) throws Exception {
        Map<String, Object> doc = obj(Json.parse(Files.readString(jsonFile)), "state document");
        String schema = str(doc.get("schema"), "schema");
        boolean legacy = LEGACY_STATE_SCHEMA.equals(schema);
        if (!STATE_SCHEMA.equals(schema) && !legacy) {
            if (KNOWN_UNCONSUMED_FAMILIES.contains(schema))
                throw new IllegalArgumentException("UNSUPPORTED_FACT_FAMILY: " + schema + " (state loader consumes " + STATE_SCHEMA + ")");
            throw new IllegalArgumentException("unsupported state schema: " + schema
                + " (accepted: " + Set.of(STATE_SCHEMA, LEGACY_STATE_SCHEMA) + ")");
        }
        List<StateWriteFact> writes = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("state_writes", List.of()), "state_writes")) {
            Map<String, Object> w = obj(o, "state_write");
            ValueRef receiver = valueRef(w.get("receiver_ref"), "state_write.receiver_ref");
            writes.add(new StateWriteFact(
                lng(w.get("assignment_call_id"), "state_write.id"),
                lng(w.get("function_id"), "state_write.function_id"),
                str(w.get("accessor"), "state_write.accessor"),
                receiver,
                keySelector(w.get("key"), "state_write.key"),
                valueRef(w.get("value_ref"), "state_write.value_ref"),
                resolution(w.get("resolution")),
                intOrNull(w.get("line")),
                derivation(w.get("derivation"), "state_write.derivation"),
                legacy ? StateLocation.direct(receiver)
                       : stateLocation(w.get("receiver_location"), "state_write.receiver_location")));
        }
        List<StateReadFact> reads = new ArrayList<>();
        for (Object o : arr(doc.getOrDefault("state_reads", List.of()), "state_reads")) {
            Map<String, Object> r = obj(o, "state_read");
            ValueRef receiver = valueRef(r.get("receiver_ref"), "state_read.receiver_ref");
            reads.add(new StateReadFact(
                lng(r.get("index_call_id"), "state_read.id"),
                lng(r.get("function_id"), "state_read.function_id"),
                str(r.get("accessor"), "state_read.accessor"),
                receiver,
                keySelector(r.get("key"), "state_read.key"),
                resolution(r.get("resolution")),
                intOrNull(r.get("line")),
                derivation(r.get("derivation"), "state_read.derivation"),
                legacy ? StateLocation.direct(receiver)
                       : stateLocation(r.get("receiver_location"), "state_read.receiver_location")));
        }
        return new StateFacts(writes, reads);
    }

    private static StateLocation stateLocation(Object v, String where) {
        Map<String, Object> m = obj(v, where);
        ValueRef root = valueRef(m.get("root_ref"), where + ".root_ref");
        List<KeySelector> path = new ArrayList<>();
        for (Object key : arr(m.getOrDefault("path", List.of()), where + ".path"))
            path.add(keySelector(key, where + ".path"));
        return new StateLocation(root, path);
    }

    private static KeySelector keySelector(Object v, String where) {
        Map<String, Object> m = obj(v, where);
        String kind = str(m.get("kind"), where + ".kind");
        return switch (kind) {
            case "LITERAL" -> KeySelector.literal(str(m.get("value"), where + ".value"));
            case "DYNAMIC" -> KeySelector.dynamic(str(m.get("ref"), where + ".ref"));
            default -> throw new IllegalArgumentException("unknown key selector kind: " + kind + " at " + where);
        };
    }
    private static FactDerivation derivation(Object v, String where) {
        if (v == null) throw new IllegalArgumentException("missing derivation at " + where);
        Map<String, Object> m = obj(v, where);
        List<Long> src = new ArrayList<>();
        for (Object x : arr(m.getOrDefault("source_node_ids", List.of()), where + ".source_node_ids")) src.add(lng(x, where));
        return new FactDerivation(str(m.get("origin"), where + ".origin"), str(m.get("rule"), where + ".rule"), src);
    }

    // ---- strict field helpers (loudly typed; no coercion, no defaults for required fields) ----
    private static Resolution resolution(Object v) {
        String s = str(v, "resolution");
        return switch (s) {
            case "EXACT" -> Resolution.EXACT;
            case "HEURISTIC" -> Resolution.HEURISTIC;
            case "AMBIGUOUS" -> Resolution.AMBIGUOUS;
            case "UNRESOLVED" -> Resolution.UNRESOLVED;
            default -> throw new IllegalArgumentException("unknown resolution: " + s);
        };
    }
    private static ValueRef valueRef(Object v, String where) {
        if (v == null) throw new IllegalArgumentException("missing value_ref at " + where);
        Map<String, Object> m = obj(v, where);
        String kind = str(m.get("kind"), where + ".kind");
        long id = m.containsKey("id") ? lng(m.get("id"), where + ".id") : -1L;
        String code = str(m.getOrDefault("code", ""), where + ".code");
        return switch (kind) {
            case "PARAMETER" -> ValueRef.parameter(id, code);
            case "LOCAL" -> ValueRef.local(id, code);
            case "CALL" -> ValueRef.call(id, code);
            case "PERSISTENCE_READ" -> ValueRef.persistenceRead(id, code);
            case "STATE_CHANNEL_READ" -> ValueRef.stateChannelRead(id, code);
            case "STATE_READ" -> ValueRef.stateRead(id, code);
            case "SELF" -> ValueRef.self(id);
            case "FUNCTION" -> ValueRef.function(id, code);
            case "EXTERNAL_INPUT" -> ValueRef.externalInput(id, code);
            case "CONSTANT" -> ValueRef.constant(code);
            case "UNKNOWN" -> ValueRef.unknown(code);
            default -> throw new IllegalArgumentException("unknown value_ref kind: " + kind + " at " + where);
        };
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> obj(Object v, String where) {
        if (!(v instanceof Map)) throw new IllegalArgumentException("expected object at " + where);
        return (Map<String, Object>) v;
    }
    @SuppressWarnings("unchecked")
    private static List<Object> arr(Object v, String where) {
        if (!(v instanceof List)) throw new IllegalArgumentException("expected array at " + where);
        return (List<Object>) v;
    }
    private static String str(Object v, String where) {
        if (!(v instanceof String)) throw new IllegalArgumentException("expected string at " + where);
        return (String) v;
    }
    private static long lng(Object v, String where) {
        if (v instanceof Long l) return l;
        if (v instanceof Integer i) return i.longValue();
        if (v instanceof Double d && d == Math.floor(d)) return (long) (double) d;
        throw new IllegalArgumentException("expected integer at " + where + ", got " + v);
    }
    private static Integer intOrNull(Object v) {
        if (v == null) return null;
        return (int) lng(v, "int");
    }
    private static boolean bool(Object v) {
        if (v instanceof Boolean b) return b;
        throw new IllegalArgumentException("expected boolean, got " + v);
    }

    /** Minimal strict JSON parser (objects, arrays, strings, numbers, booleans, null). */
    static final class Json {
        private final String s; private int i;
        private Json(String s) { this.s = s; }
        static Object parse(String s) {
            Json j = new Json(s);
            Object v = j.value();
            j.ws();
            if (j.i != s.length()) throw new IllegalArgumentException("trailing content at " + j.i);
            return v;
        }
        private Object value() {
            ws();
            char c = peek();
            if (c == '{') return object();
            if (c == '[') return array();
            if (c == '"') return string();
            if (c == 't') { expect("true"); return Boolean.TRUE; }
            if (c == 'f') { expect("false"); return Boolean.FALSE; }
            if (c == 'n') { expect("null"); return null; }
            return number();
        }
        private Map<String, Object> object() {
            expect("{"); ws();
            LinkedHashMap<String, Object> m = new LinkedHashMap<>();
            if (peek() == '}') { i++; return m; }
            while (true) {
                ws();
                String k = string();
                ws(); expect(":");
                m.put(k, value());
                ws();
                char c = next();
                if (c == '}') return m;
                if (c != ',') throw new IllegalArgumentException("expected , or } at " + (i - 1));
            }
        }
        private List<Object> array() {
            expect("["); ws();
            ArrayList<Object> a = new ArrayList<>();
            if (peek() == ']') { i++; return a; }
            while (true) {
                a.add(value());
                ws();
                char c = next();
                if (c == ']') return a;
                if (c != ',') throw new IllegalArgumentException("expected , or ] at " + (i - 1));
            }
        }
        private String string() {
            expect("\"");
            StringBuilder b = new StringBuilder();
            while (true) {
                char c = next();
                if (c == '"') return b.toString();
                if (c == '\\') {
                    char e = next();
                    switch (e) {
                        case '"' -> b.append('"');
                        case '\\' -> b.append('\\');
                        case '/' -> b.append('/');
                        case 'b' -> b.append('\b');
                        case 'f' -> b.append('\f');
                        case 'n' -> b.append('\n');
                        case 'r' -> b.append('\r');
                        case 't' -> b.append('\t');
                        case 'u' -> { b.append((char) Integer.parseInt(s.substring(i, i + 4), 16)); i += 4; }
                        default -> throw new IllegalArgumentException("bad escape \\" + e);
                    }
                } else b.append(c);
            }
        }
        private Object number() {
            int start = i;
            if (peek() == '-') i++;
            while (i < s.length() && "0123456789+-.eE".indexOf(s.charAt(i)) >= 0) i++;
            String t = s.substring(start, i);
            if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) return Long.parseLong(t);
            return Double.parseDouble(t);
        }
        private void ws() { while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++; }
        private char peek() { if (i >= s.length()) throw new IllegalArgumentException("eof"); return s.charAt(i); }
        private char next() { char c = peek(); i++; return c; }
        private void expect(String t) {
            if (!s.startsWith(t, i)) throw new IllegalArgumentException("expected " + t + " at " + i);
            i += t.length();
        }
    }
}

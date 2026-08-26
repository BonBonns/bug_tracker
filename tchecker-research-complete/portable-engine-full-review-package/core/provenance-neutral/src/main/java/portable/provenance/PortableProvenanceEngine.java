package portable.provenance;

import portable.graph.*;
import java.util.*;

/**
 * Language-neutral semantic provenance engine.
 *
 * Core invariant: provenance is evaluated from ValueRef / function summaries, never
 * by searching source-language AST subtrees for syntactic source membership.
 */
public final class PortableProvenanceEngine {
    private final ProgramGraph graph;
    private final AnalysisBudget budget;
    private final Map<Long, ProvenanceSummary> memo = new HashMap<>();
    private final Set<Long> active = new HashSet<>();
    private AnalysisSession session;

    private static final class AnalysisSession {
        long work;
        final List<TruncationEvent> events = new ArrayList<>();
    }

    public PortableProvenanceEngine(ProgramGraph graph) {
        this(graph, AnalysisBudget.DEFAULT);
    }

    public PortableProvenanceEngine(ProgramGraph graph, AnalysisBudget budget) {
        this.graph = Objects.requireNonNull(graph);
        this.budget = Objects.requireNonNull(budget);
    }

    public ProvenanceSummary summarize(long functionId) {
        boolean root = session == null;
        if (root) session = new AnalysisSession();
        try {
            return summarize(functionId, 0);
        } finally {
            if (root) session = null;
        }
    }

    /** SINK-R01: the SAME provenance question asked at a different OBSERVATION
     *  POINT — the value passed at a call argument, rather than a function's
     *  return. No provenance semantics change: this reuses evalValue and the same
     *  budget/session machinery, so the resulting status vocabulary (EXACT /
     *  AMBIGUOUS / POSSIBLE_UNBOUNDED / UNRESOLVED) means exactly what it means
     *  for returns. Vulnerability-specific reasoning stays OUT of the core: a
     *  "sink" is just a call argument someone chose to observe. */
    public ProvenanceSummary summarizeSinkArgument(long callId, int argIndex) {
        CallFact call = graph.call(callId).orElse(null);
        if (call == null) return ProvenanceSummary.unresolved();
        FunctionFact enclosing = graph.function(call.enclosingFunctionId()).orElse(null);
        if (enclosing == null) return ProvenanceSummary.unresolved();
        ArgumentFact arg = null;
        for (ArgumentFact a : call.arguments()) if (a.index() == argIndex) { arg = a; break; }
        if (arg == null) return ProvenanceSummary.unresolved();
        boolean root = session == null;
        if (root) session = new AnalysisSession();
        try {
            // REACH-R02: consult reaching definitions AT THIS USE, exactly as the
            // return path does. Without it a sink argument merges every definition
            // of the location regardless of order.
            if (System.getenv("REACH_R02_OFF") == null && arg.value().kind() == ValueRef.Kind.LOCAL) {
                ReachingDefFact rd = graph.reachingDefsFor(arg.id()).orElse(null);
                if (rd != null && rd.functionId() == enclosing.id()
                        && rd.localId() == arg.value().referencedId()) {
                    List<AssignmentFact> defs = new ArrayList<>();
                    for (AssignmentFact a2 : graph.assignmentsTo(enclosing.id(), rd.localId()))
                        if (rd.defIds().contains(a2.id())) defs.add(a2);
                    if (defs.size() == 1) return evalValue(enclosing, defs.get(0).value(), 0);
                    if (defs.size() > 1) {
                        List<ProvenanceSummary> parts = new ArrayList<>();
                        for (AssignmentFact a2 : defs) parts.add(evalValue(enclosing, a2.value(), 1));
                        return mergeAlternatives(parts, Resolution.AMBIGUOUS);
                    }
                }
            }
            return evalValue(enclosing, arg.value(), 0);
        } finally {
            if (root) session = null;
        }
    }

    private ProvenanceSummary summarize(long functionId, int depth) {
        ProvenanceSummary cached = memo.get(functionId);
        if (cached != null) return cached;
        ProvenanceSummary budgetStop = consume(functionId, depth, "summarize function");
        if (budgetStop != null) return budgetStop;
        if (!active.add(functionId)) return ProvenanceSummary.unresolved();
        try {
            FunctionFact f = graph.function(functionId).orElseThrow();
            List<ReturnFact> returns = graph.returnsIn(functionId);
            ProvenanceSummary result;
            if (returns.isEmpty()) {
                result = ProvenanceSummary.exact(Set.of());
            } else {
                List<ProvenanceSummary> alternatives = new ArrayList<>();
                for (ReturnFact r : returns) alternatives.add(returnSummary(f, r, depth));
                result = mergeAlternatives(alternatives, Resolution.EXACT);
            }
            // Never memoize a budget-dependent partial result.
            if (result.completeness() != AnalysisCompleteness.PARTIAL) memo.put(functionId, result);
            return result;
        } finally {
            active.remove(functionId);
        }
    }

    private ProvenanceSummary evalValue(FunctionFact enclosing, ValueRef value, int depth) {
        ProvenanceSummary budgetStop = consume(enclosing.id(), depth, value == null ? "null value" : value.code());
        if (budgetStop != null) return budgetStop;
        if (value == null) return ProvenanceSummary.unresolved();
        return switch (value.kind()) {
            case CONSTANT -> ProvenanceSummary.exact(Set.of());
            case UNKNOWN -> ProvenanceSummary.unresolved();
            case PARAMETER -> parameterSummary(enclosing, value.referencedId());
            case LOCAL -> localSummary(enclosing, value.referencedId(), depth);
            case CALL -> callSummary(enclosing, value.referencedId(), depth);
            case PERSISTENCE_READ -> persistenceReadSummary(enclosing, value.referencedId(), depth);
            case STATE_CHANNEL_READ -> stateChannelReadSummary(enclosing, value.referencedId(), depth);
            case STATE_READ -> stateReadSummary(enclosing, value.referencedId(), depth);
            case SELF -> ProvenanceSummary.unresolved(); // a bare receiver reference has no standalone provenance
            // A callable value carries no DATA origin of its own (a function
            // literal is not derived from any parameter). EXACT-with-no-origins is
            // the honest answer, not unknown.
            // SOURCE-R02e: an external-input value carries its ORIGIN and is subject
            // to ordinary definition/use semantics — reaching definitions may kill it.
            case EXTERNAL_INPUT -> makeSummary(Resolution.EXACT, Set.of(), new TreeSet<>(),
                Set.of(OriginRef.fileInput(value.referencedId(), enclosing.id(), value.code())),
                Set.of(), false, AnalysisCompleteness.COMPLETE, List.of());
            case FUNCTION -> makeSummary(Resolution.EXACT, Set.of(), Set.of(), Set.of(), Set.of(),
                false, AnalysisCompleteness.COMPLETE, List.of());
        };
    }

    private ProvenanceSummary parameterSummary(FunctionFact enclosing, long parameterId) {
        for (ParameterFact p : enclosing.parameters()) {
            if (p.id() != parameterId) continue;
            // JS-SOURCE-R02: a registered event callback may also be invoked
            // directly, so its formal parameter has two honest alternatives:
            // ordinary caller input, or the external message event. Preserve both
            // as MAY; never upgrade a registration observation to an EXACT origin.
            for (SourceOriginFact sf : graph.sourceOrigins()) {
                if (sf.functionId() == enclosing.id()
                        && sf.targetKind() == SourceOriginFact.TargetKind.PARAMETER
                        && sf.targetLocalId() == parameterId) {
                    OriginRef ref = sourceOriginRef(sf);
                    return makeSummary(Resolution.AMBIGUOUS, Set.of(), new TreeSet<>(Set.of(p.index())),
                        Set.of(), Set.of(ref), false, AnalysisCompleteness.COMPLETE, List.of());
                }
            }
            return ProvenanceSummary.exact(Set.of(p.index()));
        }
        return ProvenanceSummary.unresolved();
    }

    private OriginRef sourceOriginRef(SourceOriginFact sf) {
        return switch (sf.originKind()) {
            case "FILE_INPUT" -> OriginRef.fileInput(sf.id(), sf.functionId(), sf.location());
            case "NETWORK_INPUT" -> OriginRef.networkInput(sf.id(), sf.functionId(), sf.location());
            case "WEBEXT_EXTERNAL_MESSAGE_INPUT" ->
                OriginRef.webextExternalMessageInput(sf.id(), sf.functionId(), sf.location());
            case "WEBEXT_TAB_URL_INPUT" ->
                OriginRef.webextTabUrlInput(sf.id(), sf.functionId(), sf.location());
            default -> throw new IllegalArgumentException("unsupported source origin kind: " + sf.originKind());
        };
    }

    /** SOURCE-R02: a local whose value was introduced by an external source is
     *  answered with that ORIGIN rather than a parameter position. The engine does
     *  not know which API produced it — the frontend asserted the origin kind. */
    /** True when `loc` IS the source target or is a DESCENDANT of it, following
     *  base_id transitively. This is deliberately generic memory reasoning —
     *  "an external write to X defines X's descendants" — not knowledge of any
     *  particular API or of struct fields specifically, so future source kinds
     *  reuse it unchanged. */
    private boolean reachesSourceTarget(long functionId, long loc, long target, int depth) {
        if (loc == target) return true;
        if (depth > 8) return false;
        for (MemoryLocationFact m : graph.memoryLocations()) {
            if (m.functionId() != functionId || m.id() != loc) continue;
            if (m.baseId() == 0) return false;
            return reachesSourceTarget(functionId, m.baseId(), target, depth + 1);
        }
        return false;
    }

    private ProvenanceSummary sourceOriginSummary(FunctionFact f, long localId) {
        long functionId = f.id();
        for (SourceOriginFact sf : graph.sourceOrigins()) {
            if (sf.functionId() != functionId) continue;
            if (sf.targetKind() != SourceOriginFact.TargetKind.LOCAL
                    && sf.targetKind() != SourceOriginFact.TargetKind.MEMORY_LOCATION) continue;
            if (!reachesSourceTarget(functionId, localId, sf.targetLocalId(), 0)) continue;
            // OVERWRITE KILLING: a definite assignment to this exact location that
            // occurs AFTER the external write supersedes it (h5). An assignment
            // BEFORE it does not (h6). Ordering is by source line, which is a
            // known approximation — CFG-ordered killing is the correct long-term
            // form and is recorded as such rather than claimed here.
            int srcLine = -1;
            for (CallFact c : graph.calls()) if (c.id() == sf.id()) srcLine = c.line();
            boolean overwritten = false;
            for (AssignmentFact a : graph.assignmentsTo(functionId, localId))
                if (a.line() > srcLine) overwritten = true;
            if (overwritten) return null;
            OriginRef ref = sourceOriginRef(sf);
            return makeSummary(Resolution.EXACT, Set.of(), new TreeSet<>(), Set.of(ref), Set.of(),
                false, AnalysisCompleteness.COMPLETE, List.of());
        }
        return null;
    }

    private ProvenanceSummary localSummary(FunctionFact enclosing, long localId, int depth) {
        // In R02e shadow mode the standing annotation must not short-circuit; the
        // origin arrives as a definition instead.
        if (System.getenv("SOURCE_R02E_OFF") != null) {
            ProvenanceSummary src = sourceOriginSummary(enclosing, localId);
            if (src != null) return src;
        }
        Optional<LocalFact> local = graph.local(localId);
        if (local.isEmpty() || local.get().functionId() != enclosing.id()) return ProvenanceSummary.unresolved();
        List<AssignmentFact> defs = graph.assignmentsTo(enclosing.id(), localId);
        if (defs.isEmpty()) return ProvenanceSummary.unresolved();
        // JS-SOURCE-R01: a file reader RETURNS its buffer, so `const x = readFile(..)`
        // is a single assignment whose RHS is the reader call. When a source origin
        // targets this local, the reader-call definition IS the external write, so
        // resolve it to the FILE_INPUT origin. This keeps the origin participating
        // in definition semantics (it is THE def of x), not a standing annotation:
        // an intervening reassignment produces >1 def and the overwrite logic in
        // sourceOriginSummary / the MAY merge below takes over.
        if (defs.size() == 1) {
            // JS-SOURCE-R01: consult a source origin ONLY when the sole definition
            // IS the recognised reader call. Scopes the change to
            // `const x = readFile(..)`; C reaching-def/overwrite semantics untouched.
            AssignmentFact only = defs.get(0);
            if (only.value().kind() == ValueRef.Kind.CALL) {
                        for (SourceOriginFact sf : graph.sourceOrigins()) {
                    if (sf.functionId() == enclosing.id()
                            && sf.targetKind() == SourceOriginFact.TargetKind.LOCAL
                            && sf.targetLocalId() == localId
                            && only.value().referencedId() == sf.id()) {
                        OriginRef ref = sourceOriginRef(sf);
                        return makeSummary(Resolution.EXACT, Set.of(), new TreeSet<>(),
                            Set.of(ref), Set.of(), false, AnalysisCompleteness.COMPLETE, List.of());
                    }
                }
            }
            return evalValue(enclosing, only.value(), depth);
        }
        // CORE-S03: multiple definitions without CFG proof -> MAY over all defs
        // (the validated Gate-15 semantics): every def is a possibility, none proven.
        List<ProvenanceSummary> alternatives = new ArrayList<>();
        for (AssignmentFact def : defs) alternatives.add(evalValue(enclosing, def.value(), depth + 1));
        ProvenanceSummary merged = mergeAlternatives(alternatives, Resolution.AMBIGUOUS);
        TreeSet<Integer> may = new TreeSet<>(merged.provenPositions()); may.addAll(merged.mayPositions());
        Set<OriginRef> mayO = new HashSet<>(merged.provenOrigins()); mayO.addAll(merged.mayOrigins());
        return makeSummary(Resolution.weakest(Resolution.AMBIGUOUS, merged.resolution()),
            Set.of(), may, Set.of(), mayO, merged.unknown(), merged.completeness(), merged.truncations());
    }

    /** CORE-S02: identity-keyed interprocedural state (JSTS-R03 semantics, ported).
     *  A call to a method whose return is a SELF-state read is answered from the
     *  caller's sequential state store: the caller's earlier EXACT-dispatch calls
     *  apply their callees' SELF-writes at the callsite receiver's identity set.
     *  must (singleton) identity -> strong update; may -> weak update on every
     *  identity; a dynamic-key write pollutes the receiver. Reads see only PRIOR
     *  writes (call-id order = source order, the validated convention). Identity
     *  answers WHICH object a binding denotes; provenance flows only through the
     *  written values. */
    private java.util.Optional<KeySelector> selfReadReturnKey(FunctionFact callee) {
        List<ReturnFact> rets = graph.returnsIn(callee.id());
        if (rets.size() != 1) return java.util.Optional.empty();
        ValueRef v = rets.get(0).value();
        if (v.kind() != ValueRef.Kind.STATE_READ) return java.util.Optional.empty();
        return graph.stateRead(v.referencedId())
            .filter(r -> r.receiver().kind() == ValueRef.Kind.SELF)
            .map(StateReadFact::key);
    }

    private List<StateWriteFact> selfWrites(FunctionFact callee) {
        List<StateWriteFact> out = new ArrayList<>();
        for (StateWriteFact w : graph.stateWritesIn(callee.id()))
            if (w.receiver().kind() == ValueRef.Kind.SELF) out.add(w);
        out.sort(java.util.Comparator.comparingLong(StateWriteFact::id));
        return out;
    }

    private ProvenanceSummary calleeParamValueAtCallsite(FunctionFact caller, FunctionFact callee,
                                                         CallFact site, ValueRef calleeRef, int depth) {
        if (calleeRef.kind() == ValueRef.Kind.PARAMETER) {
            for (ParameterFact p : callee.parameters()) {
                if (p.id() == calleeRef.referencedId()) {
                    for (ArgumentFact a : site.arguments())
                        if (a.index() == p.index()) return evalValue(caller, a.value(), depth + 1);
                    return ProvenanceSummary.unresolved();
                }
            }
            return ProvenanceSummary.unresolved();
        }
        if (calleeRef.kind() == ValueRef.Kind.CONSTANT) return ProvenanceSummary.exact(java.util.Set.of());
        return ProvenanceSummary.unresolved();
    }

    private ProvenanceSummary identityStateLookup(FunctionFact caller, CallFact readSite,
                                                  KeySelector readKey, int depth) {
        IdentityFact recvId = (readSite.receiverName() == null) ? null
            : graph.identityOf(caller.id(), readSite.receiverName()).orElse(null);
        if (recvId == null) return null;
        Map<String, Map<String, List<ProvenanceSummary>>> slots = new HashMap<>();
        Map<String, List<ProvenanceSummary>> pollution = new HashMap<>();
        java.util.Set<String> weakTouched = new java.util.HashSet<>();
        for (CallFact c : graph.callsIn(caller.id())) {
            if (c.id() >= readSite.id()) continue;                       // reads see only prior writes
            if (c.resolution() != Resolution.EXACT || c.candidateTargetIds().size() != 1) continue;
            FunctionFact callee = graph.function(c.candidateTargetIds().get(0)).orElse(null);
            if (callee == null || c.receiverName() == null) continue;
            IdentityFact wid = graph.identityOf(caller.id(), c.receiverName()).orElse(null);
            if (wid == null) continue;
            boolean strong = wid.must();
            for (StateWriteFact w : selfWrites(callee)) {
                ProvenanceSummary val = calleeParamValueAtCallsite(caller, callee, c, w.value(), depth);
                for (String ident : wid.identities()) {
                    if (w.key().kind() == KeySelector.Kind.LITERAL) {
                        Map<String, List<ProvenanceSummary>> byKey = slots.computeIfAbsent(ident, k -> new HashMap<>());
                        List<ProvenanceSummary> slot = byKey.computeIfAbsent(w.key().literal(), k -> new ArrayList<>());
                        if (strong) { slot.clear(); slot.add(val); weakTouched.remove(ident + "\u0000" + w.key().literal()); }
                        else {
                            // a weak write leaves 'slot possibly unset' as a live
                            // alternative (canonical STATE_UNKNOWN semantics): seed it
                            // once when the slot had no content before this weak write.
                            if (slot.isEmpty()) slot.add(makeSummary(Resolution.EXACT,
                                java.util.Set.of(), java.util.Set.of(), java.util.Set.of(), java.util.Set.of(),
                                true, AnalysisCompleteness.COMPLETE, List.of()));
                            slot.add(val); weakTouched.add(ident + "\u0000" + w.key().literal());
                        }
                    } else {
                        pollution.computeIfAbsent(ident, k -> new ArrayList<>()).add(val);
                    }
                }
            }
        }
        List<ProvenanceSummary> alternatives = new ArrayList<>();
        boolean weak = !recvId.must();
        for (String ident : recvId.identities()) {
            if (readKey.kind() == KeySelector.Kind.LITERAL) {
                List<ProvenanceSummary> slot = slots.getOrDefault(ident, Map.of()).get(readKey.literal());
                if (slot != null) {
                    alternatives.addAll(slot);
                    if (slot.size() > 1 || weakTouched.contains(ident + "\u0000" + readKey.literal())) weak = true;
                }
                List<ProvenanceSummary> pol = pollution.get(ident);
                if (pol != null) { alternatives.addAll(pol); weak = true; }
            } else {
                Map<String, List<ProvenanceSummary>> byKey = slots.getOrDefault(ident, Map.of());
                for (List<ProvenanceSummary> slot : byKey.values()) alternatives.addAll(slot);
                List<ProvenanceSummary> pol = pollution.get(ident);
                if (pol != null) alternatives.addAll(pol);
                weak = true;
            }
        }
        if (alternatives.isEmpty()) return ProvenanceSummary.unresolved();
        return mergeAlternatives(alternatives, weak ? Resolution.AMBIGUOUS : Resolution.EXACT);
    }

    /** Walk a transitive capture chain from an inner materialized local to the
     *  CALLER's own binding; null when the chain does not terminate in the caller. */
    private ProvenanceSummary captureChainSummary(FunctionFact enclosing, long innerLocalId, int depth) {
        CaptureFact cap = graph.captureOfLocal(innerLocalId).orElse(null);
        int hops = 0;
        while (cap != null && hops++ < 8) {
            if (cap.outerFunctionId() == enclosing.id()) {
                if (cap.outerKind() == CaptureFact.OuterKind.PARAMETER)
                    return parameterSummary(enclosing, cap.outerNodeId());
                return localSummary(enclosing, cap.outerNodeId(), depth + 1);
            }
            CaptureFact next = graph.captureOfLocal(cap.outerNodeId()).orElse(null);
            if (next == null) break;
            cap = next;
        }
        return (cap != null) ? ProvenanceSummary.unresolved() : null;
    }

    /** A return's value, narrowed by reaching definitions when the frontend proved
     *  which definitions can actually reach THIS use. Narrowing may only drop
     *  definitions that cannot reach; synthetic uncertainty contributions are
     *  anchored to their generating statement and therefore survive like any other
     *  definition (they are never dropped for being synthetic). */
    private ProvenanceSummary returnSummary(FunctionFact f, ReturnFact r, int depth) {
        if (r.value().kind() == ValueRef.Kind.LOCAL) {
            ReachingDefFact rd = graph.reachingDefsFor(r.id()).orElse(null);
            if (rd != null && rd.functionId() == f.id() && rd.localId() == r.value().referencedId()) {
                List<AssignmentFact> defs = new ArrayList<>();
                for (AssignmentFact a : graph.assignmentsTo(f.id(), rd.localId()))
                    if (rd.defIds().contains(a.id())) defs.add(a);
                if (!defs.isEmpty()) {
                    if (defs.size() == 1) return evalValue(f, defs.get(0).value(), depth);
                    List<ProvenanceSummary> parts = new ArrayList<>();
                    for (AssignmentFact a : defs) parts.add(evalValue(f, a.value(), depth + 1));
                    ProvenanceSummary merged = mergeAlternatives(parts, Resolution.AMBIGUOUS);
                    TreeSet<Integer> may = new TreeSet<>(merged.provenPositions()); may.addAll(merged.mayPositions());
                    Set<OriginRef> mayO = new HashSet<>(merged.provenOrigins()); mayO.addAll(merged.mayOrigins());
                    return makeSummary(Resolution.AMBIGUOUS, Set.of(), may, Set.of(), mayO,
                        merged.unknown(), merged.completeness(), merged.truncations());
                }
            }
        }
        return evalValue(f, r.value(), depth);
    }

    private ProvenanceSummary callSummary(FunctionFact enclosing, long callId, int depth) {
        // Expression family: a value combining operands carries every operand's
        // origins as POSSIBILITIES. Never EXACT (the record forbids it), and any
        // unresolved operand leaves the result unknown — so decomposition can add
        // MAY coverage but can never harden a row.
        ExpressionFact expr = graph.expressionFor(callId).orElse(null);
        if (expr != null && expr.functionId() == enclosing.id()) {
            ProvenanceSummary budgetStop = consume(enclosing.id(), depth, "expression:" + expr.operator());
            if (budgetStop != null) return budgetStop;
            List<ProvenanceSummary> parts = new ArrayList<>();
            for (ValueRef operand : expr.operands()) parts.add(evalValue(enclosing, operand, depth + 1));
            ProvenanceSummary merged = mergeAlternatives(parts, Resolution.AMBIGUOUS);
            TreeSet<Integer> may = new TreeSet<>(merged.provenPositions()); may.addAll(merged.mayPositions());
            Set<OriginRef> mayO = new HashSet<>(merged.provenOrigins()); mayO.addAll(merged.mayOrigins());
            return makeSummary(Resolution.AMBIGUOUS, Set.of(), may, Set.of(), mayO,
                merged.unknown(), merged.completeness(), merged.truncations());
        }
        Optional<CallFact> maybeCall = graph.call(callId);
        if (maybeCall.isEmpty()) return ProvenanceSummary.unresolved();
        CallFact call = maybeCall.get();
        if (call.enclosingFunctionId() != enclosing.id()) return ProvenanceSummary.unresolved();

        // Cross-language link family: applied ONLY when the frontend-native
        // resolution could not already prove the dispatch (never weakens a
        // frontend-proven EXACT), and only for EXACT links to a function this
        // graph actually contains. The link carries its own FactDerivation.
        if (call.resolution() != Resolution.EXACT) {
            CrossLangLinkFact link = graph.crossLangLinkForCall(call.id()).orElse(null);
            if (link != null && link.resolution() == Resolution.EXACT
                    && graph.function(link.calleeFunctionId()).isPresent()) {
                call = new CallFact(call.id(), call.enclosingFunctionId(), call.name(),
                    call.methodFullName(), call.dispatchType(), call.typeFullName(), call.code(),
                    call.file(), call.line(),
                    List.of(link.calleeFunctionId()),
                    List.of(graph.function(link.calleeFunctionId()).get().fullName()),
                    Resolution.EXACT, call.arguments(), call.receiverName());
            }
        }
        if (call.resolution() == Resolution.UNRESOLVED) return ProvenanceSummary.unresolved();

        // CORE-S03: a call to a closure whose return is a captured binding answers
        // from the CALLER's binding via the transitive capture chain. Capture is a
        // lexical relationship only; provenance comes from the outer binding's facts.
        if (call.resolution() == Resolution.EXACT && call.candidateTargetIds().size() == 1) {
            FunctionFact t = graph.function(call.candidateTargetIds().get(0)).orElse(null);
            if (t != null) {
                List<ReturnFact> trets = graph.returnsIn(t.id());
                if (trets.size() == 1 && trets.get(0).value().kind() == ValueRef.Kind.LOCAL) {
                    ProvenanceSummary viaCapture = captureChainSummary(enclosing,
                        trets.get(0).value().referencedId(), depth);
                    if (viaCapture != null) return viaCapture;
                }
                // CORE-S03 x CPP-R03 item 2: a closure returning a COMBINED
                // EXPRESSION over captured bindings (e.g. `() => a + b`). Each
                // operand resolves through its own capture chain; the result is
                // MAY over all of them, never EXACT — the composition of the two
                // features, neither of which could answer this alone.
                if (trets.size() == 1 && trets.get(0).value().kind() == ValueRef.Kind.CALL) {
                    ExpressionFact ce = graph.expressionFor(trets.get(0).value().referencedId()).orElse(null);
                    if (ce != null) {
                        List<ProvenanceSummary> parts = new ArrayList<>();
                        for (ValueRef operand : ce.operands()) {
                            ProvenanceSummary part = (operand.kind() == ValueRef.Kind.LOCAL)
                                ? captureChainSummary(enclosing, operand.referencedId(), depth) : null;
                            parts.add(part != null ? part : ProvenanceSummary.unresolved());
                        }
                        ProvenanceSummary merged = mergeAlternatives(parts, Resolution.AMBIGUOUS);
                        TreeSet<Integer> may = new TreeSet<>(merged.provenPositions()); may.addAll(merged.mayPositions());
                        Set<OriginRef> mayO = new HashSet<>(merged.provenOrigins()); mayO.addAll(merged.mayOrigins());
                        return makeSummary(Resolution.AMBIGUOUS, Set.of(), may, Set.of(), mayO,
                            merged.unknown(), merged.completeness(), merged.truncations());
                    }
                }
            }
        }

        // CORE-S02: a call returning a SELF-state read answers from the caller's
        // identity-keyed store (only for EXACT single-target dispatch).
        if (call.resolution() == Resolution.EXACT && call.candidateTargetIds().size() == 1) {
            FunctionFact t = graph.function(call.candidateTargetIds().get(0)).orElse(null);
            if (t != null) {
                java.util.Optional<KeySelector> rk = selfReadReturnKey(t);
                if (rk.isPresent()) {
                    ProvenanceSummary viaStore = identityStateLookup(enclosing, call, rk.get(), depth);
                    if (viaStore != null) return viaStore;
                }
            }
        }

        List<ProvenanceSummary> targetAlternatives = new ArrayList<>();
        for (long targetId : call.candidateTargetIds()) {
            FunctionFact target = graph.function(targetId).orElse(null);
            if (target == null) {
                targetAlternatives.add(ProvenanceSummary.unresolved());
                continue;
            }
            ProvenanceSummary callee = summarize(targetId, depth + 1);
            targetAlternatives.add(projectThroughArguments(enclosing, target, call, callee, depth));
        }
        if (targetAlternatives.isEmpty()) return ProvenanceSummary.unresolved();

        ProvenanceSummary merged = mergeAlternatives(targetAlternatives, call.resolution());
        if (call.resolution() == Resolution.HEURISTIC) {
            TreeSet<Integer> may = new TreeSet<>(merged.provenPositions());
            may.addAll(merged.mayPositions());
            Set<OriginRef> mayOrigins = new HashSet<>(merged.provenOrigins());
            mayOrigins.addAll(merged.mayOrigins());
            return makeSummary(
                Resolution.weakest(Resolution.HEURISTIC, merged.resolution()),
                Set.of(), may, Set.of(), mayOrigins, merged.unknown(), merged.completeness(), merged.truncations());
        }
        return merged;
    }

    private ProvenanceSummary projectThroughArguments(
        FunctionFact caller,
        FunctionFact calleeFunction,
        CallFact call,
        ProvenanceSummary callee,
        int depth
    ) {
        Map<Integer, ArgumentFact> byIndex = new HashMap<>();
        for (ArgumentFact a : call.arguments()) byIndex.put(a.index(), a);

        TreeSet<Integer> proven = new TreeSet<>();
        TreeSet<Integer> may = new TreeSet<>();
        Set<OriginRef> provenOrigins = new HashSet<>(callee.provenOrigins());
        Set<OriginRef> mayOrigins = new HashSet<>(callee.mayOrigins());
        boolean unknown = callee.unknown();
        Resolution resolution = callee.resolution();
        AnalysisCompleteness completeness = callee.completeness();
        List<TruncationEvent> truncations = new ArrayList<>(callee.truncations());

        for (int calleePos : callee.provenPositions()) {
            ArgumentFact arg = byIndex.get(calleePos);
            if (arg == null) { unknown = true; resolution = Resolution.UNRESOLVED; completeness = weaken(completeness, AnalysisCompleteness.UNKNOWN); continue; }
            ProvenanceSummary a = evalValue(caller, arg.value(), depth);
            resolution = Resolution.weakest(resolution, a.resolution());
            if (a.unknown()) unknown = true;
            completeness = weaken(completeness, a.completeness());
            truncations.addAll(a.truncations());
            proven.addAll(a.provenPositions());
            may.addAll(a.mayPositions());
        }
        for (int calleePos : callee.mayPositions()) {
            ArgumentFact arg = byIndex.get(calleePos);
            if (arg == null) { unknown = true; resolution = Resolution.UNRESOLVED; completeness = weaken(completeness, AnalysisCompleteness.UNKNOWN); continue; }
            ProvenanceSummary a = evalValue(caller, arg.value(), depth);
            resolution = Resolution.weakest(resolution, a.resolution());
            if (a.unknown()) unknown = true;
            completeness = weaken(completeness, a.completeness());
            truncations.addAll(a.truncations());
            may.addAll(a.provenPositions());
            may.addAll(a.mayPositions());
        }
        may.removeAll(proven);
        return makeSummary(resolution, proven, may, provenOrigins, mayOrigins, unknown, completeness, truncations);
    }

    private ProvenanceSummary mergeAlternatives(List<ProvenanceSummary> alternatives, Resolution edgeResolution) {
        if (alternatives.isEmpty()) return ProvenanceSummary.exact(Set.of());
        TreeSet<Integer> possible = new TreeSet<>();
        TreeSet<Integer> guaranteed = null;
        Set<OriginRef> possibleOrigins = new HashSet<>();
        Set<OriginRef> guaranteedOrigins = null;
        boolean unknown = false;
        Resolution resolution = edgeResolution;
        AnalysisCompleteness completeness = AnalysisCompleteness.COMPLETE;
        List<TruncationEvent> truncations = new ArrayList<>();

        for (ProvenanceSummary s : alternatives) {
            TreeSet<Integer> thisPossible = new TreeSet<>(s.provenPositions());
            thisPossible.addAll(s.mayPositions());
            possible.addAll(thisPossible);
            Set<OriginRef> thisPossibleOrigins = new HashSet<>(s.provenOrigins());
            thisPossibleOrigins.addAll(s.mayOrigins());
            possibleOrigins.addAll(thisPossibleOrigins);
            if (guaranteed == null) guaranteed = new TreeSet<>(s.provenPositions());
            else guaranteed.retainAll(s.provenPositions());
            if (guaranteedOrigins == null) guaranteedOrigins = new HashSet<>(s.provenOrigins());
            else guaranteedOrigins.retainAll(s.provenOrigins());
            unknown |= s.unknown();
            resolution = Resolution.weakest(resolution, s.resolution());
            completeness = weaken(completeness, s.completeness());
            truncations.addAll(s.truncations());
        }
        if (guaranteed == null) guaranteed = new TreeSet<>();
        if (guaranteedOrigins == null) guaranteedOrigins = new HashSet<>();

        if (edgeResolution == Resolution.AMBIGUOUS) resolution = Resolution.weakest(resolution, Resolution.AMBIGUOUS);
        TreeSet<Integer> may = new TreeSet<>(possible);
        may.removeAll(guaranteed);
        Set<OriginRef> mayOrigins = new HashSet<>(possibleOrigins);
        mayOrigins.removeAll(guaranteedOrigins);
        return makeSummary(resolution, guaranteed, may, guaranteedOrigins, mayOrigins, unknown, completeness, truncations);
    }

    /** CORE-S01: keyed-state read, porting the JSTS-R02 semantics verbatim.
     *  Same-function writes to the SAME receiver reference, in fact-id (source) order:
     *  literal write to the read key = strong update (kills prior slot content, incl.
     *  pollution); dynamic-key write to the same receiver = weak update (pollutes: MAY
     *  union of the written value); other literal keys are ignored. A dynamic read is
     *  MAY over every write to the receiver. Distinct receivers never cross-flow
     *  (reference inequality). A never-written slot abstains (unresolved). */
    private ProvenanceSummary stateReadSummary(FunctionFact enclosing, long readId, int depth) {
        Optional<StateReadFact> maybeRead = graph.stateRead(readId);
        if (maybeRead.isEmpty()) return ProvenanceSummary.unresolved();
        StateReadFact read = maybeRead.get();
        if (read.functionId() != enclosing.id()) return ProvenanceSummary.unresolved();
        if (read.receiver().kind() == ValueRef.Kind.UNKNOWN
                || read.receiverLocation().root().kind() == ValueRef.Kind.UNKNOWN)
            return ProvenanceSummary.unresolved();

        // Conservative ordering ceiling: if any write in the function may
        // replace a parent of this receiver, abstain even when another child-slot
        // write exists. Without CFG/order facts, choosing which one wins would be
        // fabricated precision.
        for (StateWriteFact w : graph.stateWritesIn(read.functionId())) {
            if (writeMayReplaceReceiver(w, read.receiverLocation()))
                return ProvenanceSummary.unresolved();
        }

        List<StateWriteFact> writes = new ArrayList<>();
        for (StateWriteFact w : graph.stateWritesIn(read.functionId())) {
            if (sameStateLocation(w.receiverLocation(), read.receiverLocation())) {
                writes.add(w);
            }
        }
        writes.sort(java.util.Comparator.comparingLong(StateWriteFact::id));
        if (writes.isEmpty()) {
            // JS-SOURCE-R03: a frontend may identify one particular keyed read as
            // browser-controlled input. Targeting the read fact (rather than the
            // callback parameter) is what keeps tab.url separate from tab.id,
            // cookieStoreId, changeInfo.status, and every sibling field. This is
            // still MAY: the callback can also be called as an ordinary function.
            for (SourceOriginFact sf : graph.sourceOrigins()) {
                if (sf.functionId() != enclosing.id()
                        || sf.targetKind() != SourceOriginFact.TargetKind.STATE_READ
                        || sf.targetLocalId() != read.id()) continue;
                TreeSet<Integer> may = new TreeSet<>();
                ValueRef root = read.receiverLocation().root();
                if (root.kind() == ValueRef.Kind.PARAMETER) {
                    for (ParameterFact p : enclosing.parameters())
                        if (p.id() == root.referencedId()) may.add(p.index());
                }
                return makeSummary(Resolution.AMBIGUOUS, Set.of(), may, Set.of(),
                    Set.of(sourceOriginRef(sf)), false, AnalysisCompleteness.COMPLETE, List.of());
            }
            // PROP-R02: no write to this object anywhere in the function, so there
            // is no evidence that intervening mutation invalidates the
            // relationship between the object and the property value. Under a
            // STATIC key, on a base that is a PARAMETER or a single-definition
            // LOCAL, the read MAY carry the base's provenance.
            // This is NOT property-value equivalence and NEVER yields EXACT:
            // dynamic keys, multi-def bases, written objects and alias-to-mutable
            // bases all continue to abstain (the frontend does not emit an
            // eligible read for them, and the write check above covers mutation).
            // PROP-R03: the same ceiling extends through a fully-literal nested
            // path when the canonical root is a PARAMETER or LOCAL and no parent
            // mutation above invalidated it. This is MAY only; SELF, CALL roots,
            // and any dynamic path component continue to abstain.
            ValueRef baseRef = read.receiverLocation().root();
            if (read.key().kind() == KeySelector.Kind.LITERAL
                    && read.receiverLocation().fullyLiteral()
                    && (baseRef.kind() == ValueRef.Kind.PARAMETER
                        || baseRef.kind() == ValueRef.Kind.LOCAL)) {
                ProvenanceSummary base = evalValue(enclosing, baseRef, depth + 1);
                if (!base.provenPositions().isEmpty() || !base.mayPositions().isEmpty()) {
                    TreeSet<Integer> may = new TreeSet<>(base.provenPositions());
                    may.addAll(base.mayPositions());
                    Set<OriginRef> mayO = new HashSet<>(base.provenOrigins());
                    mayO.addAll(base.mayOrigins());
                    return makeSummary(Resolution.AMBIGUOUS, Set.of(), may, Set.of(), mayO,
                        base.unknown(), base.completeness(), base.truncations());
                }
            }
            return ProvenanceSummary.unresolved();
        }

        if (read.key().kind() == KeySelector.Kind.LITERAL) {
            String k = read.key().literal();
            List<StateWriteFact> slot = new ArrayList<>();
            boolean polluted = false;
            for (StateWriteFact w : writes) {
                if (w.key().kind() == KeySelector.Kind.LITERAL) {
                    if (w.key().literal().equals(k)) { slot.clear(); slot.add(w); polluted = false; }
                    // a different literal slot never affects this one
                } else {
                    slot.add(w); polluted = true;
                }
            }
            if (slot.isEmpty()) return ProvenanceSummary.unresolved();
            List<ProvenanceSummary> alternatives = new ArrayList<>();
            for (StateWriteFact w : slot) alternatives.add(evalValue(enclosing, w.value(), depth + 1));
            Resolution edge = (polluted || slot.size() > 1)
                ? Resolution.AMBIGUOUS
                : Resolution.weakest(read.resolution(), slot.get(0).resolution());
            return mergeAlternatives(alternatives, edge);
        }
        // DYNAMIC read: any slot of this receiver may be returned
        List<ProvenanceSummary> alternatives = new ArrayList<>();
        for (StateWriteFact w : writes) alternatives.add(evalValue(enclosing, w.value(), depth + 1));
        return mergeAlternatives(alternatives, Resolution.AMBIGUOUS);
    }

    private boolean sameStateRoot(StateLocation a, StateLocation b) {
        return a.root().kind() == b.root().kind()
            && a.root().referencedId() == b.root().referencedId();
    }

    /** Exact receiver identity. Dynamic components never establish identity. */
    private boolean sameStateLocation(StateLocation a, StateLocation b) {
        if (!sameStateRoot(a, b) || a.path().size() != b.path().size()) return false;
        for (int i = 0; i < a.path().size(); i++) {
            KeySelector left = a.path().get(i), right = b.path().get(i);
            if (left.kind() != KeySelector.Kind.LITERAL || right.kind() != KeySelector.Kind.LITERAL
                    || !left.literal().equals(right.literal())) return false;
        }
        return true;
    }

    /** Whether a write's complete path may equal a prefix ending at the read's
     *  receiver. A dynamic selector may alias; a differing literal proves it does
     *  not. Descendant writes are not parent replacements. */
    private boolean writeMayReplaceReceiver(StateWriteFact write, StateLocation receiver) {
        StateLocation writeReceiver = write.receiverLocation();
        if (!sameStateRoot(writeReceiver, receiver)) return false;
        List<KeySelector> writePath = writeReceiver.withKey(write.key());
        if (writePath.size() > receiver.path().size()) return false;
        for (int i = 0; i < writePath.size(); i++) {
            KeySelector w = writePath.get(i), r = receiver.path().get(i);
            if (w.kind() == KeySelector.Kind.DYNAMIC || r.kind() == KeySelector.Kind.DYNAMIC)
                continue;
            if (!w.literal().equals(r.literal())) return false;
        }
        return true;
    }

    private ProvenanceSummary persistenceReadSummary(FunctionFact enclosing, long readId, int depth) {
        Optional<PersistenceReadFact> maybeRead = graph.persistenceRead(readId);
        if (maybeRead.isEmpty()) return ProvenanceSummary.unresolved();
        PersistenceReadFact read = maybeRead.get();
        if (read.functionId() != enclosing.id()) return ProvenanceSummary.unresolved();
        if (read.resolution() == Resolution.UNRESOLVED) return ProvenanceSummary.unresolved();

        List<ProvenanceSummary> alternatives = new ArrayList<>();
        for (long writeId : read.candidateWriteIds()) {
            PersistenceWriteFact write = graph.persistenceWrite(writeId).orElse(null);
            if (write == null || !write.location().equals(read.location())) {
                alternatives.add(ProvenanceSummary.unresolved());
                continue;
            }
            FunctionFact writer = graph.function(write.functionId()).orElse(null);
            if (writer == null) {
                alternatives.add(ProvenanceSummary.unresolved());
                continue;
            }
            ProvenanceSummary upstream = evalValue(writer, write.value(), depth + 1);
            Set<OriginRef> provenOrigins = new HashSet<>(upstream.provenOrigins());
            Set<OriginRef> mayOrigins = new HashSet<>(upstream.mayOrigins());
            for (int pos : upstream.provenPositions()) {
                provenOrigins.add(OriginRef.persistedParameter(write.id(), writer.id(), pos, write.location().stableKey()));
            }
            for (int pos : upstream.mayPositions()) {
                mayOrigins.add(OriginRef.persistedParameter(write.id(), writer.id(), pos, write.location().stableKey()));
            }
            alternatives.add(makeSummary(upstream.resolution(), Set.of(), Set.of(), provenOrigins, mayOrigins,
                upstream.unknown(), upstream.completeness(), upstream.truncations()));
        }
        if (alternatives.isEmpty()) return ProvenanceSummary.unresolved();
        ProvenanceSummary merged = mergeAlternatives(alternatives, read.resolution());
        if (read.resolution() == Resolution.HEURISTIC) {
            Set<OriginRef> mayOrigins = new HashSet<>(merged.provenOrigins());
            mayOrigins.addAll(merged.mayOrigins());
            return makeSummary(Resolution.weakest(Resolution.HEURISTIC, merged.resolution()), Set.of(), Set.of(),
                Set.of(), mayOrigins, merged.unknown(), merged.completeness(), merged.truncations());
        }
        return merged;
    }

    private ProvenanceSummary stateChannelReadSummary(FunctionFact enclosing, long readId, int depth) {
        Optional<StateChannelReadFact> maybeRead = graph.stateChannelRead(readId);
        if (maybeRead.isEmpty()) return ProvenanceSummary.unresolved();
        StateChannelReadFact read = maybeRead.get();
        if (read.functionId() != enclosing.id()) return ProvenanceSummary.unresolved();

        if (read.sourceMode() == StateChannelSourceMode.UNMODELED) {
            return ProvenanceSummary.unresolved();
        }

        if (read.sourceMode() == StateChannelSourceMode.EXTERNAL_SOURCE) {
            OriginRef origin = OriginRef.stateChannelExternal(read.id(), read.location().stableKey());
            if (read.resolution() == Resolution.HEURISTIC) {
                return makeSummary(Resolution.HEURISTIC, Set.of(), Set.of(), Set.of(), Set.of(origin), false,
                    AnalysisCompleteness.COMPLETE, List.of());
            }
            if (read.resolution() == Resolution.UNRESOLVED) return ProvenanceSummary.unresolved();
            return makeSummary(Resolution.EXACT, Set.of(), Set.of(), Set.of(origin), Set.of(), false,
                AnalysisCompleteness.COMPLETE, List.of());
        }

        List<ProvenanceSummary> alternatives = new ArrayList<>();
        for (long writeId : read.candidateWriteIds()) {
            StateChannelWriteFact write = graph.stateChannelWrite(writeId).orElse(null);
            if (write == null || !write.location().equals(read.location())) {
                alternatives.add(ProvenanceSummary.unresolved());
                continue;
            }
            FunctionFact writer = graph.function(write.functionId()).orElse(null);
            if (writer == null) {
                alternatives.add(ProvenanceSummary.unresolved());
                continue;
            }
            ProvenanceSummary upstream = evalValue(writer, write.value(), depth + 1);
            Set<OriginRef> provenOrigins = new HashSet<>(upstream.provenOrigins());
            Set<OriginRef> mayOrigins = new HashSet<>(upstream.mayOrigins());
            for (int pos : upstream.provenPositions()) {
                provenOrigins.add(OriginRef.stateChannelParameter(write.id(), writer.id(), pos, write.location().stableKey()));
            }
            for (int pos : upstream.mayPositions()) {
                mayOrigins.add(OriginRef.stateChannelParameter(write.id(), writer.id(), pos, write.location().stableKey()));
            }
            alternatives.add(makeSummary(upstream.resolution(), Set.of(), Set.of(), provenOrigins, mayOrigins,
                upstream.unknown(), upstream.completeness(), upstream.truncations()));
        }
        if (alternatives.isEmpty()) return ProvenanceSummary.unresolved();
        ProvenanceSummary merged = mergeAlternatives(alternatives, read.resolution());
        if (read.resolution() == Resolution.HEURISTIC) {
            Set<OriginRef> mayOrigins = new HashSet<>(merged.provenOrigins());
            mayOrigins.addAll(merged.mayOrigins());
            return makeSummary(Resolution.weakest(Resolution.HEURISTIC, merged.resolution()), Set.of(), Set.of(),
                Set.of(), mayOrigins, merged.unknown(), merged.completeness(), merged.truncations());
        }
        return merged;
    }

    private ProvenanceSummary consume(long functionId, int depth, String detail) {
        if (depth > budget.maxDepth()) {
            return truncation(TruncationEvent.Kind.DEPTH_BUDGET, functionId, depth, detail);
        }
        session.work++;
        if (session.work > budget.maxWorkItems()) {
            return truncation(TruncationEvent.Kind.WORK_BUDGET, functionId, depth, detail);
        }
        return null;
    }

    private ProvenanceSummary truncation(TruncationEvent.Kind kind, long functionId, int depth, String detail) {
        TruncationEvent e = new TruncationEvent(kind, functionId, depth, session.work, detail);
        session.events.add(e);
        return ProvenanceSummary.truncated(e);
    }

    private static AnalysisCompleteness weaken(AnalysisCompleteness a, AnalysisCompleteness b) {
        if (a == AnalysisCompleteness.PARTIAL || b == AnalysisCompleteness.PARTIAL) return AnalysisCompleteness.PARTIAL;
        if (a == AnalysisCompleteness.UNKNOWN || b == AnalysisCompleteness.UNKNOWN) return AnalysisCompleteness.UNKNOWN;
        return AnalysisCompleteness.COMPLETE;
    }

    private static ProvenanceSummary makeSummary(
        Resolution resolution,
        Set<Integer> proven,
        Set<Integer> may,
        Set<OriginRef> provenOrigins,
        Set<OriginRef> mayOrigins,
        boolean unknown,
        AnalysisCompleteness completeness,
        List<TruncationEvent> truncations
    ) {
        // STATUS-R02 (additive relabelling only — no inference changes). A row that
        // could not be bounded but DOES carry a known contribution is reported as
        // POSSIBLE_UNBOUNDED rather than UNRESOLVED, so the output stops
        // conflating "a contribution is known but unbounded" with "nothing is
        // known". Origin sets, proven/may membership and unknown are untouched.
        // STATUS-R03: derive the resolution from the EVIDENCE (proven / may /
        // unknown) instead of patching whatever the upstream label happened to be.
        // HEURISTIC is left alone: it grades DISPATCH evidence, not value
        // provenance, and relabelling it would change JS/TS dispatch reporting.
        if (resolution != Resolution.HEURISTIC) {
            if (proven.isEmpty() && !may.isEmpty())
                resolution = unknown ? Resolution.POSSIBLE_UNBOUNDED : Resolution.AMBIGUOUS;
            else if (proven.isEmpty() && may.isEmpty() && unknown)
                resolution = Resolution.UNRESOLVED;
        }
        if (!truncations.isEmpty()) completeness = AnalysisCompleteness.PARTIAL;
        else if (unknown && completeness == AnalysisCompleteness.COMPLETE) completeness = AnalysisCompleteness.UNKNOWN;
        // Position sets are unordered semantically, but the engine's OUTPUT must be
        // deterministic: conformance harnesses compare printed rows, and an
        // iteration-order difference is indistinguishable from a real change.
        return new ProvenanceSummary(resolution, new java.util.TreeSet<>(proven), new java.util.TreeSet<>(may),
            provenOrigins, mayOrigins, unknown, completeness, truncations);
    }
}

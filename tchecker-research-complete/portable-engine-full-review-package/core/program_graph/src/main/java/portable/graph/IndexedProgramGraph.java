package portable.graph;

import java.util.*;

/**
 * Immutable indexed view over any ProgramGraph.
 *
 * This is a behavior-preserving performance layer: it changes lookup complexity,
 * not graph semantics. Duplicate stable IDs are rejected rather than silently
 * allowing an index to choose one record.
 */
public final class IndexedProgramGraph implements ProgramGraph {
    private final String frontend;
    private final List<FunctionFact> functions;
    private final List<TypeDeclFact> typeDecls;
    private final List<CallFact> calls;
    private final List<ReturnFact> returns;
    private final List<LocalFact> locals;
    private final List<AssignmentFact> assignments;
    private final List<PersistenceWriteFact> persistenceWrites;
    private final List<PersistenceReadFact> persistenceReads;
    private final List<StateChannelWriteFact> stateChannelWrites;
    private final List<StateChannelReadFact> stateChannelReads;
    private final List<StateWriteFact> stateWrites;
    private final List<StateReadFact> stateReads;
    private final List<IdentityFact> identityFacts;
    private final List<CaptureFact> captureFacts;
    private final Map<Long, CaptureFact> captureByInnerLocal;
    private final List<CrossLangLinkFact> crossLangLinks;
    private final Map<Long, CrossLangLinkFact> crossLangByCall;
    private final List<MemoryLocationFact> memoryLocations;
    private final Map<Long, MemoryLocationFact> memoryById;
    private final List<PointsToFact> pointsTo;
    private final List<ExpressionFact> expressionFacts;
    private final Map<Long, ExpressionFact> expressionById;
    private final List<ReachingDefFact> reachingDefs;
    private final List<SourceOriginFact> sourceOrigins;
    private final Map<Long, ReachingDefFact> reachingByUse;
    private final Map<IdentityKey, IdentityFact> identityByBinding;
    private record IdentityKey(long functionId, String binding) {}

    private final Map<Long, FunctionFact> functionById;
    private final Map<Long, CallFact> callById;
    private final Map<Long, LocalFact> localById;
    private final Map<Long, PersistenceWriteFact> persistenceWriteById;
    private final Map<Long, PersistenceReadFact> persistenceReadById;
    private final Map<Long, StateChannelWriteFact> stateChannelWriteById;
    private final Map<Long, StateChannelReadFact> stateChannelReadById;
    private final Map<Long, StateWriteFact> stateWriteById;
    private final Map<Long, StateReadFact> stateReadById;
    private final Map<Long, List<StateWriteFact>> stateWritesByFunction;

    private final Map<Long, List<CallFact>> callsByFunction;
    private final Map<Long, List<ReturnFact>> returnsByFunction;
    private final Map<AssignmentKey, List<AssignmentFact>> assignmentsByTarget;

    private record AssignmentKey(long functionId, long localId) {}

    public IndexedProgramGraph(ProgramGraph source) {
        Objects.requireNonNull(source, "source");
        frontend = source.frontend();
        functions = List.copyOf(source.functions());
        typeDecls = List.copyOf(source.typeDecls());
        calls = List.copyOf(source.calls());
        returns = List.copyOf(source.returns());
        locals = List.copyOf(source.locals());
        assignments = List.copyOf(source.assignments());
        persistenceWrites = List.copyOf(source.persistenceWrites());
        persistenceReads = List.copyOf(source.persistenceReads());
        stateChannelWrites = List.copyOf(source.stateChannelWrites());
        stateChannelReads = List.copyOf(source.stateChannelReads());
        stateWrites = List.copyOf(source.stateWrites());
        stateReads = List.copyOf(source.stateReads());
        identityFacts = List.copyOf(source.identityFacts());
        captureFacts = List.copyOf(source.captureFacts());

        functionById = uniqueIndex(functions, FunctionFact::id, "function");
        callById = uniqueIndex(calls, CallFact::id, "call");
        localById = uniqueIndex(locals, LocalFact::id, "local");
        persistenceWriteById = uniqueIndex(persistenceWrites, PersistenceWriteFact::id, "persistence write");
        persistenceReadById = uniqueIndex(persistenceReads, PersistenceReadFact::id, "persistence read");
        stateChannelWriteById = uniqueIndex(stateChannelWrites, StateChannelWriteFact::id, "state-channel write");
        stateChannelReadById = uniqueIndex(stateChannelReads, StateChannelReadFact::id, "state-channel read");
        stateWriteById = uniqueIndex(stateWrites, StateWriteFact::id, "state write");
        stateReadById = uniqueIndex(stateReads, StateReadFact::id, "state read");
        stateWritesByFunction = group(stateWrites, StateWriteFact::functionId);
        Map<IdentityKey, IdentityFact> ib = new HashMap<>();
        for (IdentityFact f : identityFacts) {
            if (ib.putIfAbsent(new IdentityKey(f.functionId(), f.binding()), f) != null)
                throw new IllegalArgumentException("duplicate identity fact: " + f.functionId() + "/" + f.binding());
        }
        identityByBinding = Collections.unmodifiableMap(ib);
        captureByInnerLocal = uniqueIndex(captureFacts, CaptureFact::innerLocalId, "capture");
        crossLangLinks = List.copyOf(source.crossLangLinks());
        crossLangByCall = uniqueIndex(crossLangLinks, CrossLangLinkFact::callId, "crosslang link");
        memoryLocations = List.copyOf(source.memoryLocations());
        memoryById = uniqueIndex(memoryLocations, MemoryLocationFact::id, "memory location");
        pointsTo = List.copyOf(source.pointsTo());
        expressionFacts = List.copyOf(source.expressionFacts());
        expressionById = uniqueIndex(expressionFacts, ExpressionFact::id, "expression");
        reachingDefs = List.copyOf(source.reachingDefs());
        sourceOrigins = List.copyOf(source.sourceOrigins());
        reachingByUse = uniqueIndex(reachingDefs, ReachingDefFact::useId, "reaching-def");
        // cross-validation: every declared memory location must exist as a local
        // of the SAME function in the program doc — the fact family is contractual,
        // not decorative.
        for (MemoryLocationFact m : memoryLocations) {
            LocalFact l = localById.get(m.id());
            if (l == null)
                throw new IllegalArgumentException("memory location " + m.id() + " (" + m.name() + ") has no corresponding local");
            if (l.functionId() != m.functionId())
                throw new IllegalArgumentException("memory location " + m.id() + " function mismatch: " + m.functionId() + " vs local's " + l.functionId());
        }

        callsByFunction = group(calls, CallFact::enclosingFunctionId);
        returnsByFunction = group(returns, ReturnFact::functionId);
        Map<AssignmentKey, List<AssignmentFact>> a = new HashMap<>();
        for (AssignmentFact fact : assignments) {
            a.computeIfAbsent(new AssignmentKey(fact.functionId(), fact.targetLocalId()), ignored -> new ArrayList<>()).add(fact);
        }
        assignmentsByTarget = freezeGrouped(a);
    }

    @FunctionalInterface private interface LongKey<T> { long key(T value); }

    private static <T> Map<Long,T> uniqueIndex(List<T> values, LongKey<T> key, String kind) {
        Map<Long,T> out = new HashMap<>(Math.max(16, values.size() * 2));
        for (T value : values) {
            long id = key.key(value);
            T previous = out.putIfAbsent(id, value);
            if (previous != null) throw new IllegalArgumentException("duplicate " + kind + " id: " + id);
        }
        return Collections.unmodifiableMap(out);
    }

    private static <T> Map<Long,List<T>> group(List<T> values, LongKey<T> key) {
        Map<Long,List<T>> out = new HashMap<>();
        for (T value : values) out.computeIfAbsent(key.key(value), ignored -> new ArrayList<>()).add(value);
        return freezeGrouped(out);
    }

    private static <K,T> Map<K,List<T>> freezeGrouped(Map<K,List<T>> source) {
        Map<K,List<T>> out = new HashMap<>(Math.max(16, source.size() * 2));
        source.forEach((key, value) -> out.put(key, List.copyOf(value)));
        return Collections.unmodifiableMap(out);
    }

    @Override public String frontend() { return frontend; }
    @Override public List<FunctionFact> functions() { return functions; }
    @Override public List<TypeDeclFact> typeDecls() { return typeDecls; }
    @Override public List<CallFact> calls() { return calls; }
    @Override public List<ReturnFact> returns() { return returns; }
    @Override public List<LocalFact> locals() { return locals; }
    @Override public List<AssignmentFact> assignments() { return assignments; }
    @Override public List<PersistenceWriteFact> persistenceWrites() { return persistenceWrites; }
    @Override public List<PersistenceReadFact> persistenceReads() { return persistenceReads; }
    @Override public List<StateChannelWriteFact> stateChannelWrites() { return stateChannelWrites; }
    @Override public List<StateChannelReadFact> stateChannelReads() { return stateChannelReads; }
    @Override public List<IdentityFact> identityFacts() { return identityFacts; }
    @Override public List<CaptureFact> captureFacts() { return captureFacts; }
    @Override public List<CrossLangLinkFact> crossLangLinks() { return crossLangLinks; }
    @Override public List<MemoryLocationFact> memoryLocations() { return memoryLocations; }
    @Override public java.util.Optional<MemoryLocationFact> memoryLocation(long id) {
        return java.util.Optional.ofNullable(memoryById.get(id));
    }
    @Override public List<PointsToFact> pointsTo() { return pointsTo; }
    @Override public List<ExpressionFact> expressionFacts() { return expressionFacts; }
    @Override public List<ReachingDefFact> reachingDefs() { return reachingDefs; }
    @Override public List<SourceOriginFact> sourceOrigins() { return sourceOrigins; }
    @Override public java.util.Optional<ReachingDefFact> reachingDefsFor(long useId) {
        return java.util.Optional.ofNullable(reachingByUse.get(useId));
    }
    @Override public java.util.Optional<ExpressionFact> expressionFor(long callId) {
        return java.util.Optional.ofNullable(expressionById.get(callId));
    }
    @Override public java.util.Optional<CrossLangLinkFact> crossLangLinkForCall(long callId) {
        return java.util.Optional.ofNullable(crossLangByCall.get(callId));
    }
    @Override public java.util.Optional<CaptureFact> captureOfLocal(long innerLocalId) {
        return java.util.Optional.ofNullable(captureByInnerLocal.get(innerLocalId));
    }
    @Override public java.util.Optional<IdentityFact> identityOf(long functionId, String binding) {
        return java.util.Optional.ofNullable(identityByBinding.get(new IdentityKey(functionId, binding)));
    }
    @Override public List<StateWriteFact> stateWrites() { return stateWrites; }
    @Override public List<StateReadFact> stateReads() { return stateReads; }
    @Override public java.util.Optional<StateReadFact> stateRead(long id) { return java.util.Optional.ofNullable(stateReadById.get(id)); }
    @Override public List<StateWriteFact> stateWritesIn(long functionId) { return stateWritesByFunction.getOrDefault(functionId, List.of()); }

    @Override public Optional<FunctionFact> function(long id) { return Optional.ofNullable(functionById.get(id)); }
    @Override public Optional<CallFact> call(long id) { return Optional.ofNullable(callById.get(id)); }
    @Override public Optional<LocalFact> local(long id) { return Optional.ofNullable(localById.get(id)); }
    @Override public Optional<PersistenceWriteFact> persistenceWrite(long id) { return Optional.ofNullable(persistenceWriteById.get(id)); }
    @Override public Optional<PersistenceReadFact> persistenceRead(long id) { return Optional.ofNullable(persistenceReadById.get(id)); }
    @Override public Optional<StateChannelWriteFact> stateChannelWrite(long id) { return Optional.ofNullable(stateChannelWriteById.get(id)); }
    @Override public Optional<StateChannelReadFact> stateChannelRead(long id) { return Optional.ofNullable(stateChannelReadById.get(id)); }

    @Override public List<CallFact> callsIn(long functionId) { return callsByFunction.getOrDefault(functionId, List.of()); }
    @Override public List<ReturnFact> returnsIn(long functionId) { return returnsByFunction.getOrDefault(functionId, List.of()); }
    @Override public List<AssignmentFact> assignmentsTo(long functionId, long localId) {
        return assignmentsByTarget.getOrDefault(new AssignmentKey(functionId, localId), List.of());
    }
}

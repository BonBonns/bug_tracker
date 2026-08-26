package portable.graph;

import java.util.List;
import java.util.Optional;

public interface ProgramGraph {
    String frontend();
    List<FunctionFact> functions();
    List<TypeDeclFact> typeDecls();
    List<CallFact> calls();
    List<ReturnFact> returns();
    List<LocalFact> locals();
    List<AssignmentFact> assignments();
    List<PersistenceWriteFact> persistenceWrites();
    List<PersistenceReadFact> persistenceReads();
    List<StateChannelWriteFact> stateChannelWrites();
    List<StateChannelReadFact> stateChannelReads();
    default List<StateWriteFact> stateWrites() { return java.util.List.of(); }
    default List<StateReadFact> stateReads() { return java.util.List.of(); }
    default List<IdentityFact> identityFacts() { return java.util.List.of(); }
    default List<CaptureFact> captureFacts() { return java.util.List.of(); }
    default java.util.Optional<CaptureFact> captureOfLocal(long innerLocalId) {
        return captureFacts().stream().filter(c -> c.innerLocalId() == innerLocalId).findFirst();
    }
    default java.util.List<CrossLangLinkFact> crossLangLinks() { return java.util.List.of(); }
    default java.util.Optional<CrossLangLinkFact> crossLangLinkForCall(long callId) {
        return crossLangLinks().stream().filter(l -> l.callId() == callId).findFirst();
    }
    default java.util.List<MemoryLocationFact> memoryLocations() { return java.util.List.of(); }
    default java.util.Optional<MemoryLocationFact> memoryLocation(long id) {
        return memoryLocations().stream().filter(m -> m.id() == id).findFirst();
    }
    default java.util.List<PointsToFact> pointsTo() { return java.util.List.of(); }
    default java.util.List<SourceOriginFact> sourceOrigins() { return java.util.List.of(); }
    default java.util.List<ReachingDefFact> reachingDefs() { return java.util.List.of(); }
    default java.util.Optional<ReachingDefFact> reachingDefsFor(long useId) {
        return reachingDefs().stream().filter(r -> r.useId() == useId).findFirst();
    }
    default java.util.List<ExpressionFact> expressionFacts() { return java.util.List.of(); }
    default java.util.Optional<ExpressionFact> expressionFor(long callId) {
        return expressionFacts().stream().filter(e -> e.id() == callId).findFirst();
    }
    default java.util.Optional<IdentityFact> identityOf(long functionId, String binding) {
        return identityFacts().stream().filter(i -> i.functionId() == functionId && i.binding().equals(binding)).findFirst();
    }

    default Optional<FunctionFact> function(long id) { return functions().stream().filter(f -> f.id() == id).findFirst(); }
    default Optional<CallFact> call(long id) { return calls().stream().filter(c -> c.id() == id).findFirst(); }
    default Optional<LocalFact> local(long id) { return locals().stream().filter(l -> l.id() == id).findFirst(); }
    default Optional<PersistenceWriteFact> persistenceWrite(long id) { return persistenceWrites().stream().filter(w -> w.id() == id).findFirst(); }
    default Optional<PersistenceReadFact> persistenceRead(long id) { return persistenceReads().stream().filter(r -> r.id() == id).findFirst(); }
    default Optional<StateChannelWriteFact> stateChannelWrite(long id) { return stateChannelWrites().stream().filter(w -> w.id() == id).findFirst(); }
    default Optional<StateChannelReadFact> stateChannelRead(long id) { return stateChannelReads().stream().filter(r -> r.id() == id).findFirst(); }

    default List<CallFact> callsIn(long functionId) { return calls().stream().filter(c -> c.enclosingFunctionId() == functionId).toList(); }
    default java.util.Optional<StateReadFact> stateRead(long id) { return stateReads().stream().filter(r -> r.id() == id).findFirst(); }
    default List<StateWriteFact> stateWritesIn(long functionId) { return stateWrites().stream().filter(w -> w.functionId() == functionId).toList(); }
    default List<ReturnFact> returnsIn(long functionId) { return returns().stream().filter(r -> r.functionId() == functionId).toList(); }
    default List<AssignmentFact> assignmentsTo(long functionId, long localId) {
        return assignments().stream().filter(a -> a.functionId() == functionId && a.targetLocalId() == localId).toList();
    }
    default List<FunctionFact> demonstratedTargets(CallFact call) {
        return call.candidateTargetIds().stream().map(this::function).flatMap(Optional::stream).toList();
    }
}

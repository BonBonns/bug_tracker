package portable.graph;

import java.util.List;

public record InMemoryProgramGraph(
    String frontend,
    List<FunctionFact> functions,
    List<TypeDeclFact> typeDecls,
    List<CallFact> calls,
    List<ReturnFact> returns,
    List<LocalFact> locals,
    List<AssignmentFact> assignments,
    List<PersistenceWriteFact> persistenceWrites,
    List<PersistenceReadFact> persistenceReads,
    List<StateChannelWriteFact> stateChannelWrites,
    List<StateChannelReadFact> stateChannelReads,
    List<StateWriteFact> stateWrites,
    List<StateReadFact> stateReads,
    List<IdentityFact> identityFacts,
    List<CaptureFact> captureFacts,
    List<CrossLangLinkFact> crossLangLinks,
    List<MemoryLocationFact> memoryLocations,
    List<PointsToFact> pointsTo,
    List<ExpressionFact> expressionFacts,
    List<ReachingDefFact> reachingDefs,
    List<SourceOriginFact> sourceOrigins
) implements ProgramGraph {
    public InMemoryProgramGraph {
        functions = List.copyOf(functions); typeDecls = List.copyOf(typeDecls); calls = List.copyOf(calls);
        returns = List.copyOf(returns); locals = List.copyOf(locals); assignments = List.copyOf(assignments);
        persistenceWrites = List.copyOf(persistenceWrites); persistenceReads = List.copyOf(persistenceReads);
        stateChannelWrites = List.copyOf(stateChannelWrites); stateChannelReads = List.copyOf(stateChannelReads);
        stateWrites = List.copyOf(stateWrites); stateReads = List.copyOf(stateReads);
        identityFacts = List.copyOf(identityFacts);
        captureFacts = List.copyOf(captureFacts);
        crossLangLinks = List.copyOf(crossLangLinks);
        memoryLocations = List.copyOf(memoryLocations); pointsTo = List.copyOf(pointsTo);
        expressionFacts = List.copyOf(expressionFacts);
        reachingDefs = List.copyOf(reachingDefs);
        sourceOrigins = List.copyOf(sourceOrigins);
    }
    /** Compat: pre-reaching-def shape. */
    /** Compat: reaching-def-era shape (before source origins existed). */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts, List<CaptureFact> captureFacts, List<CrossLangLinkFact> crossLangLinks, List<MemoryLocationFact> memoryLocations, List<PointsToFact> pointsTo, List<ExpressionFact> expressionFacts, List<ReachingDefFact> reachingDefs) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, captureFacts, crossLangLinks, memoryLocations, pointsTo, expressionFacts, reachingDefs, List.of());
    }

    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts, List<CaptureFact> captureFacts, List<CrossLangLinkFact> crossLangLinks, List<MemoryLocationFact> memoryLocations, List<PointsToFact> pointsTo, List<ExpressionFact> expressionFacts) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, captureFacts, crossLangLinks, memoryLocations, pointsTo, expressionFacts, List.of(), List.of());
    }
    /** Compat: memory-era shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts, List<CaptureFact> captureFacts, List<CrossLangLinkFact> crossLangLinks, List<MemoryLocationFact> memoryLocations, List<PointsToFact> pointsTo) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, captureFacts, crossLangLinks, memoryLocations, pointsTo, List.of());
    }
    /** Compat: crosslang-era shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts, List<CaptureFact> captureFacts, List<CrossLangLinkFact> crossLangLinks) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, captureFacts, crossLangLinks, List.of(), List.of());
    }
    /** Compat: CORE-S03 shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts, List<CaptureFact> captureFacts) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, captureFacts, List.of());
    }
    /** Compat: CORE-S02 shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads, List<IdentityFact> identityFacts) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, identityFacts, List.of());
    }
    /** Compat: CORE-S01 shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads, List<StateWriteFact> stateWrites, List<StateReadFact> stateReads) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, stateWrites, stateReads, List.of());
    }
    /** Compat: pre-S01 canonical constructor shape. */
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads, List<StateChannelWriteFact> stateChannelWrites, List<StateChannelReadFact> stateChannelReads) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, stateChannelWrites, stateChannelReads, List.of(), List.of());
    }
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments, List<PersistenceWriteFact> persistenceWrites, List<PersistenceReadFact> persistenceReads) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, persistenceWrites, persistenceReads, List.of(), List.of());
    }
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns, List<LocalFact> locals, List<AssignmentFact> assignments) {
        this(frontend, functions, typeDecls, calls, returns, locals, assignments, List.of(), List.of(), List.of(), List.of());
    }
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls, List<ReturnFact> returns) {
        this(frontend, functions, typeDecls, calls, returns, List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }
    public InMemoryProgramGraph(String frontend, List<FunctionFact> functions, List<TypeDeclFact> typeDecls, List<CallFact> calls) {
        this(frontend, functions, typeDecls, calls, List.of(), List.of(), List.of(), List.of(), List.of(), List.of(), List.of());
    }
}

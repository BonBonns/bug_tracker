package portable.evidence;

import portable.graph.*;

import java.util.*;

/**
 * Structural relation projection over ProgramGraph facts. This class never
 * guesses a relation from syntax and never silently emits a generic fallback.
 * Every traversed ValueRef kind is either represented or explicitly abstained.
 */
public final class RelationEvidenceBuilder {
    private final ProgramGraph graph;

    public RelationEvidenceBuilder(ProgramGraph graph) {
        this.graph = Objects.requireNonNull(graph);
    }

    public List<EvidenceRelation> functionReturnRelations(long functionId) {
        List<ReturnFact> returns = graph.returnsIn(functionId);
        if (returns.isEmpty()) {
            return List.of(EvidenceRelation.abstain(
                "function:" + functionId, "return", Resolution.UNRESOLVED,
                AbstentionReason.MISSING_SEMANTIC_FACT, List.of(), "no return fact"));
        }
        if (returns.size() > 1) {
            List<Long> ids = returns.stream().map(ReturnFact::id).toList();
            return List.of(EvidenceRelation.abstain(
                "function:" + functionId, "return", Resolution.AMBIGUOUS,
                AbstentionReason.MULTIPLE_RETURN_VALUES, ids,
                "multiple return values require path/reaching-control discrimination"));
        }
        ReturnFact ret = returns.get(0);
        ArrayList<EvidenceRelation> out = new ArrayList<>();
        out.add(EvidenceRelation.established(RelationKind.RETURN_VALUE,
            valueLabel(ret.value()), "return:" + ret.id(), Resolution.EXACT,
            List.of(ret.id()), "returned semantic value"));
        walkValue(functionId, ret.value(), "return:" + ret.id(), out, new HashSet<>());
        return List.copyOf(out);
    }

    private void walkValue(long functionId, ValueRef value, String consumer, List<EvidenceRelation> out, Set<String> seen) {
        String key = functionId + ":" + value.kind() + ":" + value.referencedId() + ":" + consumer;
        if (!seen.add(key)) return;

        switch (value.kind()) {
            case PARAMETER -> out.add(EvidenceRelation.established(
                RelationKind.DIRECT_VALUE, valueLabel(value), consumer, Resolution.EXACT,
                List.of(value.referencedId()), "parameter value"));

            case CONSTANT -> out.add(EvidenceRelation.established(
                RelationKind.DIRECT_VALUE, "constant", consumer, Resolution.EXACT,
                List.of(), "constant value"));

            case UNKNOWN -> out.add(EvidenceRelation.abstain(
                valueLabel(value), consumer, Resolution.UNRESOLVED,
                AbstentionReason.MISSING_SEMANTIC_FACT, List.of(), "unknown semantic value"));

            case LOCAL -> {
                List<AssignmentFact> defs = graph.assignmentsTo(functionId, value.referencedId());
                if (defs.size() != 1) {
                    out.add(EvidenceRelation.abstain(
                        valueLabel(value), consumer,
                        defs.isEmpty() ? Resolution.UNRESOLVED : Resolution.AMBIGUOUS,
                        defs.isEmpty() ? AbstentionReason.MISSING_SEMANTIC_FACT : AbstentionReason.COMPETING_DEFINITIONS,
                        defs.stream().map(AssignmentFact::id).toList(),
                        defs.isEmpty() ? "no defining assignment" : "multiple defining assignments"));
                    return;
                }
                AssignmentFact d = defs.get(0);
                out.add(EvidenceRelation.established(RelationKind.ASSIGNMENT,
                    valueLabel(d.value()), valueLabel(value), Resolution.EXACT,
                    List.of(d.id()), "unique semantic definition"));
                walkValue(functionId, d.value(), valueLabel(value), out, seen);
            }

            case CALL -> {
                Optional<CallFact> oc = graph.call(value.referencedId());
                if (oc.isEmpty()) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.MISSING_SEMANTIC_FACT, List.of(), "call fact missing"));
                    return;
                }
                CallFact call = oc.get();
                if (call.resolution() == Resolution.UNRESOLVED) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.UNRESOLVED_CALL_TARGET, List.of(call.id()), "no demonstrated callee"));
                    return;
                }
                if (call.resolution() == Resolution.AMBIGUOUS) {
                    out.add(EvidenceRelation.possible(RelationKind.CALL_RESOLUTION,
                        "call:" + call.id(), "targets", Resolution.AMBIGUOUS,
                        call.candidateTargetIds(), "multiple demonstrated callees"));
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.AMBIGUOUS,
                        AbstentionReason.AMBIGUOUS_CALL_TARGET, call.candidateTargetIds(),
                        "do not select one callee as the return identity"));
                    return;
                }
                long targetId = call.candidateTargetIds().get(0);
                RelationStatus status = call.resolution() == Resolution.EXACT ? RelationStatus.ESTABLISHED : RelationStatus.POSSIBLE;
                EvidenceRelation cr = status == RelationStatus.ESTABLISHED
                    ? EvidenceRelation.established(RelationKind.CALL_RESOLUTION, "call:"+call.id(), "function:"+targetId, call.resolution(), List.of(targetId), "demonstrated call target")
                    : EvidenceRelation.possible(RelationKind.CALL_RESOLUTION, "call:"+call.id(), "function:"+targetId, call.resolution(), List.of(targetId), "heuristic call target");
                out.add(cr);

                FunctionFact callee = graph.function(targetId).orElse(null);
                if (callee == null) {
                    out.add(EvidenceRelation.abstain("call:"+call.id(), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.MISSING_SEMANTIC_FACT, List.of(targetId), "callee fact missing"));
                    return;
                }
                int n = Math.min(call.arguments().size(), callee.parameters().size());
                for (int i=0;i<n;i++) {
                    ArgumentFact arg = call.arguments().get(i);
                    ParameterFact param = callee.parameters().get(i);
                    out.add(status == RelationStatus.ESTABLISHED
                        ? EvidenceRelation.established(RelationKind.ARGUMENT_PARAMETER, valueLabel(arg.value()), "parameter:"+param.id(), call.resolution(), List.of(arg.id(),param.id()), "argument position "+i)
                        : EvidenceRelation.possible(RelationKind.ARGUMENT_PARAMETER, valueLabel(arg.value()), "parameter:"+param.id(), call.resolution(), List.of(arg.id(),param.id()), "argument position "+i));
                }
            }

            case PERSISTENCE_READ -> {
                Optional<PersistenceReadFact> or = graph.persistenceRead(value.referencedId());
                if (or.isEmpty()) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.MISSING_SEMANTIC_FACT, List.of(), "persistence read fact missing"));
                    return;
                }
                PersistenceReadFact read = or.get();
                if (read.resolution() == Resolution.UNRESOLVED) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.UNRESOLVED_PERSISTENCE_WRITE, List.of(read.id()), "no reaching write established"));
                    return;
                }
                RelationStatus s = read.resolution() == Resolution.EXACT ? RelationStatus.ESTABLISHED : RelationStatus.POSSIBLE;
                String from = "persistence:" + read.location().stableKey();
                out.add(s == RelationStatus.ESTABLISHED
                    ? EvidenceRelation.established(RelationKind.PERSISTENCE, from, consumer, read.resolution(), read.candidateWriteIds(), "read from persistence state")
                    : EvidenceRelation.possible(RelationKind.PERSISTENCE, from, consumer, read.resolution(), read.candidateWriteIds(), "possible persistence state"));
            }

            case STATE_CHANNEL_READ -> {
                Optional<StateChannelReadFact> or = graph.stateChannelRead(value.referencedId());
                if (or.isEmpty()) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.MISSING_SEMANTIC_FACT, List.of(), "state-channel read fact missing"));
                    return;
                }
                StateChannelReadFact read = or.get();
                if (read.sourceMode() == StateChannelSourceMode.UNMODELED) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.UNMODELED_STATE_CHANNEL, List.of(read.id()), "state channel recognized but origin model unavailable"));
                    return;
                }
                if (read.sourceMode() == StateChannelSourceMode.WRITE_LINKED && read.resolution() == Resolution.UNRESOLVED) {
                    out.add(EvidenceRelation.abstain(valueLabel(value), consumer, Resolution.UNRESOLVED,
                        AbstentionReason.UNRESOLVED_STATE_CHANNEL_WRITE, List.of(read.id()), "no reaching state-channel write established"));
                    return;
                }
                String from = "state:" + read.location().stableKey();
                RelationStatus status = read.resolution() == Resolution.EXACT ? RelationStatus.ESTABLISHED : RelationStatus.POSSIBLE;
                List<Long> support = read.sourceMode() == StateChannelSourceMode.EXTERNAL_SOURCE
                    ? List.of(read.id()) : read.candidateWriteIds();
                out.add(status == RelationStatus.ESTABLISHED
                    ? EvidenceRelation.established(RelationKind.STATE_CHANNEL, from, consumer, read.resolution(), support, "read from modeled state channel")
                    : EvidenceRelation.possible(RelationKind.STATE_CHANNEL, from, consumer, read.resolution(), support, "possible state-channel origin"));
            }
        }
    }

    private static String valueLabel(ValueRef v) {
        return v.kind().name().toLowerCase() + ":" + v.referencedId() + ":" + v.code();
    }
}

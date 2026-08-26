package portable.evidence;

import portable.provenance.OriginRef;
import portable.provenance.TruncationEvent;
import java.util.*;
import java.util.stream.Collectors;

/** Minimal dependency-free machine serializer for evidence A/B and downstream consumers. */
public final class EvidenceJsonWriter {
    private EvidenceJsonWriter() {}

    private static String q(String s) {
        if (s == null) return "null";
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\"";
    }
    private static String ints(Set<Integer> xs) {
        return xs.stream().sorted().map(String::valueOf).collect(Collectors.joining(",","[","]"));
    }
    private static String origins(Set<OriginRef> xs) {
        var list = new ArrayList<>(xs);
        list.sort(Comparator.comparing(OriginRef::channelLocation).thenComparingLong(OriginRef::eventId));
        return list.stream().map(o -> "{"+
            q("kind")+":"+q(o.kind().name())+","+
            q("event_id")+":"+o.eventId()+","+
            q("writer_function_id")+":"+o.writerFunctionId()+","+
            q("writer_parameter_index")+":"+o.writerParameterIndex()+","+
            q("channel_location")+":"+q(o.channelLocation())+"}")
            .collect(Collectors.joining(",","[","]"));
    }
    private static String contexts(List<ContextFrame> xs) {
        return xs.stream().map(c -> "{"+q("layer")+":"+q(c.layer())+","+q("context")+":"+q(c.context())+"}")
            .collect(Collectors.joining(",","[","]"));
    }
    private static String truncations(List<TruncationEvent> xs) {
        return xs.stream().map(t -> "{"+
            q("kind")+":"+q(t.kind().name())+","+
            q("function_id")+":"+t.functionId()+","+
            q("depth")+":"+t.depth()+","+
            q("work_consumed")+":"+t.workConsumed()+","+
            q("detail")+":"+q(t.detail())+"}")
            .collect(Collectors.joining(",","[","]"));
    }

    public static String toJson(ProvenanceEvidence e) {
        return "{"+
            q("schema")+":"+q("portable-evidence/0.1")+","+
            q("subject")+":{" +
            q("function_id")+":"+e.subject().functionId()+","+
            q("function_name")+":"+q(e.subject().functionName())+","+
            q("kind")+":"+q(e.subject().subjectKind())+"},"+
            q("relation_kind")+":"+q(e.relationKind().name())+","+
            q("identity_precision")+":"+q(e.identityPrecision().name())+","+
            q("origin_status")+":"+q(e.originStatus().name())+","+
            q("resolution")+":"+q(e.resolution().name())+","+
            q("completeness")+":"+q(e.completeness().name())+","+
            q("proven_parameter_positions")+":"+ints(e.provenParameterPositions())+","+
            q("may_parameter_positions")+":"+ints(e.mayParameterPositions())+","+
            q("proven_origins")+":"+origins(e.provenOrigins())+","+
            q("may_origins")+":"+origins(e.mayOrigins())+","+
            q("context_stack")+":"+contexts(e.contextStack())+","+
            q("truncations")+":"+truncations(e.truncations())+","+
            q("origin_established")+":"+e.originEstablished()+","+
            q("hard_path_eligible")+":"+e.hardPathEligible()+
            "}";
    }
}

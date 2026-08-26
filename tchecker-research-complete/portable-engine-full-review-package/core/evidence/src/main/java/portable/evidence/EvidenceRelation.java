package portable.evidence;

import portable.graph.Resolution;

import java.util.List;

/**
 * One typed semantic relationship in an evidence path. Evidence strength is
 * separate from any downstream verdict. An abstention is a real record, not
 * an omitted/fallback branch.
 */
public record EvidenceRelation(
    RelationKind kind,
    RelationStatus status,
    String from,
    String to,
    Resolution resolution,
    AbstentionReason abstentionReason,
    List<Long> relatedIds,
    String detail
) {
    public EvidenceRelation {
        relatedIds = List.copyOf(relatedIds);
        detail = detail == null ? "" : detail;
        if (kind == RelationKind.RETURN_PROVENANCE)
            throw new IllegalArgumentException("RETURN_PROVENANCE is aggregate evidence, not a path relation");
        if (status == RelationStatus.ABSTAINED) {
            if (kind != RelationKind.ABSTENTION)
                throw new IllegalArgumentException("ABSTAINED status requires ABSTENTION kind");
            if (abstentionReason == null || abstentionReason == AbstentionReason.NONE)
                throw new IllegalArgumentException("abstention requires an explicit reason");
        } else {
            if (kind == RelationKind.ABSTENTION)
                throw new IllegalArgumentException("ABSTENTION kind requires ABSTAINED status");
            if (abstentionReason != null && abstentionReason != AbstentionReason.NONE)
                throw new IllegalArgumentException("non-abstained relation cannot carry abstention reason");
        }
    }

    public static EvidenceRelation established(RelationKind kind, String from, String to, Resolution r, List<Long> ids, String detail) {
        return new EvidenceRelation(kind, RelationStatus.ESTABLISHED, from, to, r, AbstentionReason.NONE, ids, detail);
    }
    public static EvidenceRelation possible(RelationKind kind, String from, String to, Resolution r, List<Long> ids, String detail) {
        return new EvidenceRelation(kind, RelationStatus.POSSIBLE, from, to, r, AbstentionReason.NONE, ids, detail);
    }
    public static EvidenceRelation abstain(String from, String to, Resolution r, AbstentionReason why, List<Long> ids, String detail) {
        return new EvidenceRelation(RelationKind.ABSTENTION, RelationStatus.ABSTAINED, from, to, r, why, ids, detail);
    }
}

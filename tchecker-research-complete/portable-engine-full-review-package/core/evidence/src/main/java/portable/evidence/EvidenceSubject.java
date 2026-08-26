package portable.evidence;

/** Stable subject for evidence. */
public record EvidenceSubject(long functionId, String functionName, String subjectKind) {
    public EvidenceSubject {
        if (functionName == null) functionName = "";
        if (subjectKind == null) subjectKind = "FUNCTION_RETURN";
    }
}

package portable.evidence;

/**
 * Language-neutral semantic relation taxonomy used by evidence consumers.
 * Deliberately contains no generic/fallback relation: unsupported or ambiguous
 * cases must be represented explicitly as ABSTENTION with a reason.
 */
public enum RelationKind {
    DIRECT_VALUE,
    ASSIGNMENT,
    ARGUMENT_PARAMETER,
    RETURN_VALUE,
    PROPERTY_STATE,
    INDEX_STATE,
    PERSISTENCE,
    STATE_CHANNEL,
    TRANSFORMATION,
    CONTROL_JOIN,
    CALL_RESOLUTION,
    ABSTENTION,

    /** Compatibility label retained for Gate 29's aggregate function-return evidence. */
    RETURN_PROVENANCE
}

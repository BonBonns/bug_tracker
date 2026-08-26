package portable.evidence;

/** Machine-readable reasons why the engine deliberately declines to name a relation. */
public enum AbstentionReason {
    NONE,
    COMPETING_DEFINITIONS,
    UNRESOLVED_CALL_TARGET,
    AMBIGUOUS_CALL_TARGET,
    UNRESOLVED_PERSISTENCE_WRITE,
    UNRESOLVED_STATE_CHANNEL_WRITE,
    UNMODELED_STATE_CHANNEL,
    UNSUPPORTED_VALUE_KIND,
    MISSING_SEMANTIC_FACT,
    MULTIPLE_RETURN_VALUES
}

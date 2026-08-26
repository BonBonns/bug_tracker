package portable.consumer;

/** Context-specific transformation assessment. This is deliberately independent of provenance. */
public enum EffectDisposition {
    GUARANTEED_FOR_CONTEXT,
    CONDITIONAL_FOR_CONTEXT,
    INADEQUATE_FOR_CONTEXT,
    UNKNOWN_FOR_CONTEXT,
    NOT_EVALUATED
}

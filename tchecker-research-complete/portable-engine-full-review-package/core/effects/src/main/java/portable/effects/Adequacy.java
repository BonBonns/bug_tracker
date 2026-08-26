package portable.effects;

/** Whether a transformation is adequate for a specific effect-class + use-context pair. */
public enum Adequacy {
    GUARANTEED,
    CONDITIONAL,
    INADEQUATE,
    UNKNOWN
}

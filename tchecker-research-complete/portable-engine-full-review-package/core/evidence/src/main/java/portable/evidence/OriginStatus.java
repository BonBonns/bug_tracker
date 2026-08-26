package portable.evidence;

/** What the analysis established about the origin of the identified value. */
public enum OriginStatus {
    /** At least one dependency/origin is proven for all relevant alternatives. */
    ESTABLISHED,
    /** No hard origin is proven, but at least one origin is possible. */
    POSSIBLE,
    /** Complete analysis demonstrated no parameter/out-of-band origin. */
    NONE,
    /** Analysis could not establish an origin. */
    NOT_ESTABLISHED,
    /** Analysis stopped before completion; absence of origin is not meaningful. */
    PARTIAL
}

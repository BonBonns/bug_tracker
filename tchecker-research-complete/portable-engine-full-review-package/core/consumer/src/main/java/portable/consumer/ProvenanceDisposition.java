package portable.consumer;

/** Deterministic interpretation of provenance evidence only; not a security verdict. */
public enum ProvenanceDisposition {
    HARD_PATH,
    ESTABLISHED_ORIGIN_UNCERTAIN_PATH,
    POSSIBLE_ORIGIN,
    NO_ORIGIN,
    NOT_ESTABLISHED,
    PARTIAL
}

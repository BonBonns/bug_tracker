package portable.effects;

/** Generic semantic effect classes. Security profiles may define policy over these later. */
public enum EffectClass {
    NORMALIZATION,
    CANONICALIZATION,
    ENCODING,
    VALIDATION,
    REDACTION,
    PARSING
}

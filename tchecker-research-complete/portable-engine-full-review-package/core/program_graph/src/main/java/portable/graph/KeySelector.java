package portable.graph;

/** Slot identity for keyed state: a static literal slot or a dynamic (unknown) key. */
public record KeySelector(Kind kind, String literal, String dynamicRef) {
    public enum Kind { LITERAL, DYNAMIC }
    public KeySelector {
        // "" and null are DIFFERENT states. `obj[""]` is legal JavaScript (an
        // empty-string property key) and was observed in real code — axios
        // (charMap) and lodash (htmlEscapes, stringEscapes) — where the old
        // isEmpty() check refused the ENTIRE document over 1-2 such accesses.
        // A MISSING key is still rejected; an empty-string key is now accepted.
        if (kind == Kind.LITERAL && literal == null)
            throw new IllegalArgumentException("LITERAL key requires a literal value");
        if (kind == Kind.DYNAMIC && (dynamicRef == null || dynamicRef.isEmpty()))
            throw new IllegalArgumentException("DYNAMIC key requires a ref");
    }
    public static KeySelector literal(String v) { return new KeySelector(Kind.LITERAL, v, null); }
    public static KeySelector dynamic(String ref) { return new KeySelector(Kind.DYNAMIC, null, ref); }
}

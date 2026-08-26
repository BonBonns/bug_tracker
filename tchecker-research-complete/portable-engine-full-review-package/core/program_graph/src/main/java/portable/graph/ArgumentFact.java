package portable.graph;

public record ArgumentFact(
    long id,
    int index,
    String kind,
    String code,
    String name,
    String typeFullName,
    Integer line,
    ValueRef value
) {
    /** Gate-25/source compatibility: an argument whose value relation is not yet exported. */
    public ArgumentFact(long id, int index, String kind, String code, String name, String typeFullName, Integer line) {
        this(id, index, kind, code, name, typeFullName, line, ValueRef.unknown(code));
    }
}

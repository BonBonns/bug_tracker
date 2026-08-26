package portable.graph;

public record ParameterFact(long id, long methodId, int index, String name, String code, String typeFullName, Integer line) {}

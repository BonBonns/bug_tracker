package portable.graph;

/** Language-neutral local variable/binding inside one function. */
public record LocalFact(long id, long functionId, String name, String typeFullName, Integer line) {}

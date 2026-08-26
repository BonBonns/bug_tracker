package portable.graph;

import java.util.List;

public record FunctionFact(
    long id,
    String name,
    String fullName,
    String signature,
    String file,
    Integer line,
    Integer lineEnd,
    boolean external,
    List<ParameterFact> parameters,
    String returnTypeFullName
) {
    public FunctionFact {
        parameters = List.copyOf(parameters);
    }
}

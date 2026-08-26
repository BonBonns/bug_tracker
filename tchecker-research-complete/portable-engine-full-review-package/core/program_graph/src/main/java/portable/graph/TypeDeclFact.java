package portable.graph;

import java.util.List;

public record TypeDeclFact(long id, String name, String fullName, String file, Integer line, boolean external, List<String> inheritsFrom) {
    public TypeDeclFact { inheritsFrom = List.copyOf(inheritsFrom); }
}

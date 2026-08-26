package portable.graph;

import java.util.List;

/** Canonical identity for the receiver of a keyed-state access.
 *
 *  For {@code input.profile.url}, the outer {@code url} access has root
 *  {@code input} and receiver path {@code [profile]}. Keeping the root binding
 *  separate from the ordered path lets independently-created AST accessor nodes
 *  denote the same state location without equating unrelated objects.
 */
public record StateLocation(ValueRef root, List<KeySelector> path) {
    public StateLocation {
        if (root == null) throw new IllegalArgumentException("state location requires a root");
        if (path == null) throw new IllegalArgumentException("state location requires a path");
        path = List.copyOf(path);
    }

    public static StateLocation direct(ValueRef receiver) {
        return new StateLocation(receiver, List.of());
    }

    public boolean fullyLiteral() {
        return path.stream().allMatch(k -> k.kind() == KeySelector.Kind.LITERAL);
    }

    public List<KeySelector> withKey(KeySelector key) {
        java.util.ArrayList<KeySelector> out = new java.util.ArrayList<>(path);
        out.add(key);
        return List.copyOf(out);
    }
}

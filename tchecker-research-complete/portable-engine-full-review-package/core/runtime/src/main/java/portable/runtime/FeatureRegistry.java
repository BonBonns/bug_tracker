package portable.runtime;

import java.util.*;

/** Explicit registry for experimental/optional engine behavior. */
public final class FeatureRegistry {
    public record Feature(String name, boolean enabled, String source) {
        public Feature {
            if (name == null || name.isBlank()) throw new IllegalArgumentException("feature name required");
            source = source == null ? "unknown" : source;
        }
    }

    private final LinkedHashMap<String,Feature> features = new LinkedHashMap<>();

    public FeatureRegistry register(String name, boolean enabled, String source) {
        if (features.containsKey(name)) throw new IllegalArgumentException("duplicate feature: " + name);
        features.put(name, new Feature(name, enabled, source));
        return this;
    }

    public FeatureRegistry registerEnv(String name, String envVar, Map<String,String> env) {
        String raw = env.get(envVar);
        boolean enabled = raw != null && !raw.isBlank() && !raw.equals("0") && !raw.equalsIgnoreCase("false");
        return register(name, enabled, "env:" + envVar);
    }

    public boolean enabled(String name) {
        Feature f = features.get(name);
        if (f == null) throw new IllegalArgumentException("unregistered feature: " + name);
        return f.enabled();
    }

    public List<Feature> all() { return List.copyOf(features.values()); }
}

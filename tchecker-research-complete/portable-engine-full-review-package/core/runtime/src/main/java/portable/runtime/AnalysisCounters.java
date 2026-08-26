package portable.runtime;

import java.util.*;

/** Structured counters; absent counters are zero. */
public final class AnalysisCounters {
    private final TreeMap<String,Long> values = new TreeMap<>();
    public AnalysisCounters add(String key, long delta) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("counter key required");
        values.merge(key, delta, Long::sum);
        return this;
    }
    public AnalysisCounters set(String key, long value) {
        if (key == null || key.isBlank()) throw new IllegalArgumentException("counter key required");
        values.put(key, value); return this;
    }
    public long get(String key) { return values.getOrDefault(key, 0L); }
    public Map<String,Long> snapshot() { return Collections.unmodifiableMap(new TreeMap<>(values)); }
}

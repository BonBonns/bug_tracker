package portable.runtime;

import java.util.*;

/** Run collector. COMPLETE is explicit; forgetting finishComplete() yields PARTIAL. */
public final class AnalysisRunBuilder {
    private final String engineVersion;
    private final FeatureRegistry features;
    private final AnalysisCounters counters = new AnalysisCounters();
    private final List<AnalysisResultRecord> results = new ArrayList<>();
    private final List<String> abstentions = new ArrayList<>();
    private final List<String> truncations = new ArrayList<>();
    private AnalysisStatus status = AnalysisStatus.PARTIAL;
    private String failure = "";

    public AnalysisRunBuilder(String engineVersion, FeatureRegistry features) {
        this.engineVersion = engineVersion;
        this.features = features == null ? new FeatureRegistry() : features;
    }
    public AnalysisCounters counters() { return counters; }
    public AnalysisRunBuilder result(AnalysisResultRecord r) { results.add(r); return this; }
    public AnalysisRunBuilder abstention(String s) { abstentions.add(s); counters.add("abstentions",1); return this; }
    public AnalysisRunBuilder truncation(String s) { truncations.add(s); counters.add("truncated",1); return this; }
    public AnalysisRunBuilder finishComplete() { status=AnalysisStatus.COMPLETE; failure=""; return this; }
    public AnalysisRunBuilder fail(String why) { status=AnalysisStatus.FAILED; failure=why == null ? "failed" : why; return this; }
    public AnalysisRun build() { return new AnalysisRun("portable-analysis-run/0.1", engineVersion, status, features.all(), counters.snapshot(), results, abstentions, truncations, failure); }
}

package portable.runtime;

import java.util.*;

/** First-class A/B diff over stable result IDs and uncertainty transitions. */
public final class RunDiff {
    public record Changed(String stableId, String beforeResolution, String afterResolution, String beforeOrigin, String afterOrigin, String beforeCompleteness, String afterCompleteness) {}
    public record Diff(List<String> appeared, List<String> disappeared, List<Changed> changed, Map<String,Long> counterDelta) {}

    public static Diff compare(AnalysisRun a, AnalysisRun b) {
        Map<String,AnalysisResultRecord> am=index(a), bm=index(b);
        TreeSet<String> appeared=new TreeSet<>(bm.keySet()); appeared.removeAll(am.keySet());
        TreeSet<String> disappeared=new TreeSet<>(am.keySet()); disappeared.removeAll(bm.keySet());
        List<Changed> changed=new ArrayList<>();
        TreeSet<String> both=new TreeSet<>(am.keySet()); both.retainAll(bm.keySet());
        for(String id:both){ var x=am.get(id); var y=bm.get(id);
            if(!x.resolution().equals(y.resolution()) || !x.originStatus().equals(y.originStatus()) || !x.completeness().equals(y.completeness()))
                changed.add(new Changed(id,x.resolution(),y.resolution(),x.originStatus(),y.originStatus(),x.completeness(),y.completeness()));
        }
        TreeSet<String> keys=new TreeSet<>(); keys.addAll(a.counters().keySet()); keys.addAll(b.counters().keySet());
        TreeMap<String,Long> delta=new TreeMap<>(); for(String k:keys){ long d=b.counters().getOrDefault(k,0L)-a.counters().getOrDefault(k,0L); if(d!=0)delta.put(k,d); }
        return new Diff(List.copyOf(appeared),List.copyOf(disappeared),List.copyOf(changed),Collections.unmodifiableMap(delta));
    }
    private static Map<String,AnalysisResultRecord> index(AnalysisRun r){
        LinkedHashMap<String,AnalysisResultRecord> m=new LinkedHashMap<>();
        for(var x:r.results()) if(m.put(x.stableId(),x)!=null) throw new IllegalArgumentException("duplicate stable result id: "+x.stableId());
        return m;
    }
}

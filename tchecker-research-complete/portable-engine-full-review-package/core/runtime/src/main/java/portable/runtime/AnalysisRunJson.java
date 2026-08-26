package portable.runtime;

import java.util.*;

/** Dependency-free deterministic JSON for machine diffing. */
public final class AnalysisRunJson {
    private AnalysisRunJson() {}
    private static String q(String s){
        StringBuilder b=new StringBuilder("\"");
        for(char c:s.toCharArray()) switch(c){
            case '\\' -> b.append("\\\\"); case '"' -> b.append("\\\""); case '\n' -> b.append("\\n"); case '\r' -> b.append("\\r"); case '\t' -> b.append("\\t"); default -> b.append(c);
        }
        return b.append('"').toString();
    }
    private static String arr(Collection<String> xs){ return xs.stream().map(AnalysisRunJson::q).reduce("[",(a,b)->a+(a.length()>1?",":"")+b)+"]"; }
    public static String write(AnalysisRun r){
        StringBuilder b=new StringBuilder(); b.append("{");
        b.append("\"schema\":").append(q(r.schema())).append(',');
        b.append("\"engine_version\":").append(q(r.engineVersion())).append(',');
        b.append("\"analysis_status\":").append(q(r.status().name())).append(',');
        b.append("\"features\":["); boolean first=true;
        for(var f:r.features()){ if(!first)b.append(','); first=false; b.append("{\"name\":").append(q(f.name())).append(",\"enabled\":").append(f.enabled()).append(",\"source\":").append(q(f.source())).append('}'); }
        b.append("],\"counters\":{"); first=true;
        for(var e:r.counters().entrySet()){ if(!first)b.append(','); first=false; b.append(q(e.getKey())).append(':').append(e.getValue()); }
        b.append("},\"results\":["); first=true;
        for(var x:r.results()){ if(!first)b.append(','); first=false; b.append('{')
            .append("\"stable_id\":").append(q(x.stableId())).append(',')
            .append("\"subject\":").append(q(x.subject())).append(',')
            .append("\"relation_kind\":").append(q(x.relationKind())).append(',')
            .append("\"identity_precision\":").append(q(x.identityPrecision())).append(',')
            .append("\"origin_status\":").append(q(x.originStatus())).append(',')
            .append("\"resolution\":").append(q(x.resolution())).append(',')
            .append("\"completeness\":").append(q(x.completeness())).append(',')
            .append("\"proven_origins\":").append(arr(x.provenOrigins())).append(',')
            .append("\"may_origins\":").append(arr(x.mayOrigins())).append('}'); }
        b.append("],\"abstentions\":").append(arr(r.abstentions()));
        b.append(",\"truncations\":").append(arr(r.truncations()));
        b.append(",\"failure\":").append(q(r.failure())).append('}');
        return b.toString();
    }
}

import portable.runtime.*;
import java.util.*;

public final class Gate35MeasurementHarnessTest {
    static int pass=0,total=0;
    static void check(String n, boolean ok, Object got){ total++; if(!ok)throw new AssertionError(n+" failed: "+got); pass++; System.out.println("PASS "+n+" -> "+got); }
    static AnalysisResultRecord r(String id,String origin,String resolution,String completeness){
        return new AnalysisResultRecord(id,"function:return","RETURN_VALUE","VALUE_SPECIFIC",origin,resolution,completeness,List.of(),List.of());
    }
    public static void main(String[] args){
        var reg=new FeatureRegistry().register("state_channels",true,"test").registerEnv("experimental_alias","WP_EXPERIMENTAL_ALIAS",Map.of("WP_EXPERIMENTAL_ALIAS","1"));
        check("feature_registry_requires_explicit_registration",reg.enabled("state_channels")&&reg.enabled("experimental_alias"),reg.all());
        boolean unknownRejected=false; try{reg.enabled("missing");}catch(IllegalArgumentException e){unknownRejected=true;}
        check("unknown_feature_cannot_silently_default",unknownRejected,"rejected");

        var partial=new AnalysisRunBuilder("gate35",reg).result(r("A","NOT_ESTABLISHED","UNRESOLVED","UNKNOWN")).build();
        check("completion_is_not_implicit",partial.status()==AnalysisStatus.PARTIAL&&!partial.complete(),partial.status());

        var baseB=new AnalysisRunBuilder("gate35",reg);
        baseB.counters().set("exact",1).set("ambiguous",1).set("unknown",1);
        baseB.result(r("A","ESTABLISHED","EXACT","COMPLETE"));
        baseB.result(r("B","POSSIBLE","AMBIGUOUS","COMPLETE"));
        baseB.result(r("C","NOT_ESTABLISHED","UNRESOLVED","UNKNOWN"));
        baseB.abstention("C:UNRESOLVED_CALL_TARGET");
        var base=baseB.finishComplete().build();
        check("explicit_complete_marker",base.status()==AnalysisStatus.COMPLETE&&base.complete(),base.status());
        check("structured_uncertainty_counters",base.counters().get("exact")==1&&base.counters().get("ambiguous")==1&&base.counters().get("unknown")==1,base.counters());
        check("abstention_counter_is_structured",base.counters().get("abstentions")==1&&base.abstentions().size()==1,base.counters());

        var candB=new AnalysisRunBuilder("gate35",reg);
        candB.counters().set("exact",2).set("ambiguous",0).set("unknown",1);
        candB.result(r("A","ESTABLISHED","EXACT","COMPLETE"));
        candB.result(r("B","ESTABLISHED","EXACT","COMPLETE"));
        candB.result(r("D","NOT_ESTABLISHED","UNRESOLVED","UNKNOWN"));
        candB.truncation("D:WORK_BUDGET depth=12");
        var cand=candB.finishComplete().build();
        check("truncations_are_structured_and_counted",cand.counters().get("truncated")==1&&cand.truncations().size()==1,cand.counters());

        var d=RunDiff.compare(base,cand);
        check("ab_detects_appeared",d.appeared().equals(List.of("D")),d);
        check("ab_detects_disappeared",d.disappeared().equals(List.of("C")),d);
        check("ab_detects_uncertainty_transition",d.changed().size()==1&&d.changed().get(0).stableId().equals("B")&&d.changed().get(0).beforeResolution().equals("AMBIGUOUS")&&d.changed().get(0).afterResolution().equals("EXACT"),d.changed());
        check("ab_counter_delta_is_machine_readable",d.counterDelta().get("exact")==1&&d.counterDelta().get("ambiguous")==-1&&d.counterDelta().get("truncated")==1,d.counterDelta());

        String json=AnalysisRunJson.write(cand);
        check("run_json_has_schema_and_complete_status",json.contains("\"schema\":\"portable-analysis-run/0.1\"")&&json.contains("\"analysis_status\":\"COMPLETE\""),json);
        check("run_json_contains_stable_result_ids",json.contains("\"stable_id\":\"A\"")&&json.contains("\"stable_id\":\"D\""),json);
        check("run_json_contains_feature_registry",json.contains("\"name\":\"state_channels\"")&&json.contains("\"source\":\"test\""),json);
        check("run_json_contains_truncations",json.contains("D:WORK_BUDGET depth=12"),json);

        boolean dup=false;
        var dupRun=new AnalysisRunBuilder("gate35",reg).result(r("X","NONE","EXACT","COMPLETE")).result(r("X","NONE","EXACT","COMPLETE")).finishComplete().build();
        try{RunDiff.compare(dupRun,base);}catch(IllegalArgumentException e){dup=true;}
        check("duplicate_stable_ids_fail_closed",dup,"rejected");

        var failed=new AnalysisRunBuilder("gate35",reg).fail("synthetic failure").build();
        check("failed_run_is_distinct_from_partial_and_complete",failed.status()==AnalysisStatus.FAILED&&!failed.complete()&&failed.failure().contains("synthetic"),failed.status());

        System.out.println("GATE35="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

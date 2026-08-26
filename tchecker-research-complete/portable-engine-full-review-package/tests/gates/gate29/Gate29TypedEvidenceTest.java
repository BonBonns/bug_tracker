import portable.graph.*;
import portable.provenance.*;
import portable.evidence.*;
import java.util.*;

public class Gate29TypedEvidenceTest {
    static int pass=0,total=0;
    static void check(String name, boolean ok, Object got){total++; if(!ok)throw new AssertionError(name+" failed: "+got); pass++; System.out.println("PASS "+name+" -> "+got);}
    static ParameterFact p(long id,long f,int i,String n){return new ParameterFact(id,f,i,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"", "gate29.ts",1,2,false,List.of(ps),"any");}
    static ReturnFact r(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static ArgumentFact a(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,"ARG",v.code(),"","any",1,v);}
    static CallFact c(long id,long f,String n,Resolution res,List<Long> targets,ArgumentFact...args){
        return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"()","gate29.ts",1,targets,List.of(),res,List.of(args));
    }

    public static void main(String[] args){
        // identity(x) -> x
        var p1=p(101,1,0,"x"); var f1=f(1,"identity",p1);
        // constant() -> CONST
        var f2=f(2,"constant");
        // unknown() -> unknown semantic value
        var f3=f(3,"unknown");
        // second identity target for ambiguous-shared case
        var p4=p(401,4,0,"x"); var f4=f(4,"identityB",p4);
        // ambiguousShared(input) -> ambiguous call to two functions that both return arg0
        var p5=p(501,5,0,"input"); var f5=f(5,"ambiguousShared",p5);
        var c50=c(50,5,"m",Resolution.AMBIGUOUS,List.of(1L,4L),a(5001,0,ValueRef.parameter(501,"input")));
        // heuristic(input) -> heuristic call to identity
        var p6=p(601,6,0,"input"); var f6=f(6,"heuristic",p6);
        var c60=c(60,6,"identity",Resolution.HEURISTIC,List.of(1L),a(6001,0,ValueRef.parameter(601,"input")));
        // multi-return(input): two return sites, same proven origin
        var p7=p(701,7,0,"input"); var f7=f(7,"multi",p7);
        // persistence writer + reader
        var p8=p(801,8,0,"source"); var f8=f(8,"persist",p8); var f9=f(9,"load");
        var loc=new PersistenceLocation("db","user:42","name");
        var wr=new PersistenceWriteFact(8000,8,loc,ValueRef.parameter(801,"source"),1);
        var rd=new PersistenceReadFact(9000,9,loc,List.of(8000L),Resolution.EXACT,1);
        // deep chain d10 -> d11 -> d12 -> d13 to force visible partial with low budget
        var p13=p(1301,13,0,"deep"); var f13=f(13,"d13",p13);
        var p12=p(1201,12,0,"x"); var f12=f(12,"d12",p12); var c120=c(120,12,"d13",Resolution.EXACT,List.of(13L),a(12001,0,ValueRef.parameter(1201,"x")));
        var p11=p(1101,11,0,"x"); var f11=f(11,"d11",p11); var c110=c(110,11,"d12",Resolution.EXACT,List.of(12L),a(11001,0,ValueRef.parameter(1101,"x")));
        var p10=p(1001,10,0,"x"); var f10=f(10,"d10",p10); var c100=c(100,10,"d11",Resolution.EXACT,List.of(11L),a(10001,0,ValueRef.parameter(1001,"x")));

        var g=new InMemoryProgramGraph("gate29",
            List.of(f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13), List.of(),
            List.of(c50,c60,c100,c110,c120),
            List.of(
                r(10,1,ValueRef.parameter(101,"x")),
                r(20,2,ValueRef.constant("CONST")),
                r(30,3,ValueRef.unknown("opaque")),
                r(40,4,ValueRef.parameter(401,"x")),
                r(50,5,ValueRef.call(50,"m(input)")),
                r(60,6,ValueRef.call(60,"identity(input)")),
                r(70,7,ValueRef.parameter(701,"input")), r(71,7,ValueRef.parameter(701,"input")),
                r(90,9,ValueRef.persistenceRead(9000,"db[user:42].name")),
                r(100,10,ValueRef.call(100,"d11(x)")), r(110,11,ValueRef.call(110,"d12(x)")), r(120,12,ValueRef.call(120,"d13(x)")), r(130,13,ValueRef.parameter(1301,"deep"))
            ), List.of(), List.of(), List.of(wr), List.of(rd));

        var engine=new PortableProvenanceEngine(g);
        var eb=new ProvenanceEvidenceBuilder(g,engine);

        var exact=eb.functionReturn(1);
        check("value_specific_and_origin_established_are_independent_fields",
            exact.identityPrecision()==IdentityPrecision.VALUE_SPECIFIC && exact.originStatus()==OriginStatus.ESTABLISHED && exact.originEstablished(), exact);
        check("exact_complete_value_can_project_hard_path",exact.hardPathEligible(),exact);

        var constant=eb.functionReturn(2);
        check("complete_constant_is_none_not_unknown",constant.identityPrecision()==IdentityPrecision.VALUE_SPECIFIC && constant.originStatus()==OriginStatus.NONE && !constant.hardPathEligible(),constant);

        var unknown=eb.functionReturn(3);
        check("identified_value_can_have_unestablished_origin",unknown.identityPrecision()==IdentityPrecision.VALUE_SPECIFIC && unknown.originStatus()==OriginStatus.NOT_ESTABLISHED && unknown.completeness()==AnalysisCompleteness.UNKNOWN,unknown);

        var amb=eb.functionReturn(5);
        check("ambiguous_path_can_still_prove_common_origin",amb.originStatus()==OriginStatus.ESTABLISHED && amb.resolution()==Resolution.AMBIGUOUS && amb.provenParameterPositions().equals(Set.of(0)),amb);
        check("proven_origin_is_not_same_as_exact_hard_path",amb.originEstablished() && !amb.hardPathEligible(),amb);

        var heur=eb.functionReturn(6);
        check("heuristic_origin_is_possible_not_established",heur.originStatus()==OriginStatus.POSSIBLE && heur.mayParameterPositions().equals(Set.of(0)) && !heur.originEstablished(),heur);

        var multi=eb.functionReturn(7);
        check("multiple_return_values_do_not_fake_value_specific_identity",multi.identityPrecision()==IdentityPrecision.MULTI_VALUE && multi.originStatus()==OriginStatus.ESTABLISHED && !multi.hardPathEligible(),multi);

        var persisted=eb.functionReturn(9);
        check("out_of_band_persistence_origin_is_typed_established",persisted.originStatus()==OriginStatus.ESTABLISHED && persisted.provenParameterPositions().isEmpty() && persisted.provenOrigins().size()==1,persisted);

        var context=eb.functionReturn(1,List.of(new ContextFrame("parser","typescript"),new ContextFrame("consumer","display")));
        check("context_stack_is_preserved_but_does_not_change_provenance",context.contextStack().size()==2 && context.originStatus()==exact.originStatus() && context.resolution()==exact.resolution(),context.contextStack());

        var lowEngine=new PortableProvenanceEngine(g,new AnalysisBudget(1000,2));
        var partial=new ProvenanceEvidenceBuilder(g,lowEngine).functionReturn(10);
        check("truncation_is_partial_not_no_origin",partial.originStatus()==OriginStatus.PARTIAL && partial.completeness()==AnalysisCompleteness.PARTIAL && !partial.truncations().isEmpty() && !partial.hardPathEligible(),partial);

        var before=engine.summarize(5);
        String json=EvidenceJsonWriter.toJson(amb);
        var after=engine.summarize(5);
        check("evidence_projection_is_read_only",before.equals(after),json);
        check("machine_contract_exposes_identity_origin_resolution_completeness",
            json.contains("\"identity_precision\":\"VALUE_SPECIFIC\"") && json.contains("\"origin_status\":\"ESTABLISHED\"") && json.contains("\"resolution\":\"AMBIGUOUS\"") && json.contains("\"completeness\":\"COMPLETE\""),json);
        check("evidence_contract_contains_no_security_verdict",!json.toLowerCase().contains("vulnerable") && !json.toLowerCase().contains("verdict") && !amb.hasSecurityVerdict(),json);

        boolean rejected=false;
        try {
            new ProvenanceEvidence(new EvidenceSubject(99,"bad","FUNCTION_RETURN"),RelationKind.RETURN_PROVENANCE,IdentityPrecision.VALUE_SPECIFIC,OriginStatus.ESTABLISHED,Resolution.EXACT,AnalysisCompleteness.COMPLETE,Set.of(),Set.of(),Set.of(),Set.of(),List.of(),List.of());
        } catch(IllegalArgumentException ex){ rejected=true; }
        check("established_origin_requires_actual_proof",rejected,rejected);

        System.out.println("GATE29="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

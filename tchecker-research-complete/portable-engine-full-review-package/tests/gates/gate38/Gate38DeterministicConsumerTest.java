import portable.graph.*;
import portable.provenance.*;
import portable.evidence.*;
import portable.effects.*;
import portable.consumer.*;
import java.util.*;

public class Gate38DeterministicConsumerTest {
    static int pass=0,total=0;
    static void check(String n, boolean ok, Object got){total++; if(!ok) throw new AssertionError(n+" failed: "+got); pass++; System.out.println("PASS "+n+" -> "+got);}
    static ParameterFact p(long id,long f,int i,String n){return new ParameterFact(id,f,i,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate38.ts",1,2,false,List.of(ps),"any");}
    static ReturnFact r(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static ArgumentFact a(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,"ARG",v.code(),"","any",1,v);}
    static CallFact c(long id,long f,String n,Resolution res,List<Long> targets,ArgumentFact...args){return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"()","gate38.ts",1,targets,List.of(),res,List.of(args));}

    static ContextStackAssessment effect(Adequacy a, boolean complete, int layers){
        var reqs=new ArrayList<EffectRequirement>();
        var las=new ArrayList<ContextLayerAssessment>();
        for(int i=0;i<layers;i++){
            var req=new EffectRequirement(EffectClass.ENCODING,new EffectContext("parser","L"+i));
            reqs.add(req); las.add(new ContextLayerAssessment(req,List.of("enc"+i),a,"test"));
        }
        return new ContextStackAssessment(new ContextStack(reqs),las,a,complete);
    }

    public static void main(String[] args){
        var p1=p(101,1,0,"x"); var f1=f(1,"identity",p1);
        var f2=f(2,"constant");
        var f3=f(3,"unknown");
        var p4=p(401,4,0,"x"); var f4=f(4,"identityB",p4);
        var p5=p(501,5,0,"input"); var f5=f(5,"ambiguousShared",p5);
        var c50=c(50,5,"m",Resolution.AMBIGUOUS,List.of(1L,4L),a(5001,0,ValueRef.parameter(501,"input")));
        var p6=p(601,6,0,"input"); var f6=f(6,"heuristic",p6);
        var c60=c(60,6,"identity",Resolution.HEURISTIC,List.of(1L),a(6001,0,ValueRef.parameter(601,"input")));
        var p7=p(701,7,0,"input"); var f7=f(7,"multi",p7);
        var p10=p(1001,10,0,"x"); var f10=f(10,"d10",p10);
        var p11=p(1101,11,0,"x"); var f11=f(11,"d11",p11);
        var p12=p(1201,12,0,"x"); var f12=f(12,"d12",p12);
        var p13=p(1301,13,0,"x"); var f13=f(13,"d13",p13);
        var c100=c(100,10,"d11",Resolution.EXACT,List.of(11L),a(10001,0,ValueRef.parameter(1001,"x")));
        var c110=c(110,11,"d12",Resolution.EXACT,List.of(12L),a(11001,0,ValueRef.parameter(1101,"x")));
        var c120=c(120,12,"d13",Resolution.EXACT,List.of(13L),a(12001,0,ValueRef.parameter(1201,"x")));

        var g=new InMemoryProgramGraph("gate38",List.of(f1,f2,f3,f4,f5,f6,f7,f10,f11,f12,f13),List.of(),List.of(c50,c60,c100,c110,c120),
            List.of(r(10,1,ValueRef.parameter(101,"x")),r(20,2,ValueRef.constant("CONST")),r(30,3,ValueRef.unknown("opaque")),r(40,4,ValueRef.parameter(401,"x")),r(50,5,ValueRef.call(50,"m(input)")),r(60,6,ValueRef.call(60,"identity(input)")),r(70,7,ValueRef.parameter(701,"input")),r(71,7,ValueRef.parameter(701,"input")),r(100,10,ValueRef.call(100,"d11(x)")),r(110,11,ValueRef.call(110,"d12(x)")),r(120,12,ValueRef.call(120,"d13(x)")),r(130,13,ValueRef.parameter(1301,"x"))),List.of(),List.of(),List.of(),List.of());
        var engine=new PortableProvenanceEngine(g);
        var eb=new ProvenanceEvidenceBuilder(g,engine);
        var consumer=new DeterministicEvidenceConsumer();

        var exact=consumer.evaluate(eb.functionReturn(1));
        check("exact_value_specific_complete_becomes_hard_path",exact.provenance()==ProvenanceDisposition.HARD_PATH && exact.hardPathEligible(),exact);

        var amb=consumer.evaluate(eb.functionReturn(5));
        check("established_origin_ambiguous_path_not_hardened",amb.provenance()==ProvenanceDisposition.ESTABLISHED_ORIGIN_UNCERTAIN_PATH && !amb.hardPathEligible(),amb);

        var multi=consumer.evaluate(eb.functionReturn(7));
        check("multi_value_identity_not_hardened",multi.provenance()==ProvenanceDisposition.ESTABLISHED_ORIGIN_UNCERTAIN_PATH && !multi.hardPathEligible(),multi);

        var heur=consumer.evaluate(eb.functionReturn(6));
        check("possible_origin_stays_possible",heur.provenance()==ProvenanceDisposition.POSSIBLE_ORIGIN && !heur.hardPathEligible(),heur);

        var none=consumer.evaluate(eb.functionReturn(2));
        check("complete_no_origin_distinct_from_unknown",none.provenance()==ProvenanceDisposition.NO_ORIGIN,none);

        var unknown=consumer.evaluate(eb.functionReturn(3));
        check("not_established_is_not_no_origin",unknown.provenance()==ProvenanceDisposition.NOT_ESTABLISHED,unknown);

        var low=new ProvenanceEvidenceBuilder(g,new PortableProvenanceEngine(g,new AnalysisBudget(1000,2))).functionReturn(10);
        var partial=consumer.evaluate(low);
        check("truncation_is_partial_and_visible",partial.provenance()==ProvenanceDisposition.PARTIAL && partial.reasons().stream().anyMatch(x->x.startsWith("truncation:")),partial);

        var relOK=EvidenceRelation.established(RelationKind.ASSIGNMENT,"x","y",Resolution.EXACT,List.of(1L),"");
        var dRelOK=consumer.evaluate(eb.functionReturn(1),List.of(relOK),null);
        check("established_relation_consumed",dRelOK.relations()==RelationDisposition.ALL_ESTABLISHED,dRelOK);

        var relMaybe=EvidenceRelation.possible(RelationKind.CALL_RESOLUTION,"call","target",Resolution.AMBIGUOUS,List.of(1L,4L),"");
        var dRelMaybe=consumer.evaluate(eb.functionReturn(1),List.of(relMaybe),null);
        check("possible_relation_not_flattened",dRelMaybe.relations()==RelationDisposition.POSSIBLE_RELATION && !dRelMaybe.hardPathEligible(),dRelMaybe);

        var relAbstain=EvidenceRelation.abstain("x","?",Resolution.UNRESOLVED,AbstentionReason.COMPETING_DEFINITIONS,List.of(),"");
        var dRelAbstain=consumer.evaluate(eb.functionReturn(1),List.of(relAbstain),null);
        check("explicit_abstention_blocks_hard_projection",dRelAbstain.relations()==RelationDisposition.ABSTAINED_RELATION && !dRelAbstain.hardPathEligible(),dRelAbstain);

        var ctxFrames=List.of(new ContextFrame("parser","L0"),new ContextFrame("parser","L1"));
        var exactCtx=eb.functionReturn(1,ctxFrames);
        var guaranteed=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.GUARANTEED,true,2));
        check("guaranteed_effect_requires_matching_complete_context",guaranteed.effect()==EffectDisposition.GUARANTEED_FOR_CONTEXT && guaranteed.contextEffectGuaranteed(),guaranteed);

        var mismatch=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.GUARANTEED,true,1));
        check("context_stack_mismatch_cannot_claim_guarantee",mismatch.effect()==EffectDisposition.UNKNOWN_FOR_CONTEXT && !mismatch.contextEffectGuaranteed(),mismatch);

        var incomplete=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.GUARANTEED,false,2));
        check("incomplete_context_assessment_is_unknown",incomplete.effect()==EffectDisposition.UNKNOWN_FOR_CONTEXT,incomplete);

        var conditional=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.CONDITIONAL,true,2));
        check("conditional_effect_stays_conditional",conditional.effect()==EffectDisposition.CONDITIONAL_FOR_CONTEXT && !conditional.contextEffectGuaranteed(),conditional);

        var inadequate=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.INADEQUATE,true,2));
        check("inadequate_effect_stays_inadequate",inadequate.effect()==EffectDisposition.INADEQUATE_FOR_CONTEXT,inadequate);

        var unknownEff=consumer.evaluate(exactCtx,List.of(relOK),effect(Adequacy.UNKNOWN,true,2));
        check("unknown_effect_stays_unknown",unknownEff.effect()==EffectDisposition.UNKNOWN_FOR_CONTEXT,unknownEff);

        var unknownOriginButEffect=consumer.evaluate(new ProvenanceEvidence(eb.functionReturn(3).subject(),RelationKind.RETURN_PROVENANCE,IdentityPrecision.VALUE_SPECIFIC,OriginStatus.NOT_ESTABLISHED,Resolution.UNRESOLVED,AnalysisCompleteness.UNKNOWN,Set.of(),Set.of(),Set.of(),Set.of(),ctxFrames,List.of()),List.of(relOK),effect(Adequacy.GUARANTEED,true,2));
        check("effect_and_origin_are_independent_axes",unknownOriginButEffect.provenance()==ProvenanceDisposition.NOT_ESTABLISHED && unknownOriginButEffect.effect()==EffectDisposition.GUARANTEED_FOR_CONTEXT,unknownOriginButEffect);

        check("consumer_has_no_security_verdict",!exact.hasSecurityVerdict() && !guaranteed.hasSecurityVerdict(),exact);

        String consumerSurface=(DeterministicEvidenceConsumer.class.getName()+ProvenanceDisposition.class.getName()+EffectDisposition.class.getName()).toLowerCase(Locale.ROOT);
        check("consumer_is_language_and_framework_neutral",!consumerSurface.contains("php")&&!consumerSurface.contains("wordpress")&&!consumerSurface.contains("xss")&&!consumerSurface.contains("sql"),consumerSurface);

        check("not_established_never_maps_to_no_origin",unknown.provenance()!=ProvenanceDisposition.NO_ORIGIN,unknown);
        check("partial_never_maps_to_no_origin",partial.provenance()!=ProvenanceDisposition.NO_ORIGIN,partial);

        System.out.println("GATE38="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

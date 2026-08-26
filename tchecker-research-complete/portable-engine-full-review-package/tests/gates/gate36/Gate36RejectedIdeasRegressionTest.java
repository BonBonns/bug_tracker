import portable.graph.*;
import portable.provenance.*;
import portable.effects.*;
import portable.evidence.*;
import java.util.*;

/**
 * Gate 36: encode empirically rejected PHP-engine ideas as permanent portable-core regressions.
 * These are not speculative feature tests: each case protects against a failure mode already
 * measured in the legacy engine work.
 */
public final class Gate36RejectedIdeasRegressionTest {
    private static int pass=0,total=0;
    static void check(String n, boolean ok, Object got){total++; if(!ok) throw new AssertionError(n+" failed: "+got); pass++; System.out.println("PASS "+n+" -> "+got);}

    static ParameterFact p(long id,long f,int i,String n){return new ParameterFact(id,f,i,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate36.ts",1,5,false,List.of(ps),"any");}
    static ReturnFact r(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static ArgumentFact a(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,"ARG",v.code(),"","any",1,v);}
    static CallFact c(long id,long f,String n,Resolution res,List<Long> targets,ArgumentFact...args){return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"()","gate36.ts",1,targets,List.of(),res,List.of(args));}

    static boolean exact(ProvenanceSummary s, int... positions){
        Set<Integer> want=new TreeSet<>(); for(int x:positions) want.add(x);
        return s.resolution()==Resolution.EXACT && s.provenPositions().equals(want) && s.mayPositions().isEmpty() && !s.unknown() && s.completeness()==AnalysisCompleteness.COMPLETE;
    }
    static boolean abstains(List<EvidenceRelation> rs, AbstentionReason why){
        return rs.stream().anyMatch(x->x.kind()==RelationKind.ABSTENTION && x.abstentionReason()==why);
    }

    public static void main(String[] args){
        // ------------------------------------------------------------------
        // Rejected idea #1: "callee contains a source, therefore its return has that source".
        // The first parameter is deliberately irrelevant to the return.
        var p101=p(101,1,0,"guardInput");
        var p102=p(102,1,1,"returnedValue");
        var f1=f(1,"guardOnly",p101,p102);

        var p201=p(201,2,0,"source");
        var p202=p(202,2,1,"other");
        var f2=f(2,"caller",p201,p202);
        var c20=c(20,2,"guardOnly",Resolution.EXACT,List.of(1L),
            a(21,0,ValueRef.parameter(201,"source")),
            a(22,1,ValueRef.parameter(202,"other")));

        // A state-channel source exists in a function but is not returned. This protects the same
        // principle for out-of-band state: presence in the function is not return relevance.
        var f3=f(3,"statePresentButIrrelevant",p(301,3,0,"returnedValue"));
        var requestLoc=new StateChannelLocation(StateChannelKind.REQUEST,"request","body","name");
        var requestRead=new StateChannelReadFact(3001,3,requestLoc,StateChannelSourceMode.EXTERNAL_SOURCE,List.of(),Resolution.EXACT,2);

        // ------------------------------------------------------------------
        // Rejected idea #2: chase NO_DEFINING_ASSIGN as though every absence were a bug.
        // Direct call result requires no local defining assignment and should resolve semantically.
        var p401=p(401,4,0,"x"); var f4=f(4,"identity",p401);
        var p501=p(501,5,0,"input"); var f5=f(5,"directCallReturn",p501);
        var c50=c(50,5,"identity",Resolution.EXACT,List.of(4L),a(51,0,ValueRef.parameter(501,"input")));

        // A true local with no definition must remain UNKNOWN; do not invent a definition.
        var p601=p(601,6,0,"input"); var f6=f(6,"missingDefinition",p601);
        var l60=new LocalFact(6001,6,"x","any",2);

        // Competing definitions must abstain; do not pick whichever is convenient.
        var p701=p(701,7,0,"input"); var f7=f(7,"competingDefinitions",p701);
        var l70=new LocalFact(7001,7,"x","any",2);
        var d71=new AssignmentFact(7101,7,7001,ValueRef.parameter(701,"input"),2);
        var d72=new AssignmentFact(7102,7,7001,ValueRef.constant("CONST"),3);

        // Disconnected/opaque semantic value: a minimal fixture must not "resolve" simply because
        // the surrounding function has a parameter that looks source-like.
        var p801=p(801,8,0,"source"); var f8=f(8,"opaqueDisconnected",p801);

        var g=new InMemoryProgramGraph("gate36",
            List.of(f1,f2,f3,f4,f5,f6,f7,f8), List.of(),
            List.of(c20,c50),
            List.of(
                r(1001,1,ValueRef.parameter(102,"returnedValue")),
                r(2001,2,ValueRef.call(20,"guardOnly(source,other)")),
                r(3001,3,ValueRef.parameter(301,"returnedValue")),
                r(4001,4,ValueRef.parameter(401,"x")),
                r(5001,5,ValueRef.call(50,"identity(input)")),
                r(6001,6,ValueRef.local(6001,"x")),
                r(7001,7,ValueRef.local(7001,"x")),
                r(8001,8,ValueRef.unknown("opaque"))
            ),
            List.of(l60,l70), List.of(d71,d72),
            List.of(), List.of(), List.of(), List.of(requestRead));

        var engine=new PortableProvenanceEngine(g);

        var s1=engine.summarize(1);
        check("naive_callee_source_bridge_rejected_at_callee", exact(s1,1), s1);

        var s2=engine.summarize(2);
        check("naive_callee_source_bridge_rejected_at_caller", exact(s2,1), s2);
        check("guard_only_argument_never_attributed_to_return", !s2.provenPositions().contains(0) && !s2.mayPositions().contains(0), s2);

        var s3=engine.summarize(3);
        check("state_source_presence_without_return_relevance_is_ignored", exact(s3,0) && s3.provenOrigins().isEmpty() && s3.mayOrigins().isEmpty(), s3);

        var s5=engine.summarize(5);
        check("direct_call_result_needs_no_local_defining_assignment", exact(s5,0), s5);

        var s6=engine.summarize(6);
        check("no_defining_assignment_is_explicit_unknown", s6.resolution()==Resolution.UNRESOLVED && s6.unknown() && s6.completeness()==AnalysisCompleteness.UNKNOWN, s6);

        var s7=engine.summarize(7);
        // SUPERSEDED by CORE-S03 (JSTS-R04 oracle; legacy WP_GATE15_LOCAL_MAY).
        // Rejected idea stays rejected: no single-def pick, no proven positions,
        // never EXACT — now with the positive assertion that ALL defs survive
        // as MAY possibilities (a strictly stronger anti-guessing check).
        check("competing_definitions_never_guess",
            s7.resolution()==Resolution.AMBIGUOUS
                && s7.provenPositions().isEmpty()
                && s7.mayPositions().contains(0)
                && s7.resolution()!=Resolution.EXACT, s7);

        var s8=engine.summarize(8);
        check("disconnected_minimal_fixture_does_not_fabricate_origin", s8.resolution()==Resolution.UNRESOLVED && s8.unknown() && s8.provenPositions().isEmpty() && s8.mayPositions().isEmpty(), s8);

        // ------------------------------------------------------------------
        // Rejected idea #3: partial/pass-through wrapper promoted as globally adequate.
        var ctx=new EffectContext("generic-text","normalized");
        var req=new EffectRequirement(EffectClass.NORMALIZATION,ctx);
        var reg=new TransformationRegistry()
            .register(new TransformationRule("normalize",EffectClass.NORMALIZATION,ctx,Adequacy.GUARANTEED,"all paths modeled"));
        var eval=new StructureAwareTransformationEvaluator(reg);

        var transformed=EffectExpr.at(req, EffectExpr.apply("normalize",EffectExpr.source("v")));
        var raw=EffectExpr.at(req, EffectExpr.source("v"));
        var partial=EffectExpr.branch(transformed,raw);

        check("fully_transformed_wrapper_can_be_guaranteed", eval.assess(transformed).adequacy()==Adequacy.GUARANTEED, eval.assess(transformed));
        check("partial_pass_through_wrapper_never_guaranteed", eval.assess(partial).adequacy()==Adequacy.CONDITIONAL, eval.assess(partial));

        // ------------------------------------------------------------------
        // Evidence layer must make the abstentions machine-visible rather than generic fallback.
        var evidence=new RelationEvidenceBuilder(g);
        var e6=evidence.functionReturnRelations(6);
        var e7=evidence.functionReturnRelations(7);
        var e8=evidence.functionReturnRelations(8);
        check("missing_definition_has_machine_abstention", abstains(e6,AbstentionReason.MISSING_SEMANTIC_FACT), e6);
        check("competing_definition_has_machine_abstention", abstains(e7,AbstentionReason.COMPETING_DEFINITIONS), e7);
        check("opaque_value_has_machine_abstention", abstains(e8,AbstentionReason.MISSING_SEMANTIC_FACT), e8);

        // The rejected approaches are now discoverable by one stable gate, not only prose/history.
        check("rejected_ideas_gate_has_no_generic_fallback_kind",
            Arrays.stream(RelationKind.values()).noneMatch(k->k.name().contains("GENERIC")||k.name().contains("FALLBACK")),
            Arrays.toString(RelationKind.values()));

        System.out.println("GATE36="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

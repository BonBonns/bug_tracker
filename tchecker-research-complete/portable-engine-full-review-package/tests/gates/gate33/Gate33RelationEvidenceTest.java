import portable.graph.*;
import portable.evidence.*;
import java.util.*;

public class Gate33RelationEvidenceTest {
    static int pass=0,total=0;
    static void check(String n, boolean ok, Object got){total++; if(!ok) throw new AssertionError(n+" failed: "+got); pass++; System.out.println("PASS "+n+" -> "+got);}
    static ParameterFact p(long id,long f,int i,String n){return new ParameterFact(id,f,i,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate33.ts",1,2,false,List.of(ps),"any");}
    static ReturnFact r(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static ArgumentFact a(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,"ARG",v.code(),"","any",1,v);}
    static CallFact c(long id,long f,String n,Resolution res,List<Long> targets,ArgumentFact...args){return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"()","gate33.ts",1,targets,List.of(),res,List.of(args));}

    static boolean has(List<EvidenceRelation> rs, RelationKind k){return rs.stream().anyMatch(x->x.kind()==k);}
    static boolean abstains(List<EvidenceRelation> rs, AbstentionReason why){return rs.stream().anyMatch(x->x.kind()==RelationKind.ABSTENTION && x.abstentionReason()==why);}

    public static void main(String[] z){
        var p1=p(101,1,0,"x"); var f1=f(1,"identity",p1);
        var p2=p(201,2,0,"input"); var f2=f(2,"local",p2); var l20=new LocalFact(220,2,"y","any",1); var a20=new AssignmentFact(221,2,220,ValueRef.parameter(201,"input"),1);
        var p3=p(301,3,0,"input"); var f3=f(3,"competing",p3); var l30=new LocalFact(330,3,"y","any",1); var a31=new AssignmentFact(331,3,330,ValueRef.parameter(301,"input"),1); var a32=new AssignmentFact(332,3,330,ValueRef.constant("CONST"),2);
        var p4=p(401,4,0,"v"); var f4=f(4,"callee",p4);
        var p5=p(501,5,0,"input"); var f5=f(5,"caller",p5); var c50=c(550,5,"callee",Resolution.EXACT,List.of(4L),a(551,0,ValueRef.parameter(501,"input")));
        var p6=p(601,6,0,"input"); var f6=f(6,"ambCaller",p6); var p7=p(701,7,0,"v"); var f7=f(7,"calleeB",p7); var c60=c(660,6,"m",Resolution.AMBIGUOUS,List.of(4L,7L),a(661,0,ValueRef.parameter(601,"input")));
        var f8=f(8,"unresolvedCall"); var c80=c(880,8,"missing",Resolution.UNRESOLVED,List.of());
        var f9=f(9,"unknownReturn");
        var f10=f(10,"multiReturn",p(1001,10,0,"x"));
        var p11=p(1101,11,0,"source"); var f11=f(11,"persistWriter",p11); var f12=f(12,"persistReader");
        var loc=new PersistenceLocation("db","user:42","name");
        var wr=new PersistenceWriteFact(1110,11,loc,ValueRef.parameter(1101,"source"),1);
        var rdExact=new PersistenceReadFact(1210,12,loc,List.of(1110L),Resolution.EXACT,1);
        var f13=f(13,"persistUnknown"); var rdUnknown=new PersistenceReadFact(1310,13,loc,List.of(),Resolution.UNRESOLVED,1);
        var f14=f(14,"noReturn");

        var g=new InMemoryProgramGraph("gate33",
            List.of(f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14), List.of(),
            List.of(c50,c60,c80),
            List.of(
                r(10,1,ValueRef.parameter(101,"x")),
                r(20,2,ValueRef.local(220,"y")),
                r(30,3,ValueRef.local(330,"y")),
                r(40,4,ValueRef.parameter(401,"v")),
                r(50,5,ValueRef.call(550,"callee(input)")),
                r(60,6,ValueRef.call(660,"m(input)")),
                r(70,7,ValueRef.parameter(701,"v")),
                r(80,8,ValueRef.call(880,"missing()")),
                r(90,9,ValueRef.unknown("opaque")),
                r(100,10,ValueRef.parameter(1001,"x")), r(101,10,ValueRef.constant("CONST")),
                r(120,12,ValueRef.persistenceRead(1210,"db[user:42].name")),
                r(130,13,ValueRef.persistenceRead(1310,"db[user:42].name"))
            ), List.of(l20,l30), List.of(a20,a31,a32), List.of(wr), List.of(rdExact,rdUnknown));

        var b=new RelationEvidenceBuilder(g);

        var direct=b.functionReturnRelations(1);
        check("direct_return_has_return_relation",has(direct,RelationKind.RETURN_VALUE),direct);
        check("parameter_has_direct_value_relation",has(direct,RelationKind.DIRECT_VALUE),direct);
        check("no_generic_fallback_relation_exists",Arrays.stream(RelationKind.values()).noneMatch(x->x.name().contains("FALLBACK")||x.name().contains("GENERIC")),Arrays.toString(RelationKind.values()));

        var local=b.functionReturnRelations(2);
        check("unique_local_definition_is_assignment_relation",has(local,RelationKind.ASSIGNMENT) && !has(local,RelationKind.ABSTENTION),local);

        var competing=b.functionReturnRelations(3);
        check("competing_defs_explicitly_abstain",abstains(competing,AbstentionReason.COMPETING_DEFINITIONS),competing);

        var call=b.functionReturnRelations(5);
        check("exact_call_has_resolution_relation",call.stream().anyMatch(x->x.kind()==RelationKind.CALL_RESOLUTION && x.status()==RelationStatus.ESTABLISHED),call);
        check("exact_call_has_argument_parameter_relation",call.stream().anyMatch(x->x.kind()==RelationKind.ARGUMENT_PARAMETER && x.status()==RelationStatus.ESTABLISHED),call);

        var amb=b.functionReturnRelations(6);
        check("ambiguous_call_preserved_as_possible",amb.stream().anyMatch(x->x.kind()==RelationKind.CALL_RESOLUTION && x.status()==RelationStatus.POSSIBLE && x.resolution()==Resolution.AMBIGUOUS),amb);
        check("ambiguous_call_never_selects_one_return_identity",abstains(amb,AbstentionReason.AMBIGUOUS_CALL_TARGET),amb);

        var unr=b.functionReturnRelations(8);
        check("unresolved_call_explicitly_abstains",abstains(unr,AbstentionReason.UNRESOLVED_CALL_TARGET),unr);

        var unk=b.functionReturnRelations(9);
        check("unknown_value_explicitly_abstains",abstains(unk,AbstentionReason.MISSING_SEMANTIC_FACT),unk);

        var multi=b.functionReturnRelations(10);
        check("multiple_returns_explicitly_abstain",abstains(multi,AbstentionReason.MULTIPLE_RETURN_VALUES),multi);

        var pe=b.functionReturnRelations(12);
        check("persistence_is_first_class_relation",pe.stream().anyMatch(x->x.kind()==RelationKind.PERSISTENCE && x.status()==RelationStatus.ESTABLISHED),pe);

        var pu=b.functionReturnRelations(13);
        check("unresolved_persistence_explicitly_abstains",abstains(pu,AbstentionReason.UNRESOLVED_PERSISTENCE_WRITE),pu);

        var nr=b.functionReturnRelations(14);
        check("missing_return_fact_explicitly_abstains",abstains(nr,AbstentionReason.MISSING_SEMANTIC_FACT),nr);

        boolean invalidRejected=false;
        try { new EvidenceRelation(RelationKind.ASSIGNMENT,RelationStatus.ABSTAINED,"a","b",Resolution.UNRESOLVED,AbstentionReason.COMPETING_DEFINITIONS,List.of(),""); }
        catch(IllegalArgumentException e){invalidRejected=true;}
        check("abstention_cannot_hide_under_normal_relation_kind",invalidRejected,invalidRejected);

        boolean noReasonRejected=false;
        try { EvidenceRelation.abstain("a","b",Resolution.UNRESOLVED,AbstentionReason.NONE,List.of(),""); }
        catch(IllegalArgumentException e){noReasonRejected=true;}
        check("abstention_requires_machine_reason",noReasonRejected,noReasonRejected);

        check("taxonomy_contains_required_relation_families",
            EnumSet.allOf(RelationKind.class).containsAll(EnumSet.of(RelationKind.ASSIGNMENT,RelationKind.ARGUMENT_PARAMETER,RelationKind.RETURN_VALUE,RelationKind.PROPERTY_STATE,RelationKind.INDEX_STATE,RelationKind.PERSISTENCE,RelationKind.TRANSFORMATION,RelationKind.CONTROL_JOIN,RelationKind.CALL_RESOLUTION,RelationKind.ABSTENTION)),
            Arrays.toString(RelationKind.values()));

        System.out.println("GATE33="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

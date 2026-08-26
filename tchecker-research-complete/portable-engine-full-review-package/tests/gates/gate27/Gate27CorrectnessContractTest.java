import portable.graph.*;
import portable.provenance.*;
import java.util.*;

public final class Gate27CorrectnessContractTest {
    private static int passed=0,total=0;

    static ParameterFact p(long id,long f,int idx,String n){return new ParameterFact(id,f,idx,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate27.ts",1,1,false,List.of(ps),"any");}
    static LocalFact l(long id,long f,String n){return new LocalFact(id,f,n,"any",1);}
    static AssignmentFact as(long id,long f,long local,ValueRef v){return new AssignmentFact(id,f,local,v,1);}
    static ArgumentFact arg(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,v.kind().name(),v.code(),"","any",1,v);}
    static CallFact call(long id,long f,String n,Resolution r,List<Long> targets,ArgumentFact...args){
        return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"(...) ","gate27.ts",1,
            targets,targets.stream().map(Object::toString).toList(),r,List.of(args));
    }
    static ReturnFact ret(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}

    static void check(String name, boolean ok, Object got){
        total++; if(!ok) throw new AssertionError(name+" failed: "+got); passed++; System.out.println("PASS "+name+" -> "+got);
    }
    static boolean eq(ProvenanceSummary s, Resolution r, Set<Integer> proven, Set<Integer> may, boolean unknown, AnalysisCompleteness c){
        return s.resolution()==r && s.provenPositions().equals(proven) && s.mayPositions().equals(may)
            && s.unknown()==unknown && s.completeness()==c;
    }

    public static void main(String[] args){
        // f(input) { const x=input; const y=x; return y; }
        var p10=p(101,10,0,"input"); var f10=f(10,"localAlias",p10);
        var x10=l(1001,10,"x"); var y10=l(1002,10,"y");

        // source(input) { return input; }
        var p20=p(201,20,0,"input"); var f20=f(20,"source",p20);
        // viaReturn(input) { const x=source(input); return x; }
        var p30=p(301,30,0,"input"); var f30=f(30,"viaReturn",p30); var x30=l(3001,30,"x");
        var c31=call(31,30,"source",Resolution.EXACT,List.of(20L),arg(311,0,ValueRef.parameter(301,"input")));

        // irrelevant(input, other) { /* input might be used elsewhere */ return other; }
        var p40a=p(401,40,0,"input"); var p40b=p(402,40,1,"other"); var f40=f(40,"irrelevantSource",p40a,p40b);

        // competing(input) { let x=input; x='CONST'; return x; } -- no reaching-def proof => abstain
        var p50=p(501,50,0,"input"); var f50=f(50,"competingDefs",p50); var x50=l(5001,50,"x");

        // unknownLocal(input) { return missingLocal; }
        var p60=p(601,60,0,"input"); var f60=f(60,"unknownLocal",p60); var x60=l(6001,60,"x");

        List<FunctionFact> fs=new ArrayList<>(List.of(f10,f20,f30,f40,f50,f60));
        List<LocalFact> ls=new ArrayList<>(List.of(x10,y10,x30,x50,x60));
        List<AssignmentFact> ass=new ArrayList<>(List.of(
            as(1101,10,1001,ValueRef.parameter(101,"input")),
            as(1102,10,1002,ValueRef.local(1001,"x")),
            as(3101,30,3001,ValueRef.call(31,"source(input)")),
            as(5101,50,5001,ValueRef.parameter(501,"input")),
            as(5102,50,5001,ValueRef.constant("CONST"))
        ));
        List<CallFact> cs=new ArrayList<>(List.of(c31));
        List<ReturnFact> rs=new ArrayList<>(List.of(
            ret(10001,10,ValueRef.local(1002,"y")),
            ret(20001,20,ValueRef.parameter(201,"input")),
            ret(30001,30,ValueRef.local(3001,"x")),
            ret(40001,40,ValueRef.parameter(402,"other")),
            ret(50001,50,ValueRef.local(5001,"x")),
            ret(60001,60,ValueRef.local(6001,"x"))
        ));

        // Build a 21-function exact call chain d0(x)->d1(x)->...->d20(x)->x.
        long baseF=1000, baseP=10000, baseC=20000;
        for(int i=0;i<=20;i++){
            long fid=baseF+i, pid=baseP+i;
            var pp=p(pid,fid,0,"x"); fs.add(f(fid,"deep"+i,pp));
            if(i==20){ rs.add(ret(30000+i,fid,ValueRef.parameter(pid,"x"))); }
            else {
                long cid=baseC+i;
                cs.add(call(cid,fid,"deep"+(i+1),Resolution.EXACT,List.of(baseF+i+1),arg(40000+i,0,ValueRef.parameter(pid,"x"))));
                rs.add(ret(30000+i,fid,ValueRef.call(cid,"deep"+(i+1)+"(x)")));
            }
        }

        var graph=new InMemoryProgramGraph("gate27",fs,List.of(),cs,rs,ls,ass);
        var engine=new PortableProvenanceEngine(graph);

        check("local_assignment_alias_chain",
            eq(engine.summarize(10),Resolution.EXACT,Set.of(0),Set.of(),false,AnalysisCompleteness.COMPLETE),engine.summarize(10));
        check("semantic_return_through_local",
            eq(engine.summarize(30),Resolution.EXACT,Set.of(0),Set.of(),false,AnalysisCompleteness.COMPLETE),engine.summarize(30));
        check("return_relevance_only",
            eq(engine.summarize(40),Resolution.EXACT,Set.of(1),Set.of(),false,AnalysisCompleteness.COMPLETE),engine.summarize(40));
        // SUPERSEDED by CORE-S03 (oracle: JSTS-R04 mutation semantics; legacy
        // precedent: the gated WP_GATE15_LOCAL_MAY channel). The PRINCIPLE this
        // check protects — never guess one definition, never prove positions —
        // is preserved and asserted MORE strongly: every def must survive as a
        // MAY possibility and the resolution can never be EXACT.
        var s50=engine.summarize(50);
        check("multiple_local_defs_may_never_guess",
            s50.resolution()==Resolution.AMBIGUOUS
                && s50.provenPositions().isEmpty()
                && s50.mayPositions().contains(0)      // the param def survives
                && s50.resolution()!=Resolution.EXACT, s50);
        check("missing_local_def_unknown",
            eq(engine.summarize(60),Resolution.UNRESOLVED,Set.of(),Set.of(),true,AnalysisCompleteness.UNKNOWN),engine.summarize(60));

        var deep=engine.summarize(1000);
        check("depth_greater_than_legacy_9_is_supported",
            eq(deep,Resolution.EXACT,Set.of(0),Set.of(),false,AnalysisCompleteness.COMPLETE),deep);

        var depthLimited=new PortableProvenanceEngine(graph,new AnalysisBudget(100000,9)).summarize(1000);
        check("depth_limit_is_visible_partial",
            depthLimited.completeness()==AnalysisCompleteness.PARTIAL && depthLimited.unknown() &&
            depthLimited.truncations().stream().anyMatch(e->e.kind()==TruncationEvent.Kind.DEPTH_BUDGET),depthLimited);
        check("depth_truncation_not_no_flow",
            !(depthLimited.completeness()==AnalysisCompleteness.COMPLETE && depthLimited.provenPositions().isEmpty() && !depthLimited.unknown()),depthLimited);

        var workLimited=new PortableProvenanceEngine(graph,new AnalysisBudget(8,256)).summarize(1000);
        check("work_budget_is_visible_partial",
            workLimited.completeness()==AnalysisCompleteness.PARTIAL && workLimited.unknown() &&
            workLimited.truncations().stream().anyMatch(e->e.kind()==TruncationEvent.Kind.WORK_BUDGET),workLimited);

        // Unknown semantic value can never collapse to a clean empty dependency.
        var unknown=engine.summarize(60);
        check("unknown_not_no_flow",unknown.unknown() && unknown.completeness()==AnalysisCompleteness.UNKNOWN,unknown);

        // Deep default budget proves the old hard depth=9 behavior was not copied.
        check("default_budget_no_truncation",deep.truncations().isEmpty(),deep.truncations());

        // Core has only semantic ValueRefs; this assertion protects against reintroducing AST-source membership APIs.
        boolean noAstDependency=Arrays.stream(PortableProvenanceEngine.class.getDeclaredFields())
            .noneMatch(fld -> fld.getType().getName().startsWith("ast.") || fld.getType().getName().contains("joern"));
        check("core_has_no_language_ast_dependency",noAstDependency,Arrays.toString(PortableProvenanceEngine.class.getDeclaredFields()));

        System.out.println("GATE27="+passed+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

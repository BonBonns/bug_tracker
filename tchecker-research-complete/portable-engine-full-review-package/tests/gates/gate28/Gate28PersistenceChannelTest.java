import portable.graph.*;
import portable.provenance.*;
import java.util.*;

public final class Gate28PersistenceChannelTest {
    private static int passed=0,total=0;
    static ParameterFact p(long id,long f,int idx,String n){return new ParameterFact(id,f,idx,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate28.ts",1,1,false,List.of(ps),"any");}
    static ArgumentFact arg(long id,int idx,ValueRef v){return new ArgumentFact(id,idx,v.kind().name(),v.code(),"","any",1,v);}
    static CallFact call(long id,long f,String n,Resolution r,List<Long> targets,ArgumentFact...args){return new CallFact(id,f,n,n,"DYNAMIC_DISPATCH","any",n+"(...) ","gate28.ts",1,targets,targets.stream().map(Object::toString).toList(),r,List.of(args));}
    static ReturnFact ret(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static PersistenceWriteFact wr(long id,long f,PersistenceLocation loc,ValueRef v){return new PersistenceWriteFact(id,f,loc,v,1);}
    static PersistenceReadFact rd(long id,long f,PersistenceLocation loc,Resolution r,Long...writes){return new PersistenceReadFact(id,f,loc,List.of(writes),r,1);}
    static void check(String name,boolean ok,Object got){total++;if(!ok)throw new AssertionError(name+" failed: "+got);passed++;System.out.println("PASS "+name+" -> "+got);}
    static boolean hasPersisted(ProvenanceSummary s,long write,long writer,int pos,String loc,boolean proven){
        var o=OriginRef.persistedParameter(write,writer,pos,loc);
        return proven?s.provenOrigins().contains(o):s.mayOrigins().contains(o);
    }

    public static void main(String[] args){
        var userName=new PersistenceLocation("db","user:42","name");
        var userEmail=new PersistenceLocation("db","user:42","email");
        var otherName=new PersistenceLocation("db","user:99","name");

        // identity(x) -> x
        var p1=p(101,1,0,"x"); var f1=f(1,"identity",p1);
        // persist(source): WRITE user42.name <- source
        var p10=p(1001,10,0,"source"); var f10=f(10,"persist",p10);
        // persistConst(): WRITE user42.name <- CONST
        var f11=f(11,"persistConst");
        // persistEmail(source): WRITE user42.email <- source
        var p12=p(1201,12,0,"source"); var f12=f(12,"persistEmail",p12);
        // persistOther(source): WRITE user99.name <- source
        var p13=p(1301,13,0,"source"); var f13=f(13,"persistOther",p13);
        // persistViaHelper(source): WRITE user42.name <- identity(source)
        var p14=p(1401,14,0,"source"); var f14=f(14,"persistViaHelper",p14);
        var c140=call(140,14,"identity",Resolution.EXACT,List.of(1L),arg(14001,0,ValueRef.parameter(1401,"source")));

        // Readers are deliberately parameterless: provenance must cross the state channel.
        var f20=f(20,"loadExact");
        var f21=f(21,"loadConst");
        var f22=f(22,"loadAmbiguous");
        var f23=f(23,"loadUnresolved");
        var f24=f(24,"loadWrongSlot");
        var f25=f(25,"loadHeuristic");
        var f26=f(26,"loadViaHelperWrite");
        // wrapper() { return loadExact(); }
        var f30=f(30,"wrapper"); var c300=call(300,30,"loadExact",Resolution.EXACT,List.of(20L));
        // ordinary(param) { return param; } regression
        var p40=p(4001,40,0,"ordinary"); var f40=f(40,"ordinary",p40);

        List<FunctionFact> fs=List.of(f1,f10,f11,f12,f13,f14,f20,f21,f22,f23,f24,f25,f26,f30,f40);
        List<CallFact> cs=List.of(c140,c300);
        List<ReturnFact> rs=List.of(
            ret(100,1,ValueRef.parameter(101,"x")),
            ret(200,20,ValueRef.persistenceRead(2000,"db[user42].name")),
            ret(210,21,ValueRef.persistenceRead(2100,"db[user42].name")),
            ret(220,22,ValueRef.persistenceRead(2200,"db[user42].name")),
            ret(230,23,ValueRef.persistenceRead(2300,"db[user42].name")),
            ret(240,24,ValueRef.persistenceRead(2400,"db[user42].name")),
            ret(250,25,ValueRef.persistenceRead(2500,"db[user42].name")),
            ret(260,26,ValueRef.persistenceRead(2600,"db[user42].name")),
            ret(3000,30,ValueRef.call(300,"loadExact()")),
            ret(4000,40,ValueRef.parameter(4001,"ordinary"))
        );
        List<PersistenceWriteFact> writes=List.of(
            wr(10000,10,userName,ValueRef.parameter(1001,"source")),
            wr(11000,11,userName,ValueRef.constant("CONST")),
            wr(12000,12,userEmail,ValueRef.parameter(1201,"source")),
            wr(13000,13,otherName,ValueRef.parameter(1301,"source")),
            wr(14000,14,userName,ValueRef.call(140,"identity(source)"))
        );
        List<PersistenceReadFact> reads=List.of(
            rd(2000,20,userName,Resolution.EXACT,10000L),
            rd(2100,21,userName,Resolution.EXACT,11000L),
            rd(2200,22,userName,Resolution.AMBIGUOUS,10000L,11000L),
            rd(2300,23,userName,Resolution.UNRESOLVED),
            // Deliberately claims an email write for a name read: core rejects the mismatched location.
            rd(2400,24,userName,Resolution.EXACT,12000L),
            rd(2500,25,userName,Resolution.HEURISTIC,10000L),
            rd(2600,26,userName,Resolution.EXACT,14000L)
        );
        var g=new InMemoryProgramGraph("gate28",fs,List.of(),cs,rs,List.of(),List.of(),writes,reads);
        var e=new PortableProvenanceEngine(g);

        var exact=e.summarize(20);
        check("cross_function_persistence_origin", exact.provenPositions().isEmpty() && hasPersisted(exact,10000,10,0,userName.stableKey(),true) && exact.completeness()==AnalysisCompleteness.COMPLETE,exact);

        var wrapped=e.summarize(30);
        check("persistence_origin_survives_return_wrapper",hasPersisted(wrapped,10000,10,0,userName.stableKey(),true) && wrapped.provenPositions().isEmpty(),wrapped);

        var constant=e.summarize(21);
        check("constant_persistence_write_has_no_source",constant.provenOrigins().isEmpty() && constant.mayOrigins().isEmpty() && !constant.unknown() && constant.completeness()==AnalysisCompleteness.COMPLETE,constant);

        var amb=e.summarize(22);
        check("ambiguous_write_source_vs_constant_is_may",amb.resolution()==Resolution.AMBIGUOUS && amb.provenOrigins().isEmpty() && hasPersisted(amb,10000,10,0,userName.stableKey(),false),amb);
        check("ambiguous_persistence_never_hardens",amb.provenPositions().isEmpty() && amb.provenOrigins().isEmpty(),amb);

        var unresolved=e.summarize(23);
        check("unresolved_persistence_is_unknown",unresolved.unknown() && unresolved.completeness()==AnalysisCompleteness.UNKNOWN && unresolved.provenOrigins().isEmpty(),unresolved);

        var wrong=e.summarize(24);
        check("location_mismatch_abstains",wrong.unknown() && wrong.completeness()==AnalysisCompleteness.UNKNOWN && wrong.provenOrigins().isEmpty(),wrong);

        var heuristic=e.summarize(25);
        check("heuristic_persistence_is_may_only",heuristic.resolution()==Resolution.HEURISTIC && heuristic.provenOrigins().isEmpty() && hasPersisted(heuristic,10000,10,0,userName.stableKey(),false),heuristic);

        var viaHelper=e.summarize(26);
        check("persistence_write_value_uses_semantic_call_summary",hasPersisted(viaHelper,14000,14,0,userName.stableKey(),true),viaHelper);

        var ordinary=e.summarize(40);
        check("ordinary_parameter_provenance_unchanged",ordinary.provenPositions().equals(Set.of(0)) && ordinary.provenOrigins().isEmpty() && ordinary.resolution()==Resolution.EXACT,ordinary);

        check("persistence_location_is_receiver_and_slot_sensitive",!userName.equals(otherName) && !userName.equals(userEmail),List.of(userName,userEmail,otherName));
        boolean noAst=Arrays.stream(PortableProvenanceEngine.class.getDeclaredFields()).noneMatch(x->x.getType().getName().startsWith("ast.")||x.getType().getName().contains("joern"));
        check("portable_core_still_has_no_ast_dependency",noAst,Arrays.toString(PortableProvenanceEngine.class.getDeclaredFields()));

        System.out.println("GATE28="+passed+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

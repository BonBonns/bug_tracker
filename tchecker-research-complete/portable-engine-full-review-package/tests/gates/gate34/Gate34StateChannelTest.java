import portable.graph.*;
import portable.provenance.*;
import portable.evidence.*;
import java.util.*;

public final class Gate34StateChannelTest {
    private static int passed=0,total=0;
    static ParameterFact p(long id,long f,int idx,String n){return new ParameterFact(id,f,idx,n,n,"any",1);}
    static FunctionFact f(long id,String n,ParameterFact...ps){return new FunctionFact(id,n,n,"","gate34.ts",1,1,false,List.of(ps),"any");}
    static ReturnFact ret(long id,long f,ValueRef v){return new ReturnFact(id,f,v,1);}
    static StateChannelWriteFact wr(long id,long f,StateChannelLocation loc,ValueRef v){return new StateChannelWriteFact(id,f,loc,v,1);}
    static StateChannelReadFact rd(long id,long f,StateChannelLocation loc,StateChannelSourceMode mode,Resolution r,Long...writes){return new StateChannelReadFact(id,f,loc,mode,List.of(writes),r,1);}
    static void check(String name,boolean ok,Object got){total++;if(!ok)throw new AssertionError(name+" failed: "+got);passed++;System.out.println("PASS "+name+" -> "+got);}
    static boolean hasExternal(ProvenanceSummary s,long read,String loc,boolean proven){
        var o=OriginRef.stateChannelExternal(read,loc); return proven?s.provenOrigins().contains(o):s.mayOrigins().contains(o);
    }
    static boolean hasChannelParam(ProvenanceSummary s,long write,long writer,int pos,String loc,boolean proven){
        var o=OriginRef.stateChannelParameter(write,writer,pos,loc); return proven?s.provenOrigins().contains(o):s.mayOrigins().contains(o);
    }

    public static void main(String[] args){
        var reqName=new StateChannelLocation(StateChannelKind.REQUEST,"http","request","body.name");
        var reqOther=new StateChannelLocation(StateChannelKind.REQUEST,"http","request","body.other");
        var sessionCart=new StateChannelLocation(StateChannelKind.SESSION,"app","session:user42","cart");
        var sessionOther=new StateChannelLocation(StateChannelKind.SESSION,"app","session:user99","cart");
        var envHome=new StateChannelLocation(StateChannelKind.ENVIRONMENT,"process","env","HOME");
        var procCache=new StateChannelLocation(StateChannelKind.PROCESS,"runtime","singleton","cache.value");

        // writers for linked state channels
        var ps=p(1001,10,0,"source"); var fw=f(10,"writeSession",ps);
        var fc=f(11,"writeSessionConst");
        var pp=p(1201,12,0,"source"); var fp=f(12,"writeProcess",pp);

        // parameterless readers prove origin crosses an out-of-band channel
        var f20=f(20,"requestRead");
        var f21=f(21,"environmentRead");
        var f22=f(22,"sessionLinkedExact");
        var f23=f(23,"sessionLinkedAmbiguous");
        var f24=f(24,"sessionUnmodeled");
        var f25=f(25,"sessionWrongLocation");
        var f26=f(26,"requestHeuristic");
        var f27=f(27,"processLinked");
        var f28=f(28,"requestDifferentSlot");

        // Return relevance control: req is read in one function, but another function returns only its parameter.
        var px=p(3001,30,0,"x"); var f30=f(30,"returnOnlyX",px);

        List<FunctionFact> fs=List.of(fw,fc,fp,f20,f21,f22,f23,f24,f25,f26,f27,f28,f30);
        List<ReturnFact> returns=List.of(
            ret(200,20,ValueRef.stateChannelRead(2000,"req.body.name")),
            ret(210,21,ValueRef.stateChannelRead(2100,"env.HOME")),
            ret(220,22,ValueRef.stateChannelRead(2200,"session.cart")),
            ret(230,23,ValueRef.stateChannelRead(2300,"session.cart")),
            ret(240,24,ValueRef.stateChannelRead(2400,"session.cart")),
            ret(250,25,ValueRef.stateChannelRead(2500,"session.cart")),
            ret(260,26,ValueRef.stateChannelRead(2600,"req.body.name")),
            ret(270,27,ValueRef.stateChannelRead(2700,"process.cache")),
            ret(280,28,ValueRef.stateChannelRead(2800,"req.body.other")),
            ret(300,30,ValueRef.parameter(3001,"x"))
        );
        List<StateChannelWriteFact> writes=List.of(
            wr(10000,10,sessionCart,ValueRef.parameter(1001,"source")),
            wr(11000,11,sessionCart,ValueRef.constant("CONST")),
            wr(12000,12,procCache,ValueRef.parameter(1201,"source")),
            wr(13000,10,sessionOther,ValueRef.parameter(1001,"source"))
        );
        List<StateChannelReadFact> reads=List.of(
            rd(2000,20,reqName,StateChannelSourceMode.EXTERNAL_SOURCE,Resolution.EXACT),
            rd(2100,21,envHome,StateChannelSourceMode.EXTERNAL_SOURCE,Resolution.EXACT),
            rd(2200,22,sessionCart,StateChannelSourceMode.WRITE_LINKED,Resolution.EXACT,10000L),
            rd(2300,23,sessionCart,StateChannelSourceMode.WRITE_LINKED,Resolution.AMBIGUOUS,10000L,11000L),
            rd(2400,24,sessionCart,StateChannelSourceMode.UNMODELED,Resolution.UNRESOLVED),
            rd(2500,25,sessionCart,StateChannelSourceMode.WRITE_LINKED,Resolution.EXACT,13000L),
            rd(2600,26,reqName,StateChannelSourceMode.EXTERNAL_SOURCE,Resolution.HEURISTIC),
            rd(2700,27,procCache,StateChannelSourceMode.WRITE_LINKED,Resolution.EXACT,12000L),
            rd(2800,28,reqOther,StateChannelSourceMode.EXTERNAL_SOURCE,Resolution.EXACT)
        );
        var g=new InMemoryProgramGraph("gate34",fs,List.of(),List.of(),returns,List.of(),List.of(),List.of(),List.of(),writes,reads);
        var e=new PortableProvenanceEngine(g);

        var request=e.summarize(20);
        check("request_channel_is_explicit_external_origin",hasExternal(request,2000,reqName.stableKey(),true)&&request.provenPositions().isEmpty()&&request.completeness()==AnalysisCompleteness.COMPLETE,request);

        var env=e.summarize(21);
        check("environment_channel_is_explicit_external_origin",hasExternal(env,2100,envHome.stableKey(),true)&&env.provenPositions().isEmpty(),env);

        var session=e.summarize(22);
        check("session_linked_write_preserves_writer_parameter",hasChannelParam(session,10000,10,0,sessionCart.stableKey(),true)&&session.provenPositions().isEmpty(),session);

        var amb=e.summarize(23);
        check("session_source_vs_constant_write_is_ambiguous",amb.resolution()==Resolution.AMBIGUOUS&&amb.provenOrigins().isEmpty()&&hasChannelParam(amb,10000,10,0,sessionCart.stableKey(),false),amb);
        check("ambiguous_state_channel_never_hardens",amb.provenOrigins().isEmpty()&&amb.provenPositions().isEmpty(),amb);

        var unmodeled=e.summarize(24);
        check("unmodeled_session_channel_is_not_established",unmodeled.unknown()&&unmodeled.completeness()==AnalysisCompleteness.UNKNOWN&&unmodeled.provenOrigins().isEmpty(),unmodeled);

        var wrong=e.summarize(25);
        check("state_channel_location_mismatch_abstains",wrong.unknown()&&wrong.provenOrigins().isEmpty()&&wrong.completeness()==AnalysisCompleteness.UNKNOWN,wrong);

        var heur=e.summarize(26);
        check("heuristic_external_channel_is_may_only",heur.resolution()==Resolution.HEURISTIC&&heur.provenOrigins().isEmpty()&&hasExternal(heur,2600,reqName.stableKey(),false),heur);

        var process=e.summarize(27);
        check("process_state_can_be_write_linked",hasChannelParam(process,12000,12,0,procCache.stableKey(),true),process);

        var other=e.summarize(28);
        check("state_channel_slots_remain_distinct",hasExternal(other,2800,reqOther.stableKey(),true)&&!other.provenOrigins().contains(OriginRef.stateChannelExternal(2000,reqName.stableKey())),other);

        var onlyX=e.summarize(30);
        check("ordinary_return_relevance_unchanged",onlyX.provenPositions().equals(Set.of(0))&&onlyX.provenOrigins().isEmpty(),onlyX);


        var rb=new RelationEvidenceBuilder(g);
        var reqRelations=rb.functionReturnRelations(20);
        check("state_channel_is_first_class_evidence_relation",reqRelations.stream().anyMatch(x->x.kind()==RelationKind.STATE_CHANNEL && x.status()==RelationStatus.ESTABLISHED),reqRelations);
        var unknownRelations=rb.functionReturnRelations(24);
        check("unmodeled_state_channel_explicitly_abstains",unknownRelations.stream().anyMatch(x->x.kind()==RelationKind.ABSTENTION && x.abstentionReason()==AbstentionReason.UNMODELED_STATE_CHANNEL),unknownRelations);

        check("state_channel_and_persistence_are_distinct_types",!StateChannelLocation.class.getName().equals(PersistenceLocation.class.getName()),List.of(StateChannelLocation.class,PersistenceLocation.class));
        boolean noAst=Arrays.stream(PortableProvenanceEngine.class.getDeclaredFields()).noneMatch(x->x.getType().getName().startsWith("ast.")||x.getType().getName().contains("joern"));
        check("portable_core_still_has_no_ast_dependency",noAst,Arrays.toString(PortableProvenanceEngine.class.getDeclaredFields()));

        System.out.println("GATE34="+passed+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

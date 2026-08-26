import portable.graph.*;
import portable.provenance.*;
import java.util.*;

public final class Gate26PortableProvenanceTest {
    private static int passed = 0;
    private static int total = 0;

    static ParameterFact p(long id, long f, int idx, String name) {
        return new ParameterFact(id, f, idx, name, name, "any", 1);
    }
    static FunctionFact f(long id, String name, ParameterFact... ps) {
        return new FunctionFact(id, name, name, "", "gate26.ts", 1, 1, false, List.of(ps), "any");
    }
    static ArgumentFact arg(long id, int idx, ValueRef v) {
        return new ArgumentFact(id, idx, v.kind().name(), v.code(), "", "any", 1, v);
    }
    static CallFact call(long id, long enclosing, String name, Resolution r, List<Long> targets, ArgumentFact... args) {
        return new CallFact(id, enclosing, name, name, "DYNAMIC_DISPATCH", "any", name+"(...)", "gate26.ts", 1,
            targets, targets.stream().map(Object::toString).toList(), r, List.of(args));
    }
    static ReturnFact ret(long id, long f, ValueRef v) { return new ReturnFact(id, f, v, 1); }

    static void check(String name, boolean ok, Object got) {
        total++;
        if (!ok) throw new AssertionError(name + " failed: " + got);
        passed++;
        System.out.println("PASS " + name + " -> " + got);
    }
    static boolean eq(ProvenanceSummary s, Resolution r, Set<Integer> proven, Set<Integer> may, boolean unknown) {
        return s.resolution()==r && s.provenPositions().equals(proven) && s.mayPositions().equals(may) && s.unknown()==unknown;
    }

    public static void main(String[] args) {
        // 10 identity(x) => x
        var p10 = p(101,10,0,"x");
        var f10 = f(10,"identity",p10);

        // 20 constant(x) => "CONST"
        var p20 = p(201,20,0,"x");
        var f20 = f(20,"constant",p20);

        // 30 middle(x) => identity(x)
        var p30 = p(301,30,0,"x");
        var f30 = f(30,"middle",p30);
        var c31 = call(31,30,"identity",Resolution.EXACT,List.of(10L),arg(311,0,ValueRef.parameter(301,"x")));

        // 40 top(a,b) => middle(b)
        var p40a=p(401,40,0,"a"); var p40b=p(402,40,1,"b");
        var f40=f(40,"top",p40a,p40b);
        var c41=call(41,40,"middle",Resolution.EXACT,List.of(30L),arg(411,0,ValueRef.parameter(402,"b")));

        // 50 constantize(source) => constant(source)
        var p50=p(501,50,0,"source"); var f50=f(50,"constantize",p50);
        var c51=call(51,50,"constant",Resolution.EXACT,List.of(20L),arg(511,0,ValueRef.parameter(501,"source")));

        // 60 passthrough(x) => x ; 70 diverge(x) => CONST
        var p60=p(601,60,0,"x"); var f60=f(60,"pass",p60);
        var p70=p(701,70,0,"x"); var f70=f(70,"drop",p70);

        // 80 ambiguousDivergent(x): target pass or drop
        var p80=p(801,80,0,"x"); var f80=f(80,"ambiguousDivergent",p80);
        var c81=call(81,80,"process",Resolution.AMBIGUOUS,List.of(60L,70L),arg(811,0,ValueRef.parameter(801,"x")));

        // 90 ambiguousShared(x): two passing implementations
        var p90=p(901,90,0,"x"); var f90=f(90,"ambiguousShared",p90);
        var c91=call(91,90,"process",Resolution.AMBIGUOUS,List.of(10L,60L),arg(911,0,ValueRef.parameter(901,"x")));

        // 100 unresolved(x)
        var p100=p(1001,100,0,"x"); var f100=f(100,"unresolved",p100);
        var c101=call(101,100,"missing",Resolution.UNRESOLVED,List.of(),arg(1011,0,ValueRef.parameter(1001,"x")));

        // 110 heuristic(x): guessed pass target
        var p110=p(1101,110,0,"x"); var f110=f(110,"heuristic",p110);
        var c111=call(111,110,"maybe",Resolution.HEURISTIC,List.of(60L),arg(1111,0,ValueRef.parameter(1101,"x")));

        // 120 wrapAmbiguous(x) => ambiguousDivergent(x)
        var p120=p(1201,120,0,"x"); var f120=f(120,"wrapAmbiguous",p120);
        var c121=call(121,120,"ambiguousDivergent",Resolution.EXACT,List.of(80L),arg(1211,0,ValueRef.parameter(1201,"x")));

        List<FunctionFact> fs=List.of(f10,f20,f30,f40,f50,f60,f70,f80,f90,f100,f110,f120);
        List<CallFact> cs=List.of(c31,c41,c51,c81,c91,c101,c111,c121);
        List<ReturnFact> rs=List.of(
            ret(10001,10,ValueRef.parameter(101,"x")),
            ret(20001,20,ValueRef.constant("CONST")),
            ret(30001,30,ValueRef.call(31,"identity(x)")),
            ret(40001,40,ValueRef.call(41,"middle(b)")),
            ret(50001,50,ValueRef.call(51,"constant(source)")),
            ret(60001,60,ValueRef.parameter(601,"x")),
            ret(70001,70,ValueRef.constant("CONST")),
            ret(80001,80,ValueRef.call(81,"obj.process(x)")),
            ret(90001,90,ValueRef.call(91,"obj.process(x)")),
            ret(100001,100,ValueRef.call(101,"missing(x)")),
            ret(110001,110,ValueRef.call(111,"maybe(x)")),
            ret(120001,120,ValueRef.call(121,"ambiguousDivergent(x)"))
        );

        var engine = new PortableProvenanceEngine(new InMemoryProgramGraph("gate26", fs, List.of(), cs, rs));

        check("identity", eq(engine.summarize(10),Resolution.EXACT,Set.of(0),Set.of(),false), engine.summarize(10));
        check("constant", eq(engine.summarize(20),Resolution.EXACT,Set.of(),Set.of(),false), engine.summarize(20));
        check("argument_parameter_return", eq(engine.summarize(30),Resolution.EXACT,Set.of(0),Set.of(),false), engine.summarize(30));
        check("two_hop_argument_mapping", eq(engine.summarize(40),Resolution.EXACT,Set.of(1),Set.of(),false), engine.summarize(40));
        check("callee_drops_argument", eq(engine.summarize(50),Resolution.EXACT,Set.of(),Set.of(),false), engine.summarize(50));
        check("ambiguous_divergent", eq(engine.summarize(80),Resolution.AMBIGUOUS,Set.of(),Set.of(0),false), engine.summarize(80));
        check("ambiguous_shared_dependency", eq(engine.summarize(90),Resolution.AMBIGUOUS,Set.of(0),Set.of(),false), engine.summarize(90));
        check("unresolved_stays_unknown", eq(engine.summarize(100),Resolution.UNRESOLVED,Set.of(),Set.of(),true), engine.summarize(100));
        check("heuristic_never_hardens", eq(engine.summarize(110),Resolution.HEURISTIC,Set.of(),Set.of(0),false), engine.summarize(110));
        check("weakest_resolution_survives_wrapper", eq(engine.summarize(120),Resolution.AMBIGUOUS,Set.of(),Set.of(0),false), engine.summarize(120));

        System.out.println("GATE26="+passed+"/"+total);
    }
}

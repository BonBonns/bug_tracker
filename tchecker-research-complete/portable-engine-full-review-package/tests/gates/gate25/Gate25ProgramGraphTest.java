import portable.graph.*;
import java.util.*;

public class Gate25ProgramGraphTest {
    static void check(boolean x, String msg) { if (!x) throw new AssertionError(msg); }

    public static void main(String[] args) {
        FunctionFact a = new FunctionFact(10,"process","A.process","(string):string","fixture.ts",1,3,false,
            List.of(new ParameterFact(11,10,1,"x","x","string",1)),"string");
        FunctionFact b = new FunctionFact(20,"process","B.process","(string):string","fixture.ts",5,7,false,
            List.of(new ParameterFact(21,20,1,"x","x","string",5)),"string");
        FunctionFact exactFn = new FunctionFact(30,"exact","exact","(A,string):string","fixture.ts",9,11,false,List.of(),"string");
        FunctionFact ambFn = new FunctionFact(40,"amb","amb","(A|B,string):string","fixture.ts",13,15,false,List.of(),"string");
        FunctionFact unknownFn = new FunctionFact(50,"unknown","unknown","(any,string):string","fixture.ts",17,19,false,List.of(),"string");

        CallFact exact = new CallFact(31,30,"process","A.process","DYNAMIC_DISPATCH","string","obj.process(x)","fixture.ts",10,
            List.of(10L),List.of("A.process"),Resolution.EXACT,List.of());
        CallFact ambiguous = new CallFact(41,40,"process","","DYNAMIC_DISPATCH","string","obj.process(x)","fixture.ts",14,
            List.of(10L,20L),List.of("A.process","B.process"),Resolution.AMBIGUOUS,List.of());
        CallFact unresolved = new CallFact(51,50,"process","","DYNAMIC_DISPATCH","ANY","obj.process(x)","fixture.ts",18,
            List.of(),List.of(),Resolution.UNRESOLVED,List.of());

        ProgramGraph g = new InMemoryProgramGraph("synthetic-gate25", List.of(a,b,exactFn,ambFn,unknownFn), List.of(), List.of(exact,ambiguous,unresolved));
        check(g.demonstratedTargets(exact).size()==1, "exact target");
        check(g.demonstratedTargets(ambiguous).size()==2, "ambiguous targets");
        check(g.demonstratedTargets(unresolved).isEmpty(), "unresolved targets");
        check(Resolution.weakest(Resolution.EXACT, Resolution.AMBIGUOUS)==Resolution.AMBIGUOUS, "weakest ambiguity");
        check(Resolution.weakest(Resolution.HEURISTIC, Resolution.UNRESOLVED)==Resolution.UNRESOLVED, "weakest unresolved");

        boolean rejected=false;
        try {
            new CallFact(99,30,"bad","","","","","",1,List.of(10L,20L),List.of(),Resolution.EXACT,List.of());
        } catch (IllegalArgumentException expected) { rejected=true; }
        check(rejected, "invalid EXACT must fail closed");
        System.out.println("GATE25=6/6");
    }
}

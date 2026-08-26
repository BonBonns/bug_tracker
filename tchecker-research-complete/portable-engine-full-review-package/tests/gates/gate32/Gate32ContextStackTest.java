import portable.effects.*;
import java.util.*;

public class Gate32ContextStackTest {
    static int pass=0,total=0;
    static void check(String name, boolean ok, Object got) {
        total++;
        if(!ok) throw new AssertionError(name+" failed: "+got);
        pass++;
        System.out.println("PASS "+name+" -> "+got);
    }

    public static void main(String[] args) {
        var parseA = new EffectContext("parser", "A");
        var parseB = new EffectContext("parser", "B");
        var render = new EffectContext("presentation", "render");
        var reqA = new EffectRequirement(EffectClass.ENCODING, parseA);
        var reqB = new EffectRequirement(EffectClass.ENCODING, parseB);
        var reqR = new EffectRequirement(EffectClass.ENCODING, render);

        var reg = new TransformationRegistry()
            .register(new TransformationRule("encA", EffectClass.ENCODING, parseA, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encB", EffectClass.ENCODING, parseB, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encR", EffectClass.ENCODING, render, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encA", EffectClass.ENCODING, parseB, Adequacy.INADEQUATE, ""))
            .register(new TransformationRule("encA", EffectClass.ENCODING, render, Adequacy.INADEQUATE, ""))
            .register(new TransformationRule("maybeB", EffectClass.ENCODING, parseB, Adequacy.CONDITIONAL, "only some values"));

        var eval = new ContextStackEvaluator(reg);

        var stack2 = ContextStack.of(reqA, reqB);
        var good2 = eval.assess(stack2, List.of(List.of("encA"), List.of("encB")));
        check("two_parser_layers_each_satisfied", good2.guaranteed() && good2.layers().size()==2, good2);

        var reused = eval.assess(stack2, List.of(List.of("encA"), List.of()));
        check("inner_transform_not_reused_for_outer_layer", reused.adequacy()==Adequacy.INADEQUATE, reused);

        var wrongOuter = eval.assess(stack2, List.of(List.of("encA"), List.of("encA")));
        check("wrong_layer_transform_rejected", wrongOuter.adequacy()==Adequacy.INADEQUATE, wrongOuter);

        var missingSecondSegment = eval.assess(stack2, List.of(List.of("encA")));
        check("missing_declared_layer_is_incomplete", !missingSecondSegment.complete() && missingSecondSegment.adequacy()==Adequacy.UNKNOWN, missingSecondSegment);

        var extraSegment = eval.assess(stack2, List.of(List.of("encA"), List.of("encB"), List.of("encR")));
        check("extra_observed_segment_is_incomplete", !extraSegment.complete() && extraSegment.adequacy()==Adequacy.UNKNOWN, extraSegment);

        var conditional = eval.assess(stack2, List.of(List.of("encA"), List.of("maybeB")));
        check("conditional_layer_caps_stack", conditional.adequacy()==Adequacy.CONDITIONAL, conditional);

        var stack3 = ContextStack.of(reqA, reqB, reqR);
        var good3 = eval.assess(stack3, List.of(List.of("encA"), List.of("encB"), List.of("encR")));
        check("three_layer_stack_guaranteed", good3.guaranteed(), good3);

        var missingMiddle = eval.assess(stack3, List.of(List.of("encA"), List.of(), List.of("encR")));
        check("middle_parser_layer_cannot_be_skipped", missingMiddle.adequacy()==Adequacy.INADEQUATE, missingMiddle);

        // The existing structured expression evaluator must agree on the same nested ordering.
        var exprEval = new StructureAwareTransformationEvaluator(reg);
        var src = EffectExpr.source("value");
        var nested = EffectExpr.at(reqR,
                EffectExpr.apply("encR",
                    EffectExpr.at(reqB,
                        EffectExpr.apply("encB",
                            EffectExpr.at(reqA, EffectExpr.apply("encA", src))))));
        var nestedResult = exprEval.assess(nested);
        check("explicit_stack_agrees_with_structural_expression", nestedResult.adequacy()==good3.adequacy(), nestedResult);

        // A flattening algorithm would see all required transformer names in this path and could
        // wrongly declare success.  The stack evaluator must retain segment ownership.
        var flattenTrap = eval.assess(stack3, List.of(List.of("encA","encB","encR"), List.of(), List.of()));
        check("flattened_membership_cannot_satisfy_future_layers", flattenTrap.adequacy()==Adequacy.INADEQUATE, flattenTrap);

        check("stack_order_is_preserved", stack3.layers().equals(List.of(reqA,reqB,reqR)), stack3.layers());
        check("empty_stack_does_not_claim_guarantee", eval.assess(ContextStack.of(), List.of()).adequacy()==Adequacy.UNKNOWN, eval.assess(ContextStack.of(), List.of()));

        String surface=(ContextStack.class.getName()+ContextStackEvaluator.class.getName()+good3).toLowerCase(Locale.ROOT);
        check("context_stack_is_language_and_profile_neutral", !surface.contains("wordpress") && !surface.contains("php") && !surface.contains("xss") && !surface.contains("sql"), surface);

        System.out.println("GATE32="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

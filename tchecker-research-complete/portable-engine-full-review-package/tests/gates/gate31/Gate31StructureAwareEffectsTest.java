import portable.effects.*;
import java.util.*;

public class Gate31StructureAwareEffectsTest {
    static int pass=0,total=0;
    static void check(String name, boolean ok, Object got){ total++; if(!ok) throw new AssertionError(name+" failed: "+got); pass++; System.out.println("PASS "+name+" -> "+got); }

    public static void main(String[] args) {
        var inner = new EffectContext("syntax", "inner-parser");
        var outer = new EffectContext("presentation", "outer-render");
        var innerReq = new EffectRequirement(EffectClass.ENCODING, inner);
        var outerReq = new EffectRequirement(EffectClass.ENCODING, outer);

        var reg = new TransformationRegistry()
            .register(new TransformationRule("encodeInner", EffectClass.ENCODING, inner, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encodeOuter", EffectClass.ENCODING, outer, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encodeInner", EffectClass.ENCODING, outer, Adequacy.INADEQUATE, ""))
            .register(new TransformationRule("encodeOuter", EffectClass.ENCODING, inner, Adequacy.INADEQUATE, ""))
            .register(new TransformationRule("maybeInner", EffectClass.ENCODING, inner, Adequacy.CONDITIONAL, "only some values transformed"));
        var eval = new StructureAwareTransformationEvaluator(reg);
        var src = EffectExpr.source("value");

        var direct = EffectExpr.at(innerReq, EffectExpr.apply("encodeInner", src));
        check("direct_transform_satisfies_context", eval.assess(direct).adequacy()==Adequacy.GUARANTEED, eval.assess(direct));

        var wrapped = EffectExpr.at(innerReq, EffectExpr.apply("neutralWrapper", EffectExpr.apply("encodeInner", src)));
        check("enclosing_structure_preserves_inner_guarantee", eval.assess(wrapped).adequacy()==Adequacy.GUARANTEED, eval.assess(wrapped));

        var wrong = EffectExpr.at(innerReq, EffectExpr.apply("encodeOuter", src));
        check("wrong_context_not_accepted", eval.assess(wrong).adequacy()==Adequacy.INADEQUATE, eval.assess(wrong));

        var nestedGood = EffectExpr.at(outerReq,
            EffectExpr.apply("encodeOuter",
                EffectExpr.at(innerReq, EffectExpr.apply("encodeInner", src))));
        var ng = eval.assess(nestedGood);
        check("nested_context_stack_all_layers_required", ng.adequacy()==Adequacy.GUARANTEED && ng.paths().get(0).layers().size()==2, ng);

        var missingInner = EffectExpr.at(outerReq,
            EffectExpr.apply("encodeOuter", EffectExpr.at(innerReq, src)));
        check("missing_inner_layer_fails", eval.assess(missingInner).adequacy()==Adequacy.INADEQUATE, eval.assess(missingInner));

        var missingOuter = EffectExpr.at(outerReq,
            EffectExpr.at(innerReq, EffectExpr.apply("encodeInner", src)));
        check("missing_outer_layer_fails", eval.assess(missingOuter).adequacy()==Adequacy.INADEQUATE, eval.assess(missingOuter));

        // A transformation after an inner boundary cannot retroactively satisfy that earlier layer.
        var tooLate = EffectExpr.at(outerReq,
            EffectExpr.apply("encodeInner",
                EffectExpr.at(innerReq, src)));
        check("later_transform_cannot_retroactively_satisfy_prior_context", eval.assess(tooLate).adequacy()==Adequacy.INADEQUATE, eval.assess(tooLate));

        var bothBranches = EffectExpr.at(innerReq, EffectExpr.branch(
            EffectExpr.apply("encodeInner", src),
            EffectExpr.apply("encodeInner", src)));
        check("all_branches_transformed_guaranteed", eval.assess(bothBranches).adequacy()==Adequacy.GUARANTEED, eval.assess(bothBranches));

        var rawBranch = EffectExpr.at(innerReq, EffectExpr.branch(
            EffectExpr.apply("encodeInner", src), src));
        check("raw_passthrough_branch_blocks_global_guarantee", eval.assess(rawBranch).adequacy()==Adequacy.CONDITIONAL, eval.assess(rawBranch));

        var conditional = EffectExpr.at(innerReq, EffectExpr.apply("maybeInner", src));
        check("conditional_operation_stays_conditional", eval.assess(conditional).adequacy()==Adequacy.CONDITIONAL, eval.assess(conditional));

        var unknown = EffectExpr.at(innerReq, EffectExpr.apply("unknownTransform", src));
        check("unknown_operation_abstains", eval.assess(unknown).adequacy()==Adequacy.UNKNOWN, eval.assess(unknown));

        // Flattened membership would see encodeInner somewhere and could incorrectly bless both layers.
        var flattenTrap = EffectExpr.at(outerReq,
            EffectExpr.at(innerReq, EffectExpr.apply("encodeInner", src)));
        var ft = eval.assess(flattenTrap);
        check("flattened_membership_trap_rejected", ft.adequacy()==Adequacy.INADEQUATE && ft.paths().get(0).layers().get(1).adequacy()==Adequacy.INADEQUATE, ft);

        var noContext = EffectExpr.apply("encodeInner", src);
        check("no_use_context_cannot_claim_adequacy", eval.assess(noContext).adequacy()==Adequacy.UNKNOWN, eval.assess(noContext));

        var steps = ng.paths().get(0).structuralSteps();
        check("structure_and_context_order_retained",
            steps.equals(List.of("APPLY:encodeInner","CONTEXT:syntax/inner-parser","APPLY:encodeOuter","CONTEXT:presentation/outer-render")), steps);

        // Verify the implementation surface stays language/profile neutral.
        String surface = (EffectExpr.class.getName()+StructureAwareTransformationEvaluator.class.getName()+innerReq+outerReq).toLowerCase(Locale.ROOT);
        check("portable_structure_model_has_no_wordpress_or_security_verdict", !surface.contains("wordpress") && !surface.contains("vulnerable") && !surface.contains("ast_"), surface);

        System.out.println("GATE31="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

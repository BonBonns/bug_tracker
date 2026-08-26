import portable.effects.*;
import java.util.*;

public class Gate30TransformationEffectsTest {
    static int pass=0,total=0;
    static void check(String name, boolean ok, Object got){ total++; if(!ok) throw new AssertionError(name+" failed: "+got); pass++; System.out.println("PASS "+name+" -> "+got); }

    public static void main(String[] args) {
        var whitespace = new EffectContext("text", "whitespace-trimmed");
        var canonicalId = new EffectContext("identifier", "canonical");
        var pathSegment = new EffectContext("path", "segment");
        var displayText = new EffectContext("text", "display");

        var reg = new TransformationRegistry()
            .register(new TransformationRule("trim", EffectClass.NORMALIZATION, whitespace, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("trim", EffectClass.CANONICALIZATION, canonicalId, Adequacy.INADEQUATE, ""))
            .register(new TransformationRule("canonicalizeIdentifier", EffectClass.CANONICALIZATION, canonicalId, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("encodeDisplay", EffectClass.ENCODING, displayText, Adequacy.GUARANTEED, ""))
            .register(new TransformationRule("maybeNormalize", EffectClass.NORMALIZATION, whitespace, Adequacy.CONDITIONAL, "only one return branch transforms the value"));

        check("same_operation_context_specific_guarantee",
            reg.assess("trim",EffectClass.NORMALIZATION,whitespace).adequacy()==Adequacy.GUARANTEED,
            reg.assess("trim",EffectClass.NORMALIZATION,whitespace));

        check("same_operation_wrong_effect_class_not_safe",
            reg.assess("trim",EffectClass.CANONICALIZATION,canonicalId).adequacy()==Adequacy.INADEQUATE,
            reg.assess("trim",EffectClass.CANONICALIZATION,canonicalId));

        check("missing_context_abstains_unknown",
            reg.assess("trim",EffectClass.NORMALIZATION,pathSegment).adequacy()==Adequacy.UNKNOWN,
            reg.assess("trim",EffectClass.NORMALIZATION,pathSegment));

        check("different_operation_can_guarantee_different_context",
            reg.assess("canonicalizeIdentifier",EffectClass.CANONICALIZATION,canonicalId).guaranteed(),
            reg.assess("canonicalizeIdentifier",EffectClass.CANONICALIZATION,canonicalId));

        check("adequacy_not_transferable_across_contexts",
            !reg.assess("canonicalizeIdentifier",EffectClass.CANONICALIZATION,pathSegment).guaranteed(),
            reg.assess("canonicalizeIdentifier",EffectClass.CANONICALIZATION,pathSegment));

        check("conditional_rule_not_promoted_to_guaranteed",
            reg.assess("maybeNormalize",EffectClass.NORMALIZATION,whitespace).adequacy()==Adequacy.CONDITIONAL &&
            !reg.assess("maybeNormalize",EffectClass.NORMALIZATION,whitespace).guaranteed(),
            reg.assess("maybeNormalize",EffectClass.NORMALIZATION,whitespace));

        check("all_branches_required_for_guarantee",
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.GUARANTEED))==Adequacy.GUARANTEED,
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.GUARANTEED)));

        check("passthrough_branch_blocks_wrapper_guarantee",
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.INADEQUATE))==Adequacy.CONDITIONAL,
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.INADEQUATE)));

        check("unknown_branch_keeps_wrapper_unknown",
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.UNKNOWN))==Adequacy.UNKNOWN,
            BranchEffectSummary.combine(List.of(Adequacy.GUARANTEED,Adequacy.UNKNOWN)));

        boolean conflictRejected=false;
        try {
            reg.register(new TransformationRule("trim", EffectClass.NORMALIZATION, whitespace, Adequacy.INADEQUATE, ""));
        } catch (IllegalArgumentException ex) { conflictRejected=true; }
        check("conflicting_rule_rejected",conflictRejected,conflictRejected);

        boolean conditionalNeedsReason=false;
        try {
            new TransformationRule("partial",EffectClass.NORMALIZATION,whitespace,Adequacy.CONDITIONAL,"");
        } catch (IllegalArgumentException ex) { conditionalNeedsReason=true; }
        check("conditional_requires_explicit_condition",conditionalNeedsReason,conditionalNeedsReason);

        check("registry_is_relation_not_flat_membership",reg.size()==5,reg.rules());

        String all = reg.rules().toString().toLowerCase(Locale.ROOT);
        check("portable_effect_core_has_no_security_verdict_or_wordpress_rule",
            !all.contains("vulnerable") && !all.contains("wordpress") && !all.contains("esc_html") && !all.contains("esc_sql"), all);

        System.out.println("GATE30="+pass+"/"+total);
        System.out.println("ANALYSIS_STATUS=COMPLETE");
    }
}

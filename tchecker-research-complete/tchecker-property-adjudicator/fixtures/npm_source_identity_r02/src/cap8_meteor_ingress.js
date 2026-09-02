// Capability 8 (R02): Meteor.methods-registered handler parameters are a real
// APPLICATION_INGRESS_INPUT source family -- ported from export_path_traversal_integ_r01.sc's
// own findIngressParams, restored here after R01 deliberately (and, in hindsight, too
// aggressively) scoped it out. Two registered handlers: one via a direct function-literal
// property (MethodRef), one via an Identifier reference to a separately-declared function --
// both real, distinct registration shapes findIngressParams already handles.
function directHandler(userPath) {
  return userPath;
}

function referencedHandler(userInput) {
  return userInput;
}

Meteor.methods({
  directRegistration: function (userPath) {
    return userPath;
  },
  referencedRegistration: referencedHandler,
});

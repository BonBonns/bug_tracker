// JS-PROV-R04 Q3 second sub-case (missed in the first pass):
// does a cast-erased argument silently weaken a STRONGER declared contract?
declare function use(x: any): any;
class ConcreteA { a = 1 }
class ConcreteB { b = 2 }
declare const concreteB: ConcreteB;

function g(x: ConcreteA) { use(x); }
g(concreteB as any);              // declared=ConcreteA, arg erased to ANY

// control: same callee, a correctly-typed argument
declare const concreteA: ConcreteA;
function g2(x: ConcreteA) { use(x); }
g2(concreteA);

// control: ANY-declared param receiving a cast-erased arg (propagation WOULD apply)
function g3(x) { use(x); }
g3(concreteB as any);

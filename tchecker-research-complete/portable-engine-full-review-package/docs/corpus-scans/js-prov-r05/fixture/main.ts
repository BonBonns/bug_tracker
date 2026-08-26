import { Router as R, Widget } from './mod/other';   // R05-3 imported alias
declare function use(x:any):any;

// R05-1 same nominal type, spelling differs
class Router { r = 1 }
declare function makeRouter(): Router;
const viaNew = new Router();
const viaFn  = makeRouter();
function f1(x){use(x);} f1(viaNew); f1(viaFn);

// R05-2 same short name, different module
const foreign = new R();
function f2(x){use(x);} f2(foreign);

// R05-4/5/8 casts
class ConcreteA { a=1 } class ConcreteB { b=2 }
declare const cb: ConcreteB;
function f4(x){use(x);}
f4(cb as any); f4(cb as unknown); f4(cb as unknown as ConcreteA);

// R05-6 union
function f6(x: Router | Widget){use(x);}
f6(viaNew); f6(new Widget());

// R05-7 generics
function idg<T>(x:T):T{return x;}
const g1 = idg(viaNew);
function f7<T>(x:T){use(x);}
f7(viaNew);
use(g1);

// R05-8 structural interface lookalike
interface HandlerLike { post(p:string):void }
class RealRouter implements HandlerLike { post(p:string){} }
const structural: HandlerLike = { post(p:string){} };
function f8(x: HandlerLike){use(x);}
f8(new RealRouter()); f8(structural);

// R05-9 property / index access
const rec: Record<string,Router> = {};
declare const key: string;
const viaField = (new RealRouter()).post;
const viaIndex = rec[key];
function f9(x){use(x);} f9(viaIndex); f9(viaField);

// R05-4b type alias
type RouterAlias = Router;
function fAlias(x: RouterAlias){use(x);}
fAlias(viaNew);

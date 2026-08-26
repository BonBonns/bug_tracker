// JS-PROV-R06 Part C: does R01's framework discriminator survive a DECLARED
// interface lookalike (R05 showed structural matches report identically)?
import express from 'express';
declare function use(x:any):any;

const app = express();                       // real framework object
app.post("/real", (req, res) => { use(req.body.u); });

// The R05-motivated harder negative control: a DECLARED interface, not an
// inline object-literal type (which is all R01 tested).
interface FrameworkLike {
  post(path: string, cb: Function): void;
}
const notFramework: FrameworkLike = { post(p: string, cb: Function) {} };
notFramework.post("/fake", (req, res) => { use(req.body.u); });

// also: a class implementing the interface
class FakeRouter implements FrameworkLike { post(p: string, cb: Function) {} }
const nf2 = new FakeRouter();
nf2.post("/fake2", (req, res) => { use(req.body.u); });

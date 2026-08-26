import { fDecl } from './lib';                              // S8 named import
import { fConst as fAliased } from './lib';                 // S9 aliased import
import fDefault from './lib';                               // S10 default import
import * as ns from './lib';                                // D3 namespace import
import { fDecl as viaReexport } from './reexport';          // S11 through re-export
declare function use(x:any):any;
async function go() {
  use(fDecl(1)); use(fAliased(2)); use(fDefault(3));
  use(ns.fDecl(4));                                          // D3 use
  use(viaReexport(5));
  const dyn = await import('./lib');                        // D4 dynamic import
  use(dyn.fDecl(6));
  const un = await import('./does-not-exist');              // D5 unresolved
  use(un);
}
go();

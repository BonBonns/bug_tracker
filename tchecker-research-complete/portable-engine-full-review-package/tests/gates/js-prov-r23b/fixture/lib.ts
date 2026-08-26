export function fDecl(a: any) { return a; }                 // S1 export function
export const fConst = (a: any) => a;                        // S2 export const
function fLater(a: any) { return a; }
export { fLater };                                          // S3 declare then export
function fOrig(a: any) { return a; }
export { fOrig as fRenamed };                               // S4 renamed export
function fDef(a: any) { return a; }
export default fDef;                                        // S5 export default <ident>

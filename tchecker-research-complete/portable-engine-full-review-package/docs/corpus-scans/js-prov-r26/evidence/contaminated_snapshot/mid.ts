export { realFn } from './base';            // S1 single-hop re-export
export { missing } from './base';           // N1 target does NOT export `missing`
export * from './base';                     // N2 must still abstain

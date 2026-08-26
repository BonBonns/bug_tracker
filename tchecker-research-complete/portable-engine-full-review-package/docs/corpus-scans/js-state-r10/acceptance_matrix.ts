// JS-STATE-R10 acceptance matrix. Each case must have its operator recovered
// independently for the comparison node itself.
declare function sink(x: unknown): void;
declare const value: any; declare const a: any; declare const b: any; declare const c: any;

function m1_looseEq()    { if (value == "admin") sink(1); }
function m2_strictEq()   { if (value === "admin") sink(2); }
function m3_looseNeq()   { if (value != "admin") sink(3); }
function m4_strictNeq()  { if (value !== "admin") sink(4); }
function m5_chained()    { if (a == b === c) sink(5); }
function m6_stringLit()  { if ("a == b" === value) sink(6); }
function m7_comment()    { if (a /* == */ === b) sink(7); }
function m8_multiline()  {
  if (a
      ===
      b) sink(8);
}
declare const d: any;
function m9_tsNonNull() { if (d! === b) sink(9); }

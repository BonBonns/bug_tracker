// DECISIVE NEGATIVE: two functions each returning a DIFFERENT lambda,
// only ONE is exported. A resolver returning both is invalid.
function validate(s){ return async (c,n)=>{ c.vA = c.request.body; await n(); }; }
function other(s){    return async (c,n)=>{ c.vB = c.query;        await n(); }; }
module.exports = other;

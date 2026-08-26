function validate(s){ return async (c,n)=>{ c.v3 = c.request.body; await n(); }; }
function other(s){    return async (c,n)=>{ c.o3 = 1; await n(); }; }
module.exports = { validate, other };

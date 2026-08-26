function validate(s){ return async (c,n)=>{ c.v2 = c.request.body; await n(); }; }
exports.validate = validate;

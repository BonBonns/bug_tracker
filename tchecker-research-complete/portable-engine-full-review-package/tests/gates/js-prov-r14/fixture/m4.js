function validate(s){ return async (c,n)=>{ c.v4 = c.request.body; await n(); }; }
module.exports.validate = validate;

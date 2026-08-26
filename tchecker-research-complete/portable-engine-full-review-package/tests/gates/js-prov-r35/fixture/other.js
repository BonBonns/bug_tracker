function otherFn(a){ return a; }
module.exports = { otherFn, leafFn: otherFn };   // shares a member NAME with leaf

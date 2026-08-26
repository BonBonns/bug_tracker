// Identity DENIED: polymorphic dispatch -> trace identity is not unique
class A { transform(p) { return { ...p }; } }
class B { transform(p) { return { ...p, e: p }; } }
function handler(req, flag, cache) {
  const obj = flag ? new A() : new B();
  const out = obj.transform(req.body);
  cache.set('k', JSON.stringify(out));
}

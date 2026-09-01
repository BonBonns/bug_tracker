// OPEN: attacker body through a user-defined MEMBER-METHOD transform, straight to sink
class Audit {
  redact(body) { const clone = { ...body }; delete clone['password']; return clone; }
  write(req, cache) {
    const cleaned = this.redact(req.body);
    cache.set('audit', JSON.stringify(cleaned));
  }
}

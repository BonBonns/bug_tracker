// BROKEN-ish false positive: request value is only a lookup key + comparison
function handler(req, db, session) {
  const rec = db.getSecondaryEmail(req.body.email);
  if (rec && rec.uid === session.uid) {
    const value = JSON.stringify(session.uid);   // serialized value is the session id, not the body
    return value;
  }
}

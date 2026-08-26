function checkAccess(cache, userId) {
  const parser = (value) => value || {};
  const parserCopy = (value) => value || {};
  return cache.get(userId)
    .then(parser, parserCopy)
    .then((records) => records.length === 0);
}


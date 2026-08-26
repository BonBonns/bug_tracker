function checkAccess(cache, userId) {
  return cache.get(userId)
    .then((records) => records.length === 0);
}


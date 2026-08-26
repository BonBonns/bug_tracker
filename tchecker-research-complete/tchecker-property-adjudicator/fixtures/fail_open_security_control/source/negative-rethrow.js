function parseRecords(value) {
  return value || {};
}

function checkAccess(cache, userId) {
  return cache.get(userId)
    .then(parseRecords, (error) => { throw error; })
    .then((records) => records.length === 0);
}


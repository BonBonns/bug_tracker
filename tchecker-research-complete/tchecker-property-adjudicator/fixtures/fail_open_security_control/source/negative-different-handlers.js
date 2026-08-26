function parseRecords(value) {
  return value || {};
}

function denyOnError() {
  return false;
}

function checkAccess(cache, userId) {
  return cache.get(userId)
    .then(parseRecords, denyOnError)
    .then((records) => records.length === 0);
}


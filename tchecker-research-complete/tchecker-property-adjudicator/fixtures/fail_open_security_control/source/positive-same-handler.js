function parseRecords(value) {
  return value || {};
}

function isAllowed(records) {
  return Object.keys(records).length === 0;
}

function checkAccess(cache, userId) {
  return cache.get(userId)
    .then(parseRecords, parseRecords)
    .then((records) => isAllowed(records));
}


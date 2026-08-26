// Permanent source-coverage regression fixture: request.payload, request.query, and
// request.headers all feed the SAME transform and the SAME sink. Asserts all three source
// families survive enumeration independently (this file, once staged, must produce three
// distinct source_facts.tsv rows / three distinct alternatives -- not fewer).
function combine(request) {
  const merged = {
    payload: request.payload,
    query: request.query,
    headers: request.headers,
  };
  return sendReport(merged);
}

function sendReport(data) {
  return JSON.stringify(data);
}

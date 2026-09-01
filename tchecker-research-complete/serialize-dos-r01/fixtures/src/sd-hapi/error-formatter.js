// Positive (both axes), Hapi framework source pattern (request.payload).
function failAction(request) {
  const offending = request.payload;
  return JSON.stringify(offending);
}

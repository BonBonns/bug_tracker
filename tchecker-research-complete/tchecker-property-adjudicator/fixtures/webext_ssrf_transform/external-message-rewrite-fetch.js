function rewriteTarget(value) {
  return normalizeDestination(value);
}

browser.runtime.onMessageExternal.addListener(async (message) => {
  return fetch(rewriteTarget(message.url));
});

function renderCacheValue(cache, key) {
  return cache.get(key)
    .then(String, String)
    .then((text) => console.log(text));
}


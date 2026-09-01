function handleAutotranslate(text) {
  return /^(x+)+$/.test(text);
}
Meteor.methods({
  autotranslate: handleAutotranslate
});

export function nestedPositive(input) {
  return input.profile.url;
}

export function samePathOverwrite(input, replacement) {
  input.profile.url = replacement;
  return input.profile.url;
}

export function parentOverwrite(input, replacement) {
  input.profile = replacement;
  return input.profile.url;
}

export function distinctRoot(input, other, replacement) {
  other.profile.url = replacement;
  return input.profile.url;
}

export function dynamicPath(input, key) {
  return input[key].url;
}

export function siblingWrite(input, replacement) {
  input.profile.other = replacement;
  return input.profile.url;
}

export function localPositive(input) {
  const copy = input;
  return copy.profile.url;
}

export function childThenParent(input, replacement) {
  input.profile.url = replacement;
  input.profile = replacement;
  return input.profile.url;
}

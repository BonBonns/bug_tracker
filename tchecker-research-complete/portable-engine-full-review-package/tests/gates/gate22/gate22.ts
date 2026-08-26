export function objectSpreadExact(a: Record<string,string>, source: string) {
  a["fixed"] = source;
  const copy = { ...a };
  return copy["fixed"];
}

export function objectSpreadOverrideAfter(a: Record<string,string>, source: string) {
  a["fixed"] = source;
  const copy = { ...a, fixed: "CONST" };
  return copy["fixed"];
}

export function objectSpreadOverrideBefore(a: Record<string,string>, source: string) {
  a["fixed"] = source;
  const copy = { fixed: "CONST", ...a };
  return copy["fixed"];
}

export function objectSpreadLaterObjectWins(a: Record<string,string>, b: Record<string,string>, source: string) {
  a["fixed"] = source;
  b["fixed"] = "CONST";
  const copy = { ...a, ...b };
  return copy["fixed"];
}

export function objectSpreadEarlierObjectLoses(a: Record<string,string>, b: Record<string,string>, source: string) {
  a["fixed"] = "CONST";
  b["fixed"] = source;
  const copy = { ...a, ...b };
  return copy["fixed"];
}

export function objectSpreadDynamicWrite(a: Record<string,string>, key: string, source: string) {
  a["fixed"] = "CONST";
  a[key] = source;
  const copy = { ...a };
  return copy["fixed"];
}

export function arraySpreadExact(a: string[], source: string) {
  a[0] = source;
  const copy = [ ...a ];
  return copy[0];
}

export function arraySpreadPrefix(a: string[], source: string) {
  a[0] = source;
  const copy = [ "CONST", ...a ];
  return copy[1];
}

export function arraySpreadSuffix(a: string[], source: string) {
  a[0] = source;
  const copy = [ ...a, "CONST" ];
  return copy[0];
}

export function distinctReceiverSpread(a: Record<string,string>, b: Record<string,string>, source: string) {
  a["fixed"] = "CONST";
  b["fixed"] = source;
  const copy = { ...a };
  return copy["fixed"];
}

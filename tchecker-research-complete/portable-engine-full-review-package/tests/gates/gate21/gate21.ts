export function objectDestructureExact(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  const { fixed } = box;
  return fixed;
}

export function objectDestructureRename(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  const { fixed: renamed } = box;
  return renamed;
}

export function objectDestructureDifferent(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  box["other"] = "CONST";
  const { other } = box;
  return other;
}

export function objectDestructureOverwrite(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  box["fixed"] = "CONST";
  const { fixed } = box;
  return fixed;
}

export function arrayDestructureExact(arr: string[], source: string) {
  arr[0] = source;
  const [first] = arr;
  return first;
}

export function arrayDestructureDifferent(arr: string[], source: string) {
  arr[0] = source;
  arr[1] = "CONST";
  const [, second] = arr;
  return second;
}

export function computedDestructure(box: Record<string,string>, key: string, source: string) {
  box["fixed"] = source;
  box["other"] = "CONST";
  const { [key]: picked } = box;
  return picked;
}

export function objectRest(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  box["other"] = "CONST";
  const { fixed, ...rest } = box;
  return rest;
}

export function arrayRest(arr: string[], source: string) {
  arr[0] = "CONST";
  arr[1] = source;
  const [first, ...rest] = arr;
  return rest;
}

export function distinctReceiver(a: Record<string,string>, b: Record<string,string>, source: string) {
  a["fixed"] = "CONST";
  b["fixed"] = source;
  const { fixed } = a;
  return fixed;
}

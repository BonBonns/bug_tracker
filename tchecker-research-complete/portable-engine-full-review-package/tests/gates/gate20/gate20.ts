export function objectStaticExact(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  return box["fixed"];
}

export function objectStaticDifferent(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  box["other"] = "CONST";
  return box["other"];
}

export function objectStaticOverwrite(box: Record<string,string>, source: string) {
  box["fixed"] = source;
  box["fixed"] = "CONST";
  return box["fixed"];
}

export function objectDynamicWrite(box: Record<string,string>, key: string, source: string) {
  box["fixed"] = "BASE";
  box[key] = source;
  return box["fixed"];
}

export function objectDynamicRead(box: Record<string,string>, key: string, source: string) {
  box["fixed"] = source;
  box["other"] = "CONST";
  return box[key];
}

export function arrayStaticExact(arr: string[], source: string) {
  arr[0] = source;
  return arr[0];
}

export function arrayStaticDifferent(arr: string[], source: string) {
  arr[0] = source;
  arr[1] = "CONST";
  return arr[1];
}

export function arrayDynamicWrite(arr: string[], i: number, source: string) {
  arr[0] = "BASE";
  arr[i] = source;
  return arr[0];
}

export function arrayDynamicRead(arr: string[], i: number, source: string) {
  arr[0] = source;
  arr[1] = "CONST";
  return arr[i];
}

export function differentReceiver(a: Record<string,string>, b: Record<string,string>, key: string, source: string) {
  a["fixed"] = "BASE";
  b[key] = source;
  return a["fixed"];
}

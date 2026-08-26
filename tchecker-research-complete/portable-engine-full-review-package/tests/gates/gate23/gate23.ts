export function closureDirect(source: string) {
  const f = () => source;
  return f();
}

export function closureParam(source: string) {
  const f = (x: string) => x;
  return f(source);
}

export function closureShadow(source: string) {
  const f = (source: string) => source;
  return f("CONST");
}

export function closureUnrelated(source: string) {
  const f = () => "CONST";
  return f();
}

export function closureAlias(source: string) {
  const x = source;
  const f = () => x;
  return f();
}

export function closureMutation(source: string) {
  let x = source;
  const f = () => x;
  x = "CONST";
  return f();
}

export function closureMutationToSource(source: string) {
  let x = "CONST";
  const f = () => x;
  x = source;
  return f();
}

export function nestedClosure(source: string) {
  const f = () => () => source;
  const g = f();
  return g();
}

export function closureTwoCaptures(a: string, b: string) {
  const f = () => a + b;
  return f();
}

export function closureLocalShadowsOuter(source: string) {
  const x = source;
  const f = () => {
    const x = "CONST";
    return x;
  };
  return f();
}

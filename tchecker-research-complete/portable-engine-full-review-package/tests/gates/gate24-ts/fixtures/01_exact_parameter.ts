class A {
  process(x: string): string { return x; }
}
export function exact(obj: A, x: string): string {
  return obj.process(x);
}

class A { process(x: string): string { return x; } }
class B { process(x: string): string { return "constant"; } }
export function unionCall(obj: A | B, x: string): string {
  return obj.process(x);
}

class A { process(x: string): string { return x; } }
class Holder { worker!: A; }
export function propertyCall(h: Holder, x: string): string {
  return h.worker.process(x);
}

interface Worker { process(x: string): string; }
class A implements Worker { process(x: string): string { return x; } }
export function genericCall<T extends Worker>(w: T, x: string): string {
  return w.process(x);
}

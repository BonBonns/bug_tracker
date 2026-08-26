interface Worker { process(x: string): string; }
class A implements Worker { process(x: string): string { return x; } }
class B implements Worker { process(x: string): string { return "constant"; } }
export function interfaceCall(w: Worker, x: string): string {
  return w.process(x);
}

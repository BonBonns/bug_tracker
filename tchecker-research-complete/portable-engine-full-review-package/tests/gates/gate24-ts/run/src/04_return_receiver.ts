class A { process(x: string): string { return x; } }
class Holder { worker!: A; }
export function getWorker(h: Holder): A { return h.worker; }
export function returnReceiver(h: Holder, x: string): string {
  return getWorker(h).process(x);
}

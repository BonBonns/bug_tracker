class Base { process(x: string): string { return x; } }
class Child extends Base { process(x: string): string { return "child:" + x; } }
export function baseCall(b: Base, x: string): string { return b.process(x); }
export function childCall(c: Child, x: string): string { return c.process(x); }

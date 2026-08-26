export function helper(value: string): string {
  return value;
}

export function main(input: string): string {
  return helper(input);
}

export function constant(): string {
  return "CONST";
}

export function passthrough(a: string, b: string): string {
  return helper(b);
}

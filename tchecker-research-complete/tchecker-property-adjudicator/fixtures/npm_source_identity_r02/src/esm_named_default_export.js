// Export-surface capability: ESM named + default export -- confirmed (export_redos_npm_integ.sc's
// own header comment) to desugar to the EXACT same `name = <MethodRef>` + `exports.name = name`
// shape as CommonJS named exports, so no separate ESM code path is required; this fixture is a
// direct regression check of that claim inside this NEW producer.
export function namedHandler(value) {
  return value;
}

export default function defaultHandler(value) {
  return value;
}

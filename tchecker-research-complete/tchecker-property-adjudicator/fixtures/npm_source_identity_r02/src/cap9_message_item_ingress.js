// Capability 9 (R02): message/item field-access shape is a real APPLICATION_INGRESS_INPUT source
// family too -- ported verbatim (same literal regex, same field-access mechanism) from
// export_redos_npm_integ.sc's own frozen MESSAGE_SOURCE_PATTERN, restored here for real parity
// (R01's own dev-package/fixture set never had a real example, and the pattern was left
// unrecognized entirely).
function handleMessage(message) {
  return message.text;
}

function handleItem(item) {
  return item.attachments;
}

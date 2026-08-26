// STRUCTURAL REPRODUCTION: payload decodes to a harmless string; never run.
const payload = "Y29uc29sZS5sb2coJ2hpJyk=";           // base64 blob
const code = Buffer.from(payload, "base64").toString();
eval(code);                                             // decode -> eval sink

#!/usr/bin/env python3
# Builds the customs.js OPEN-edge adjudication packet.
# Design constraints (per review):
#   - PRESERVE the observed dataflow evidence (do not hide the HTTP_BODY -> sanitizePayload -> sink flow).
#   - STRIP verdict-oriented narrative. No "candidate vulnerability", "likely exploitable",
#     "false positive"; no claim that HTTP_BODY "controls" the sink beyond established flow facts.
#   - Isolate the question to the single UNKNOWN/OPEN edge (sanitizePayload), and do NOT tell the
#     model what overall verdict the path should receive.
#   - No emails.js result, no fixture/hint result.
import json, pathlib

# Observed dataflow, taken directly from the property-propagation facts (neutral labels).
# Each step is a value transition with its established property_effect; the sanitizePayload
# transform is the single edge whose effect is UNKNOWN/OPEN.
observed_dataflow = [
    {"from": "request.payload", "to": "payload (parameter)", "property_effect": "PRESERVES_PROPERTY"},
    {"from": "payload", "to": "clonePayload = { ...payload } (inside sanitizePayload)",
     "edge": "sanitizePayload", "property_effect": "UNKNOWN / OPEN"},
    {"from": "sanitizePayload(request.payload)", "to": "requestData.payload field",
     "property_effect": "PRESERVES_PROPERTY"},
    {"from": "requestData", "to": "JSON.stringify(requestData)  (serialization site)",
     "property_effect": "PRESERVES_PROPERTY"},
]

relevant_code = {
    "sanitizePayload_definition": (
        "sanitizePayload(payload) {\n"
        "  if (!payload) {\n    return;\n  }\n"
        "  const clonePayload = { ...payload };\n"
        "  const fieldsToOmit = ['authPW', 'oldAuthPW', 'paymentToken'];\n"
        "  fieldsToOmit.forEach((name) => delete clonePayload[name]);\n"
        "  return clonePayload;\n"
        "}"
    ),
    "serialization_site": "body: JSON.stringify(requestData),",
}

packet = {
    "schema": "tchecker-open-edge-adjudication/1.0",
    "security_property": "ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE",
    "observed_dataflow": observed_dataflow,
    "open_edge": {
        "edge": "sanitizePayload(...)",
        "status": "UNKNOWN / OPEN",
        "meaning": ("The transform is on the established dataflow path, but its effect on the "
                    "security property is not determined by structure alone."),
    },
    "relevant_code": relevant_code,
    "question": ("Does sanitizePayload bound or otherwise destroy attacker control of the "
                 "serialized size or structure, or does that control survive the transform?"),
    "answer_contract": {
        "answer_one_of": [
            "BREAKS_PROPERTY   (the transform bounds/replaces the value so serialized "
            "size/structure is no longer attacker-controlled)",
            "PRESERVES_PROPERTY (attacker control of serialized size/structure survives unchanged)",
            "TRANSFORMS_PROPERTY (value is changed but attacker size/structure influence survives)",
            "UNKNOWN            (cannot be determined from the provided code)",
        ],
        "require": "a rationale grounded only in the provided sanitizePayload definition",
        "do_not": "do not assign an overall verdict to the whole path; answer only the edge effect",
    },
}

out = pathlib.Path("/mnt/user-data/outputs/customs_open_edge_packet.json")
out.write_text(json.dumps(packet, indent=2))
print(out)
print(json.dumps(packet, indent=2))

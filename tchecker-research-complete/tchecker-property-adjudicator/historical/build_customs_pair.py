#!/usr/bin/env python3
# Builds the customs.js calibration PAIR. The two packets are byte-for-byte identical except
# for exactly one field: relevant_code.sanitizePayload_definition. In the withheld variant the
# function body is replaced with the neutral token "[implementation withheld]" and nothing else
# changes -- so any difference in adjudication is attributable to semantic evidence, not framing.
import json, pathlib

BODY_SHOWN = (
    "sanitizePayload(payload) {\n"
    "  if (!payload) {\n    return;\n  }\n"
    "  const clonePayload = { ...payload };\n"
    "  const fieldsToOmit = ['authPW', 'oldAuthPW', 'paymentToken'];\n"
    "  fieldsToOmit.forEach((name) => delete clonePayload[name]);\n"
    "  return clonePayload;\n"
    "}"
)
BODY_WITHHELD = "[implementation withheld]"

def packet(body):
    return {
        "schema": "tchecker-open-edge-adjudication/1.0",
        "security_property": "ATTACKER_CONTROL_OF_SERIALIZED_SIZE_OR_STRUCTURE",
        "observed_dataflow": [
            {"from": "request.payload", "to": "payload (parameter)", "property_effect": "PRESERVES_PROPERTY"},
            {"from": "payload", "to": "clonePayload = { ...payload } (inside sanitizePayload)",
             "edge": "sanitizePayload", "property_effect": "UNKNOWN / OPEN"},
            {"from": "sanitizePayload(request.payload)", "to": "requestData.payload field",
             "property_effect": "PRESERVES_PROPERTY"},
            {"from": "requestData", "to": "JSON.stringify(requestData)  (serialization site)",
             "property_effect": "PRESERVES_PROPERTY"},
        ],
        "open_edge": {
            "edge": "sanitizePayload(...)",
            "status": "UNKNOWN / OPEN",
            "meaning": ("The transform is on the established dataflow path, but its effect on the "
                        "security property is not determined by structure alone."),
        },
        "relevant_code": {
            "sanitizePayload_definition": body,
            "serialization_site": "body: JSON.stringify(requestData),",
        },
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

out = pathlib.Path("/mnt/user-data/outputs")
shown = out / "customs_pair_bodyShown.json"
withheld = out / "customs_pair_bodyWithheld.json"
shown.write_text(json.dumps(packet(BODY_SHOWN), indent=2))
withheld.write_text(json.dumps(packet(BODY_WITHHELD), indent=2))
print("wrote", shown.name, "and", withheld.name)

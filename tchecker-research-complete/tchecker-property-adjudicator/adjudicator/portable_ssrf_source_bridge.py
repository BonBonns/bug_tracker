#!/usr/bin/env python3
"""Convert portable browser source facts into the narrow SSRF producer bridge.

The bridge transports identity only. It does not assert source-to-sink flow,
host-control preservation, a vulnerability verdict, or a semantic hint; those
remain the SSRF producer/adjudicator's existing responsibilities.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

SCHEMA = "portable-source-facts/0.1"
ORIGIN = "WEBEXT_TAB_URL_INPUT"
TARGET = "STATE_READ"
LOCATIONS = {
    "tabs.onCreated.tab.url",
    "tabs.onUpdated.changeInfo.url",
    "tabs.onUpdated.tab.url",
}
EXTERNAL_ORIGIN = "WEBEXT_EXTERNAL_MESSAGE_INPUT"
EXTERNAL_TARGET = "PARAMETER"
EXTERNAL_LOCATION = "runtime.onMessageExternal"


def derive(document: dict) -> list[tuple[int, str, str, str]]:
    if document.get("schema") != SCHEMA:
        raise ValueError(f"unsupported portable source schema: {document.get('schema')!r}")
    facts = document.get("source_origins")
    if not isinstance(facts, list):
        raise ValueError("source_origins must be a list")
    out = []
    seen = set()
    for fact in facts:
        if not isinstance(fact, dict):
            raise ValueError("source origin row must be an object")
        origin = fact.get("origin_kind")
        if origin not in {ORIGIN, EXTERNAL_ORIGIN}:
            continue  # file/network/internal-message origins remain separate classes
        node_id = fact.get("target_local_id")
        if not isinstance(node_id, int) or node_id <= 0:
            raise ValueError(f"{origin} target id must be a positive integer")
        location = fact.get("location")
        if node_id in seen:
            raise ValueError(f"duplicate portable SSRF source target id: {node_id}")
        derivation = fact.get("derivation") or {}
        source_ids = derivation.get("source_node_ids")
        if origin == ORIGIN:
            if fact.get("target_kind") != TARGET:
                raise ValueError(f"{ORIGIN} must target {TARGET}")
            if fact.get("id") != node_id:
                raise ValueError(f"{ORIGIN} fact id must equal its use-scoped STATE_READ target")
            if location not in LOCATIONS:
                raise ValueError(f"unsupported {ORIGIN} location: {location!r}")
            if derivation.get("rule") != "JS_WEBEXT_TAB_URL_SOURCE":
                raise ValueError(f"{ORIGIN} must carry JS_WEBEXT_TAB_URL_SOURCE derivation")
            target = TARGET
        else:
            if fact.get("target_kind") != EXTERNAL_TARGET:
                raise ValueError(f"{EXTERNAL_ORIGIN} must target {EXTERNAL_TARGET}")
            registration_id = fact.get("id")
            if not isinstance(registration_id, int) or registration_id <= 0 or registration_id == node_id:
                raise ValueError(f"{EXTERNAL_ORIGIN} must retain a distinct registration-call id")
            if location != EXTERNAL_LOCATION:
                raise ValueError(f"unsupported {EXTERNAL_ORIGIN} location: {location!r}")
            if derivation.get("rule") != "JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE":
                raise ValueError(f"{EXTERNAL_ORIGIN} must carry JS_WEBEXT_EXTERNAL_MESSAGE_SOURCE derivation")
            if not isinstance(source_ids, list) or registration_id not in source_ids or node_id not in source_ids:
                raise ValueError(f"{EXTERNAL_ORIGIN} derivation must bind registration and parameter identities")
            target = EXTERNAL_TARGET
        seen.add(node_id)
        out.append((node_id, origin, target, location))
    return sorted(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source_json", type=Path)
    ap.add_argument("out_tsv", type=Path)
    args = ap.parse_args()
    if not args.source_json.is_file():
        raise FileNotFoundError(args.source_json)
    rows = derive(json.loads(args.source_json.read_text(encoding="utf-8")))
    args.out_tsv.parent.mkdir(parents=True, exist_ok=True)
    args.out_tsv.write_text("".join("\t".join(map(str, row)) + "\n" for row in rows), encoding="utf-8")
    print(f"PORTABLE_SSRF_SOURCE_BRIDGE={len(rows)}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""ORIGIN-KIND evaluation: TWO independent metrics, TWO independent sources.

The engine must not grade itself. So this tool compares:
  INDEPENDENT characterization  (source-shape APIs present in the code, and the
                                 curated/external layer for DATABASE_INPUT)
      vs.
  ENGINE-PRODUCED provenance    (origins the engine actually emitted)

Two metrics, deliberately kept separate:

  ORIGIN_KIND_CORPUS_PURITY = correctly-typed emitted / all emitted   (target 1.0)
      "Does the engine lie when it speaks?"  A system that emits nothing scores
      1.0 here TRIVIALLY — which is why purity ALONE is not a coverage claim.

  SUPPORTED_ORIGIN_COVERAGE = correctly emitted / independently-identified appearances
      "How often can the engine speak?"  Abstention lowers THIS number, never
      purity. This is where the abstention cost is made visible and honest.

EXPECTED/OBSERVED is derived from independent corpus characterization, NOT engine
output. The 'source' of each appearance count is labelled so no one can mistake a
curated-layer identification for an engine discovery.
"""
import json, pathlib, sys
from collections import defaultdict

# INDEPENDENT characterization: source-shape API sets (corpus grep, not engine).
SHAPE = {
 'FILE_INPUT':{'fread','fgets','read','getline','readFile','readFileSync'},
 'NETWORK_INPUT':{'recv','recvfrom','recvmsg'},
 'DATABASE_INPUT':{'sqlite3_column_blob','sqlite3_column_text','sqlite3_column_bytes'},
 'STREAM_EVENT_INPUT':{'createReadStream'},
 'WEBEXT_EXTERNAL_MESSAGE_INPUT':{'runtime.onMessageExternal'},
 'WEBEXT_TAB_URL_INPUT':{'tabs.onCreated.tab.url','tabs.onUpdated.changeInfo.url',
                         'tabs.onUpdated.tab.url'},
}
# how each kind's appearances are IDENTIFIED (provenance of the EXPECTED column):
IDENTIFIED_BY = {
 'FILE_INPUT':'corpus-grep','NETWORK_INPUT':'corpus-grep',
 'DATABASE_INPUT':'curated-layer','STREAM_EVENT_INPUT':'corpus-grep','REQUEST_INPUT':'none',
 'WEBEXT_EXTERNAL_MESSAGE_INPUT':'listener-shape',
 'WEBEXT_TAB_URL_INPUT':'listener-url-shape',
}
# the ONLY kind an engine recognizer may currently emit, + its canonical API set:
ENGINE_EMITS = {
 'FILE_INPUT': SHAPE['FILE_INPUT'],
 'WEBEXT_EXTERNAL_MESSAGE_INPUT': SHAPE['WEBEXT_EXTERNAL_MESSAGE_INPUT'],
 'WEBEXT_TAB_URL_INPUT': SHAPE['WEBEXT_TAB_URL_INPUT'],
}

def measure(fact_files):
    appear=defaultdict(int); emit=defaultdict(int)
    correct=defaultdict(int); mismatch=defaultdict(int)
    for pj in fact_files:
        pj=pathlib.Path(pj)
        if not pj.exists(): continue
        d=json.load(open(pj))
        for c in d.get('calls',[]):
            for kind,apis in SHAPE.items():
                if c['name'] in apis: appear[kind]+=1
            code=''.join((c.get('code') or '').split())
            if (code.startswith('browser.runtime.onMessageExternal.addListener(')
                    or code.startswith('chrome.runtime.onMessageExternal.addListener(')):
                appear['WEBEXT_EXTERNAL_MESSAGE_INPUT']+=1
            if (code.startswith('browser.tabs.onCreated.addListener(')
                    or code.startswith('chrome.tabs.onCreated.addListener(')
                    or code.startswith('browser.tabs.onUpdated.addListener(')
                    or code.startswith('chrome.tabs.onUpdated.addListener(')):
                appear['WEBEXT_TAB_URL_INPUT'] += len(__import__('re').findall(r'\.url\b', code))
        sc=pathlib.Path(str(pj)+'.source.json')
        if sc.exists():
            for o in json.load(open(sc)).get('source_origins',[]):
                k=o.get('origin_kind'); emit[k]+=1
                if o.get('location') in ENGINE_EMITS.get(k,set()): correct[k]+=1
                else: mismatch[k]+=1
    return appear,emit,correct,mismatch

if __name__=='__main__':
    files=sys.argv[1:] or [
        '/tmp/sd_scan/p.json','/tmp/norm_scan/p.json','/tmp/upw_multer/js.json',
        '/tmp/upw_express-fileupload/js.json','/tmp/cmw/js.json','/tmp/jssrc_w2/js.json','/tmp/crs_w/js.json']
    appear,emit,correct,mismatch=measure(files)
    kinds=['FILE_INPUT','NETWORK_INPUT','DATABASE_INPUT','STREAM_EVENT_INPUT',
           'WEBEXT_EXTERNAL_MESSAGE_INPUT','WEBEXT_TAB_URL_INPUT','REQUEST_INPUT']
    print(f"{'ORIGIN KIND':20s}{'EXPECTED*':>10}{'EMITTED':>9}{'UNRESOLVED':>12}{'MISMATCH':>9}{'IDENTIFIED BY':>16}")
    for k in kinds:
        unresolved=appear[k]-emit[k]
        print(f"{k:20s}{appear[k]:>10}{emit[k]:>9}{unresolved:>12}{mismatch[k]:>9}{IDENTIFIED_BY[k]:>16}")
    tot_emit=sum(emit.values()); tot_correct=sum(correct.values()); tot_mis=sum(mismatch.values())
    tot_appear=sum(appear.values())
    purity = (tot_correct/tot_emit) if tot_emit else 1.0
    coverage = (tot_correct/tot_appear) if tot_appear else 0.0
    print(f"\n* EXPECTED derived from INDEPENDENT corpus characterization / curated layer,")
    print(f"  NOT engine output. DATABASE_INPUT appearances are curated-layer, not engine finds.")
    print(f"\nORIGIN_KIND_CORPUS_PURITY  = {tot_correct}/{tot_emit} = {purity:.3f}   (does it lie when it speaks)")
    print(f"SUPPORTED_ORIGIN_COVERAGE  = {tot_correct}/{tot_appear} = {coverage:.3f}   (how often it can speak)")
    print(f"  per-kind coverage: " + ", ".join(
        f"{k}={correct[k]}/{appear[k]}" for k in kinds if appear[k]))
    # GATE: purity must be 1.0 (0 mismatches). Coverage is REPORTED, never gated.
    ok = (tot_mis==0)
    print(f"\nORIGIN_KIND_CORPUS_PURITY={'PASS' if ok else 'FAIL'} (mismatch={tot_mis})")
    print(f"(coverage is a reported quantity, deliberately NOT a pass/fail gate —")
    print(f" gating coverage would punish honest abstention.)")
    sys.exit(0 if ok else 1)

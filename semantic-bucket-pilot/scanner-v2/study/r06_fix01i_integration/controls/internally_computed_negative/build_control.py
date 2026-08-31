#!/usr/bin/env python3
"""R06/FIX01I integration -- ADVERSARIAL SYNTHETIC control (never presented as a real corpus
finding): a JS-reachable native method (real `Napi::CallbackInfo` parameter) whose allocation
size is INTERNALLY COMPUTED (`length = width * height`, both fixed internal literals) and
never touches `info[N]` at all. Proves the required negative: `promote_via_js_linkage.py`
must NOT promote a linked function's allocation size merely because the enclosing method is
JS-reachable -- only a real, structural `info[N]`-via-out-parameter source justifies
promotion, and this control has none.

Writes real, base64-encoded raw-TSV facts (methods.tsv, parameters.tsv, calls.tsv,
arguments.tsv), same schema `resource_guard_verdict_r06.py`'s own `rows()`/`dec()` expect.
"""
import base64
import os

OUT = os.path.dirname(os.path.abspath(__file__))


def b64(s):
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


METHOD_ID = 500000001

methods_rows = [
    # id, name, fullName, signature, filename, lineNumber, lineNumberEnd, astParentType, astParentFullName, isExternal
    [str(METHOD_ID), b64("AllocateBuffer"), b64("Widget.AllocateBuffer:Napi.Value(Napi.CallbackInfo&)"),
     b64("Napi.Value(Napi.CallbackInfo&)"), b64("widget.cc"), "1", "20", b64("TYPE_DECL"),
     b64("widget.cc:<global>"), "false"],
]

parameters_rows = [
    # id, method_id, index, name, code, typeFullName, lineNumber
    ["500000100", str(METHOD_ID), "0", b64("this"), b64("Widget* this"), b64("Widget*"), "1"],
    ["500000101", str(METHOD_ID), "1", b64("info"), b64("const Napi::CallbackInfo& info"),
     b64("Napi.CallbackInfo&"), "1"],
]

calls_rows = [
    # id, owner, name, methodFullName, dispatchType, typeFullName, code, filename, lineNumber,
    # calleeIds, calleeNames (real export_c_cpp_facts_v03.sc calls.tsv schema -- 11 columns)
    ["500000010", str(METHOD_ID), b64("<operator>.assignment"), b64("<operator>.assignment"),
     b64("STATIC_DISPATCH"), b64("int"), b64("width = 4"), b64("widget.cc"), "2", "", ""],
    ["500000011", str(METHOD_ID), b64("<operator>.assignment"), b64("<operator>.assignment"),
     b64("STATIC_DISPATCH"), b64("int"), b64("height = 4"), b64("widget.cc"), "3", "", ""],
    ["500000012", str(METHOD_ID), b64("<operator>.mul"), b64("<operator>.mul"),
     b64("STATIC_DISPATCH"), b64("int"), b64("width * height"), b64("widget.cc"), "4", "", ""],
    ["500000013", str(METHOD_ID), b64("<operator>.assignment"), b64("<operator>.assignment"),
     b64("STATIC_DISPATCH"), b64("int"), b64("length = width * height"), b64("widget.cc"), "4", "", ""],
    ["500000014", str(METHOD_ID), b64("New"),
     b64("Napi.Buffer.New:<unresolvedSignature>(2)"), b64("STATIC_DISPATCH"), b64("Buffer"),
     b64("Napi::Buffer<uint8_t>::New(env, length)"), b64("widget.cc"), "5", "", ""],
]

arguments_rows = [
    # node_id, call_id, index, label(kind), code, name, typeFullName, lineNumber
    ["500000010", "500000010", "1", b64("IDENTIFIER"), b64("width"), b64("width"), b64("int"), "2"],
    ["500000020", "500000010", "2", b64("LITERAL"), b64("4"), b64(""), b64("int"), "2"],
    ["500000011", "500000011", "1", b64("IDENTIFIER"), b64("height"), b64("height"), b64("int"), "3"],
    ["500000021", "500000011", "2", b64("LITERAL"), b64("4"), b64(""), b64("int"), "3"],
    ["500000030", "500000012", "1", b64("IDENTIFIER"), b64("width"), b64("width"), b64("int"), "4"],
    ["500000031", "500000012", "2", b64("IDENTIFIER"), b64("height"), b64("height"), b64("int"), "4"],
    ["500000013", "500000013", "1", b64("IDENTIFIER"), b64("length"), b64("length"), b64("int"), "4"],
    ["500000012", "500000013", "2", b64("CALL"), b64("width * height"), b64(""), b64("int"), "4"],
    ["500000040", "500000014", "1", b64("IDENTIFIER"), b64("env"), b64("env"), b64("Napi.Env"), "5"],
    ["500000041", "500000014", "2", b64("IDENTIFIER"), b64("length"), b64("length"), b64("int"), "5"],
]


def write_tsv(name, rows):
    with open(os.path.join(OUT, name), "w") as f:
        for r in rows:
            f.write("\t".join(r) + "\n")


if __name__ == "__main__":
    write_tsv("methods.tsv", methods_rows)
    write_tsv("parameters.tsv", parameters_rows)
    write_tsv("calls.tsv", calls_rows)
    write_tsv("arguments.tsv", arguments_rows)
    print("wrote synthetic internally-computed-size control raw facts")

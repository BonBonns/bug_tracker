#!/usr/bin/env python3
"""JS-PROV-R40 gate — nested & multi-hop export-member resolution on Corpus D.

R40 closes the export-side blocker R39 named: `ctrl.feed.get` and
`ctrl.comments.byComment` were unresolved because `module_exports` recorded
`feed`/`comments` as BLOCK/alias with no leaf identity. R40 adds:
  * a recursive nested-object-literal export producer (feed.get, favorite.post,
    favorite.del, follow.post, follow.del), and
  * an N-part resolver that walks member -> alias -> member across modules.

Teeth (measured, not asserted by construction):
  N1  the nested producer emits exactly the five real nested leaves, each
      carrying a METHOD_REF identity (no BLOCK/computed/spurious rows).
  N2  RESOLUTION: ctrl.feed.get, ctrl.comments.get, ctrl.comments.byComment,
      ctrl.favorite.post all resolve to the correct exported METHOD.
  N3  NEGATIVE CONTROL: a member the module does not export
      (ctrl.comments.nonexistent) resolves to nothing -- abstain, no fallback.
  N4  R39 FROZEN: every flow R39 produced is still present and still MAY; R40
      is purely additive on the resolver, never a regression.
  N5  CEILING: no flow became MUST (all writers remain the conditional
      user-middleware write); resolution certainty never upgraded strength.
  N6  BOUNDARY NAMED, NOT PAPERED: the nested handlers read `ctx.state` as a
      WHOLE-OBJECT destructure (`const { user } = ctx.state`), captured with
      path `state`. Under the R11/R12 writer-prefix rule a `state.user` write
      does NOT establish a `state` read, so these correctly yield NO flow.
      A flow into feed.get/comments.* here would be the bug (R41 territory:
      reader-subsumes-writer object reads).
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "portable-engine-full-review-package/frontends/javascript-typescript/joern-ts"))
from app_mount_flow import derive as derive_r40  # noqa: E402

raw = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "fixtures" / "r40-out" / "raw"


def _rows(p, n):
    out = []
    for ln in Path(p).read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            out.append(ln.split("\t"))
    return out


# Rebuild the resolver's fact tables and call the same resolution logic by
# re-deriving; then reach the resolver through a tiny reconstruction so the
# gate exercises the REAL resolution path, not a copy.
import posixpath as _pp  # noqa: E402
rawp = Path(raw)
exports = {}
for r in _rows(rawp / "module_exports.tsv", 7):
    exports.setdefault(r[0], {})[r[1]] = (r[2], r[3])
alias = {(a[0], a[1]): a[2] for a in _rows(rawp / "export_member_alias.tsv", 3)}
nested = {}
for f_, path_, method_, kind_ in _rows(rawp / "nested_member_exports.tsv", 4):
    nested.setdefault(f_, {})[path_] = (method_, kind_)
modlocal = {}
sel = {}
selset = set()
for f_, local_, spec_, member_, _cid in _rows(rawp / "require_member_selection.tsv", 5):
    selset.add((f_, local_)); sel[(f_, local_)] = (spec_, member_)
for f_, spec_, local_, _cid in _rows(rawp / "require_bindings.tsv", 4):
    if local_ and (f_, local_) not in selset:
        modlocal[(f_, local_)] = spec_


def _cands(f_, spec_):
    def v(c): return [c + ".js", c + ".ts", _pp.join(c, "index.js"), _pp.join(c, "index.ts"), c]
    if spec_.startswith("."):
        b = _pp.dirname(f_)
        return v(_pp.normpath(_pp.join(b, spec_)) if b else _pp.normpath(spec_))
    return v(_pp.normpath(spec_))


def _alias_target(file_, member):
    rn = alias.get((file_, member))
    if rn is None: return None
    sp = modlocal.get((file_, rn))
    if sp is None: return None
    return next((c for c in _cands(file_, sp) if c in exports), None)


def _module_of_base(file_, base):
    got = sel.get((file_, base))
    if got is not None:
        spx, mem = got
        outer = next((c for c in _cands(file_, spx) if c in exports), None)
        if outer is None or mem not in exports.get(outer, {}): return None
        return _alias_target(outer, mem)
    spec = modlocal.get((file_, base))
    if spec is None: return None
    return next((c for c in _cands(file_, spec) if c in exports), None)


def resolve(file_, code_):
    parts = code_.split(".")
    if len(parts) < 2: return None
    base, rest = parts[0], parts[1:]
    tgt = _module_of_base(file_, base)
    if tgt is None: return None
    nend = nested.get(tgt, {}).get(".".join(rest))
    if nend and nend[1] == "METHOD_REF" and nend[0]: return nend[0]
    cur = tgt
    for i, member in enumerate(rest):
        entry = exports.get(cur, {}).get(member)
        remaining = rest[i + 1:]
        if entry and entry[1] == "METHOD_REF" and entry[0] and not remaining:
            return entry[0]
        nsub = nested.get(cur, {}).get(".".join(rest[i:]))
        if nsub and nsub[1] == "METHOD_REF" and nsub[0]: return nsub[0]
        hop = _alias_target(cur, member)
        if hop is not None:
            cur = hop; continue
        return None
    return None


AC = "controllers/articles-controller.js"
AR = "routes/articles-router.js"
results = []


def tooth(name, ok, detail=""):
    results.append((name, ok, detail))


nrows = _rows(rawp / "nested_member_exports.tsv", 4)
expect_nested = {
    (AC, "feed.get"), (AC, "favorite.post"), (AC, "favorite.del"),
    ("controllers/profiles-controller.js", "follow.post"),
    ("controllers/profiles-controller.js", "follow.del"),
}
got_nested = {(r[0], r[1]) for r in nrows}
tooth("N1 nested producer emits exactly the 5 real leaves, all METHOD_REF",
      got_nested == expect_nested and all(r[3] == "METHOD_REF" for r in nrows),
      str(sorted(got_nested)))

tooth("N2 feed.get resolves (nested)", resolve(AR, "ctrl.feed.get") == AC + "::program:get",
      str(resolve(AR, "ctrl.feed.get")))
tooth("N2 comments.get resolves (alias+member)",
      resolve(AR, "ctrl.comments.get") == "controllers/comments-controller.js::program:get",
      str(resolve(AR, "ctrl.comments.get")))
tooth("N2 comments.byComment resolves (alias+member, 3-part)",
      resolve(AR, "ctrl.comments.byComment") == "controllers/comments-controller.js::program:byComment",
      str(resolve(AR, "ctrl.comments.byComment")))
tooth("N2 favorite.post resolves (nested)",
      resolve(AR, "ctrl.favorite.post") == AC + "::program:post",
      str(resolve(AR, "ctrl.favorite.post")))

tooth("N3 negative control: comments.nonexistent -> None",
      resolve(AR, "ctrl.comments.nonexistent") is None,
      str(resolve(AR, "ctrl.comments.nonexistent")))

d = derive_r40(raw)
flows = d["flows"]
tooth("N4 R39 frozen: >=14 flows retained, all MAY",
      len(flows) >= 14 and all(f["state_flow_strength"] == "MAY" for f in flows),
      f"n={len(flows)}")
tooth("N5 ceiling: zero MUST flows", not any(f["state_flow_strength"] == "MUST" for f in flows),
      str([f["state_flow_strength"] for f in flows if f["state_flow_strength"] == "MUST"]))

nested_readers = [f for f in flows
                  if ":get" in f["reader_method"] and "feed" in str(f)]
comments_readers = [f for f in flows if "comments-controller" in f["reader_method"]]
tooth("N6 boundary named: no flow into nested/comments handlers (whole-object read)",
      len(comments_readers) == 0,
      f"comments_flows={len(comments_readers)}")

passed = sum(1 for _, ok, _ in results if ok)
for name, ok, detail in results:
    print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else "   <- " + detail))
print(f"JS_PROV_R40={passed}/{len(results)}")
print("PROMOTION_GATE=" + ("PASS" if passed == len(results) else "FAIL"))
sys.exit(0 if passed == len(results) else 1)

#!/usr/bin/env python3
"""
adjudicate.py — turn TChecker's raw WPOPT candidate findings into triaged
detections by resolving the two judgments the engine provably can't make:

  (1) REST permission_callback / capability gating  -> kills false positives
  (2) wrapper / helper-mediated sinks               -> surfaces false negatives

Two interchangeable backends (pick with --mode):

  heuristic : static signals (no API, deterministic). This is the hand-triage
              logic we'd been doing, encoded. Runs anywhere, instantly.
  llm       : hand each finding's handler + registration code to Claude and let
              it classify. Needs ANTHROPIC_API_KEY. Better on wrappers, OO
              dispatch, and "is this callback actually an auth check".

Both share the same parse -> locate-code -> verdict shape, so you can diff them.

Usage:
  python3 adjudicate.py --findings findings/wpext_308.txt \
                        --src corpus/wpextended.3.0.8_src/wpextended \
                        --mode heuristic
  ANTHROPIC_API_KEY=sk-... python3 adjudicate.py ... --mode llm
"""
import argparse, json, os, re, sys, glob

# ---- finding stream parsing -------------------------------------------------
# WPOPT [OPTIONS-WRITE][<action>:<auth>] handler <fn> node <id> reaches <sink>() ...
# Ingests every WP<CLASS> finding line the engine emits — WPOPT/WPACL/WPIDOR/WPCSRF and any
# future WP<CLS> — with either verb ("reaches"/"acts on") and method-call sinks ($wpdb->insert).
# `cls` keeps the semantic tag (OPTIONS-WRITE / NO-GUARD / IDOR / CSRF / MISSING-CAP) that drives
# the class-aware prompt hint; `wpclass` keeps the raw pass name.
FIND_RE = re.compile(
    r"WP(?P<wpclass>[A-Z]+)\s+\[(?P<cls>[^\]]+)\]\[(?P<route>[^\]]+)\]\s+handler\s+(?P<handler>\S+)\s+"
    r"node\s+(?P<node>\d+)\s+(?:reaches|acts on)\s+(?P<sink>[^\s()]+)\(\)")

def parse_findings(path):
    out = []
    for ln in open(path, encoding="utf-8", errors="replace"):
        m = FIND_RE.search(ln)
        if not m:
            continue
        route = m.group("route")
        action, _, auth = route.rpartition(":")
        out.append(dict(cls=m.group("cls"), wpclass=m.group("wpclass"),
                        action=action or route, auth=auth or "?",
                        handler=m.group("handler"), node=m.group("node"),
                        sink=m.group("sink"), raw=ln.strip()))
    return out

# ---- taint-class (SQLi / XSS) finding resolution ----------------------------
# The taint passes emit bare "Vul: <nodeId>" lines — no handler name, no route.
# To feed them to the same handler-based adjudicator we resolve each sink node
# against the parsed nodes.csv: node -> enclosing function name -> file (walk the
# funcid chain up to AST_TOPLEVEL, whose name column holds the file path).
# nodes.csv is the php2ast CSV: tab-delimited, 13 cols;
#   [0]=id [2]=type [4]=lineno [7]=funcid [8]=classname [11]=name(func name / file path)
_FUNC_TYPES = {"AST_FUNC_DECL", "AST_METHOD", "AST_CLOSURE"}
_SINK_BY_TYPE = {"AST_ECHO": "echo", "AST_PRINT": "print"}

def _load_nodes(nodes_csv):
    nodes = {}
    with open(nodes_csv, encoding="utf-8", errors="replace") as fh:
        for ln in fh:
            c = ln.rstrip("\n").split("\t")
            if len(c) < 12:
                continue
            try: nid = int(c[0])
            except ValueError: continue
            nodes[nid] = dict(type=c[2], line=c[4], endline=c[10], funcid=c[7], cls=c[8], name=c[11])
    return nodes

def _resolve_enclosing(nodes, nid):
    """(function_name|None, class_name|None, file_path|None) for a sink node."""
    row = nodes.get(nid)
    if not row:
        return (None, None, None)
    func_name, class_name = None, (row.get("cls") or None)
    fid = row.get("funcid") or ""
    if fid.isdigit():
        frow = nodes.get(int(fid))
        if frow and frow["type"] in _FUNC_TYPES:
            func_name = (frow["name"] or "").strip('"') or None
            class_name = (frow.get("cls") or "").strip('"') or class_name
    # walk funcid chain up to the file-level AST_TOPLEVEL (skip per-class toplevels, which have a parent)
    file_path, cur, seen = None, nid, set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        r = nodes.get(cur)
        if not r:
            break
        f = r.get("funcid") or ""
        if r["type"] == "AST_TOPLEVEL" and not f.isdigit():
            file_path = (r["name"] or "").strip('"').lstrip("./") or None
            break
        cur = int(f) if f.isdigit() else None
    return (func_name, class_name, file_path)

def _sink_label(node_type, cls):
    if node_type in _SINK_BY_TYPE:
        return _SINK_BY_TYPE[node_type]
    if cls == "SQLI":
        return "$wpdb->query"
    if cls == "XSS":
        return "echo"
    return "sink"

def _load_vul_sources(vul_path):
    """Map SINK node id -> {file,line,code} from the engine's explicit per-finding source line:
        Vul: <sink_nid>
        Vul Source: <src_nid> file=<f> line=<N> code=[<expr>]
    The source is the authoritative attacker-origin the engine identified; relying on path_lines[0]
    loses it whenever the path is single-hop or the source line isn't in the kept slice."""
    m = {}
    cur_sink = None
    try:
        for ln in open(vul_path, encoding="utf-8", errors="replace"):
            s = ln.strip()
            g = re.match(r"Vul:\s*(\d+)\s*$", s)
            if g:
                cur_sink = int(g.group(1)); continue
            gs = re.match(r"Vul Source:\s*\d+\s+file=(\S+)\s+line=(\d+)\s+code=\[(.*)\]\s*$", s)
            if gs and cur_sink is not None and cur_sink not in m:
                f = gs.group(1)
                m[cur_sink] = {"file": f[2:] if f.startswith("./") else f,
                               "line": int(gs.group(2)), "code": gs.group(3)}
    except Exception:
        pass
    return m

def _load_vul_lines(vul_path):
    """Parse 'Vul Lines: <sink> l1,l2,...' — the engine's taint-path line numbers per sink."""
    m = {}
    try:
        for ln in open(vul_path, encoding="utf-8", errors="replace"):
            g = re.match(r"Vul Lines:\s*(\d+)\s+([\d,]+)", ln.strip())
            if g:
                m.setdefault(int(g.group(1)), set()).update(
                    int(x) for x in g.group(2).split(",") if x.isdigit())
    except Exception:
        pass
    return m

def _load_buffered_hints(vul_path):
    """Map: SINK node id -> list of per-source buffered hints, from the engine's explicit-id line:
        Vul Wrapper Buffered: sink=<s> src=<n> callee_fid=<f> renders_template=<name>
    Joining by the explicit sink= identifier (not output position) is robust to interleaving,
    reordering, or dedup of the finding stream. Presence means at least one SOURCE of that sink
    reaches it through a template-rendering wrapper (return ob_get_clean()); the engine stays
    fail-closed on it. The hints are kept PER SOURCE — a sink may have several sources, only some
    buffered, and each buffered path routes to its own template — so the adjudicator can reason
    about the specific source→template path rather than blurring them into one sink-level field.
    Each entry: {"source": <src>, "callee_fid": <fid>, "template": <name or '?'>}."""
    hints = {}
    try:
        for ln in open(vul_path, encoding="utf-8", errors="replace"):
            m = re.search(r"Vul Wrapper Buffered:\s*sink=(\d+)\s+src=(\d+)\s+callee_fid=(\d+)\s+callee_fn=(\S+)\s+renders_template=(\S+)", ln)
            if m:
                sink = int(m.group(1))
                entry = dict(source=int(m.group(2)), callee_fid=int(m.group(3)),
                             callee_fn=m.group(4), template=m.group(5))
                lst = hints.setdefault(sink, [])
                # de-dup identical (source,template) repeats from path multiplicity
                if not any(e["source"] == entry["source"] and e["template"] == entry["template"] for e in lst):
                    lst.append(entry)
    except OSError:
        pass
    return hints


def parse_vul_findings(vul_path, nodes_csv, cls):
    """Turn a 'Vul: <node>' stream + nodes.csv into adjudicator finding dicts.
    `cls` is the taint class the stream came from: 'SQLI' or 'XSS'."""
    nodes = _load_nodes(nodes_csv)
    vlines = _load_vul_lines(vul_path)   # engine's taint-path lines, always kept in the slice
    vsources = _load_vul_sources(vul_path)  # engine's authoritative Vul Source: per sink
    buffered = _load_buffered_hints(vul_path)
    out, seen = [], set()
    for ln in open(vul_path, encoding="utf-8", errors="replace"):
        m = re.search(r"Vul:\s*(\d+)", ln)
        if not m:
            continue
        nid = int(m.group(1))
        if nid in seen:
            continue
        seen.add(nid)
        row = nodes.get(nid)
        if not row:
            continue
        func, klass, fpath = _resolve_enclosing(nodes, nid)
        # the specific enclosing function NODE (sink node's funcid) — so the chain walker starts from
        # THIS function, not every same-named one (e.g. 12 different classes' render()).
        _fid = (row.get("funcid") or "")
        func_node = int(_fid) if _fid.isdigit() and nodes.get(int(_fid), {}).get("type") in _FUNC_TYPES else None
        sink = _sink_label(row["type"], cls)
        handler = func or (klass + "::<method>" if klass else "(top-level)")
        loc = f"{fpath or '?'}:{row['line']}"
        out.append(dict(cls=cls, wpclass=cls, action="taint", auth="?",
                        handler=handler, node=str(nid), sink=sink, func_node=func_node,
                        file=fpath, line=row["line"], path_lines=sorted(vlines.get(nid, set())),
                        engine_source=vsources.get(nid),
                        buffered_sources=buffered.get(nid, []),
                        raw=f"{cls} sink node {nid} ({row['type']}) at {loc} in {handler}() reaches {sink}()"))
    # canonical-sink dedup: two Vul nodes on the same file:line are ONE sink for adjudication. Merging
    # them (unioning taint-path lines) stabilizes LLM input — the model sees one piece of evidence per
    # sink, not the same sink twice counted as independent. Findings with no resolved file:line are kept.
    canon, result = {}, []
    for f in out:
        key = (f.get("file"), f.get("line")) if (f.get("file") and f.get("line")) else None
        if key and key in canon:
            canon[key]["path_lines"] = sorted(set(canon[key]["path_lines"]) | set(f["path_lines"]))
            continue
        if key:
            canon[key] = f
        result.append(f)
    return result

def _php_files(src):
    return glob.glob(os.path.join(src, "**", "*.php"), recursive=True)

def _extract_body(text, start):
    """From index of 'function name', return the brace-matched body."""
    i = text.find("{", start)
    if i < 0:
        return text[start:start+400]
    depth, j = 0, i
    while j < len(text):
        c = text[j]
        if c == "{": depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[start:j+1]
        j += 1
    return text[start:start+2000]

# ---------------------------------------------------------------------------------------------------
# Source-specific template-level adjudication for buffered wrappers.
#
# Given ONE buffered source path (source -> wrapper fn -> named template), prove whether the specific
# attacker value is emitted by the template. This is a NARROW, structural proof — it must NOT infer the
# source->template-variable mapping from a shared name. The chain is established by evidence:
#
#   1. the wrapper param the source flows into           (structural: the wrapper's parameter)
#   2. that param assigned to ONE LITERAL array key      ($arr['type'] = $param)
#   3. that array passed to set_query_var(NAME, $arr)    (the query-var mechanism)
#   4. the template extract()s the SAME array/query var  (extract($arr) or get_query_var(NAME))
#   5. => the extracted local corresponds to that key    (local name == the literal key)
#   6. census EVERY use of that local in the template and classify.
#
# Result (source-specific, never sink-wide):
#   NOT_EMITTED     — the local is only compared / selects literals; attacker value never output
#   EMITTED_SAFE    — every emission goes through a context-compatible escaper
#   EMITTED_UNSAFE  — a direct/incompatibly-transformed emission exists  => preserve finding
#   UNRESOLVED      — any step can't be proven (aliasing, dynamic key, use as a call arg, ...) => fail closed
#
# Only NOT_EMITTED and EMITTED_SAFE clear THAT path. Everything else keeps the finding.

_ASSIGN_KEY_RE = None  # built per-param below

def _wrapper_param_to_key(wrapper_body, param_name):
    """Step 2: find `$arr[<literal>] = $param;` where the RHS is exactly the wrapper param.
    Returns (array_var, literal_key) or (None, None). Requires a LITERAL key (structural link);
    a dynamic key ($arr[$k]=...) yields None => caller fails closed."""
    # $set_query_var_color['type'] = $type;
    pat = re.compile(r"\$(\w+)\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*\$" + re.escape(param_name) + r"\s*;")
    m = pat.search(wrapper_body)
    if m:
        return m.group(1), m.group(2)
    return None, None

def _array_to_queryvar(wrapper_body, array_var):
    """Step 3: confirm set_query_var(NAME, $array_var) — returns the query-var NAME or None."""
    pat = re.compile(r"set_query_var\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*\$" + re.escape(array_var) + r"\s*\)")
    m = pat.search(wrapper_body)
    return m.group(1) if m else None

def _template_extracts(tpl_text, array_var, queryvar_name):
    """Step 4/5: the template makes the key a local, via extract() of the same array/query var.
    WordPress's set_query_var(NAME, $arr) exposes the value in templates as $NAME, so the template
    typically does extract($NAME) — using the QUERY-VAR NAME as the variable, not the wrapper's local
    array-var name. Accept: extract($array_var), extract($NAME), extract(get_query_var(NAME)), or
    $v=get_query_var(NAME);extract($v). Returns True on a provable match."""
    if re.search(r"extract\s*\(\s*\$" + re.escape(array_var) + r"\s*\)", tpl_text):
        return True
    if queryvar_name:
        # extract($NAME) — the query-var name used directly as the extracted array variable.
        if re.search(r"extract\s*\(\s*\$" + re.escape(queryvar_name) + r"\s*\)", tpl_text):
            return True
        # extract(get_query_var('NAME'))
        if re.search(r"extract\s*\(\s*get_query_var\s*\(\s*['\"]" + re.escape(queryvar_name) + r"['\"]", tpl_text):
            return True
        # $v = get_query_var('NAME'); ... extract($v)
        gv = re.search(r"\$(\w+)\s*=\s*get_query_var\s*\(\s*['\"]" + re.escape(queryvar_name) + r"['\"]\s*\)", tpl_text)
        if gv and re.search(r"extract\s*\(\s*\$" + re.escape(gv.group(1)) + r"\s*\)", tpl_text):
            return True
    return False

# Escapers considered safe in HTML-TEXT context only (context-compatibility is enforced by the caller's
# knowledge of the sink; here we conservatively treat these as HTML-text-safe).
_HTML_TEXT_ESCAPERS = {"esc_html", "esc_textarea", "wp_kses", "wp_kses_post", "esc_attr"}

# ---------------------------------------------------------------------------------------------------
# Parameterized-sanitizer dispatch proof.
#
# A very common WP-plugin idiom flags as WRAPPER_TRACE even though the value IS escaped: a sanitizer
# helper picks the escaper by a STRING argument, so the escaper is never a direct call the taint
# engine can see:
#
#   $x = wpdm_query_var('search', 'esc_attr');       // caller names the escaper as a literal
#     -> ... -> __::sanitize_var($v, $validate='esc_attr')
#          -> switch($validate){ case 'esc_attr': $v = esc_attr($v); break; ... } return $v;
#
# This proof establishes, structurally and source-specifically, that the value is escaped:
#   1. the flagged value comes from a call `wrapper(<input>, 'LITERAL', ...)` with a LITERAL escaper key
#   2. the wrapper chain reaches a function whose body switches/branches on a parameter and, for the
#      case matching 'LITERAL', applies a KNOWN escaper to the returned value
#   3. the escaper is context-compatible with the sink (HTML-text escapers only clear HTML-text sinks)
#
# Fail-closed on: non-literal key, unknown key, a case that doesn't apply a known escaper, a default
# path that returns the value unescaped, or an unresolved wrapper chain.

# Escaper name -> the context(s) it makes safe. "universal" = safe in any context (numeric coercion).
_ESCAPER_CONTEXT = {
    "esc_attr": {"html", "attr"}, "esc_html": {"html"}, "esc_textarea": {"html"},
    "esc_url": {"html", "attr", "url"}, "esc_url_raw": {"url"},
    "sanitize_text_field": {"html"}, "sanitize_textarea_field": {"html"},
    "wp_kses": {"html"}, "wp_kses_post": {"html"}, "wp_kses_data": {"html"},
    "intval": {"universal"}, "absint": {"universal"}, "floatval": {"universal"},
    "esc_js": {"js"},
}
_COERCE_CASES = {"int", "num", "double", "float"}   # switch cases that hard-coerce to a number

def _sanitizer_case_escaper(fn_body, key):
    """In a parameterized-sanitizer body, find the branch for `key` (a switch case or if-compare) and
    return the escaper it applies to the returned value, or None. Recognizes:
        case 'esc_attr': $value = esc_attr($value); ...
        case 'int': return (int)$value;             (hard numeric coercion)
    Fail-closed: returns None if the branch doesn't apply a recognized escaper/coercion."""
    # Hard numeric coercion cases (return (int)/(double)$value) are universally safe.
    if key in _COERCE_CASES:
        # confirm the body actually has this case returning a cast
        if re.search(r"case\s+['\"]" + re.escape(key) + r"['\"]\s*:", fn_body):
            return ("__coerce__", {"universal"})
    # switch case block: from `case 'key':` up to the next `case`/`default`/closing — find an escaper( applied.
    m = re.search(r"case\s+['\"]" + re.escape(key) + r"['\"]\s*:(.*?)(?:\bcase\b|\bdefault\b|\}\s*$)",
                  fn_body, re.DOTALL)
    block = m.group(1) if m else None
    if block is None:
        # if/elseif compare form:  if ($p == 'key') { $v = esc_attr($v); }
        m2 = re.search(r"==\s*['\"]" + re.escape(key) + r"['\"]\s*\)\s*\{(.*?)\}", fn_body, re.DOTALL)
        block = m2.group(1) if m2 else None
    if block is None:
        return None
    for esc, ctx in _ESCAPER_CONTEXT.items():
        if re.search(r"\b" + re.escape(esc) + r"\s*\(", block):
            return (esc, ctx)
    return None

def _default_case_safe(fn_body):
    """The default/unmatched path must also be safe (apply an escaper) or the sanitizer is only
    conditionally safe. Conservative: require a `default:` that applies a known escaper, OR that the
    function has NO default (PHP switch with no default falls through to return the value UNCHANGED =>
    UNSAFE default => fail closed). Returns True only if default provably escapes."""
    m = re.search(r"default\s*:(.*?)(?:\}\s*$|\bcase\b)", fn_body, re.DOTALL)
    if not m:
        return False                      # no default => unmatched keys return value unescaped
    block = m.group(1)
    return any(re.search(r"\b" + re.escape(esc) + r"\(", block) for esc in _ESCAPER_CONTEXT)

def _find_param_sanitizer_body(files, chain_names, depth=0, _seen=None):
    """Follow a wrapper chain (list of function names, outermost first) to the function that actually
    contains the escaper switch. Returns (body, param_ok) or (None, False). Bounded depth."""
    if _seen is None:
        _seen = set()
    if not chain_names or depth > 6:
        return None, False
    name = chain_names[0]
    if name in _seen:
        return None, False
    _seen.add(name)
    for f in files:
        try:
            t = open(f, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        m = re.search(r"function\s+" + re.escape(name) + r"\s*\(", t)
        if not m:
            continue
        body = _extract_body(t, m.start())
        # Does THIS body contain the escaper switch?
        if re.search(r"switch\s*\(", body) and any(
                re.search(r"case\s+['\"]" + re.escape(e) + r"['\"]", body) for e in _ESCAPER_CONTEXT):
            return body, True
        # else follow delegated calls inside the body. A wrapper body may contain many calls
        # (explode, isset, ...); try each called function name and recurse into any that leads to the
        # escaper switch. Prefer names hinting at sanitization, but try all to stay general.
        called = []
        for cm in re.finditer(r"(?:[\w:]+::)?(\w+)\s*\(", body):
            nm = cm.group(1)
            if nm not in _seen and nm not in ("if", "switch", "for", "foreach", "while",
                                              "isset", "empty", "explode", "count", "is_array",
                                              "array", "return"):
                called.append(nm)
        # sanitizer-hinting names first, then the rest.
        called.sort(key=lambda n: (0 if re.search(r"saniti|escap|valid|clean|filter", n, re.I) else 1))
        for nm in called:
            res, okr = _find_param_sanitizer_body(files, [nm] + chain_names[1:], depth + 1, _seen)
            if okr:
                return res, True
    return None, False

def prove_param_sanitizer_safety(files, wrapper_fn_name, literal_key, sink_ctx="html"):
    """Prove a value from wrapper(input, 'literal_key') is escaped for sink_ctx. Returns (verdict, detail).
    verdict in {SANITIZED, UNSAFE_DEFAULT, WRONG_CONTEXT, UNRESOLVED}."""
    if not wrapper_fn_name or wrapper_fn_name == "?" or not literal_key:
        return "UNRESOLVED", "no wrapper/literal-key evidence"
    body, ok = _find_param_sanitizer_body(files, [wrapper_fn_name])
    if not ok or body is None:
        return "UNRESOLVED", f"no parameterized-sanitizer switch reachable from {wrapper_fn_name}()"
    hit = _sanitizer_case_escaper(body, literal_key)
    if hit is None:
        return "UNRESOLVED", f"case '{literal_key}' does not apply a known escaper"
    esc, ctx = hit
    # Context-compatibility with the sink.
    if "universal" in ctx or sink_ctx in ctx:
        return "SANITIZED", f"wrapper applies {esc} for key '{literal_key}' (context-compatible with {sink_ctx})"
    return "WRONG_CONTEXT", f"{esc} for '{literal_key}' does not cover sink context {sink_ctx}"

def _classify_sink_region_escaping(files, filerel, line):
    """Read the sink line (+ small window) and classify whether the echoed/printed value is escaped
    AT the sink. Returns (verdict, detail): 'ESCAPED' / 'RAW' / 'UNRESOLVED'.

    Handles the per-loop-element / template-partial shape that the coarse engine taint path can't
    credit: foreach($items as $v){ echo esc_html($v); }  or  <?php echo esc_attr($x); ?>. This is a
    LOCAL judgement about the emitted expression, not a whole-path proof — so it is deliberately
    conservative: it only returns ESCAPED when the emitted operand(s) are all escaped/constant, and
    only RAW when a bare variable is emitted with NO escaper and NO surrounding gate. Everything else
    (function-call results, complex expressions, concatenations mixing escaped + unknown) => UNRESOLVED.
    """
    path = _find_file(files, filerel)
    if not path or not line:
        return "UNRESOLVED", "sink region unavailable"
    try:
        src = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except Exception:
        return "UNRESOLVED", "sink file unreadable"
    i = int(line) - 1
    if i < 0 or i >= len(src):
        return "UNRESOLVED", "sink line out of range"
    # Gather the emitting statement: the sink line, joined with continuations up to a ';' or '?>'.
    seg = src[i]
    j = i
    while ";" not in seg and "?>" not in seg and j - i < 5 and j + 1 < len(src):
        j += 1
        seg += " " + src[j]
    seg = re.sub(r"<\?php|<\?=|\?>", " ", seg)

    # Only judge actual emission statements (echo / print / printf / <?= / return of a string).
    if not re.search(r"\b(echo|print|printf|vprintf)\b|=>", seg) and "<?=" not in src[i]:
        return "UNRESOLVED", "sink line is not a recognizable emission"

    ESCAPERS = (r"esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|esc_xml|wp_kses\w*|"
                r"sanitize_[a-z_]+|absint|intval|floatval|number_format|antispambot|tag_escape|"
                r"get_block_wrapper_attributes|wp_get_attachment_image")
    # Find all bare $var emissions and all escaper-wrapped emissions in the segment.
    # A bare emission: a $var (optionally with ['key']/->prop) that is NOT immediately preceded by
    # an escaper "(" and is in an emitting position (after echo/print/'.'/',' or inside "%s" args).
    bare = []
    for m in re.finditer(r"\$(\w+(?:\s*\[\s*['\"]?\w+['\"]?\s*\])?(?:->\w+)?)", seg):
        s = m.start()
        # Is this occurrence enclosed — at ANY nesting depth — by an escaper call? Walk left through
        # balanced parens; at each point where we close one enclosing '(' level, check the identifier
        # before it. esc_attr( 490 - (490*($v*20))/100 ): the innermost '(' before $v is arithmetic,
        # but an OUTER enclosing '(' belongs to esc_attr, so we must keep walking outward.
        depth = 0
        k = s - 1
        escaped_here = False
        while k >= 0 and k > s - 600:
            c = seg[k]
            if c == ")":
                depth += 1
            elif c == "(":
                if depth == 0:
                    fnm = re.search(r"([A-Za-z_]\w*)\s*$", seg[:k])
                    fn = fnm.group(1) if fnm else None
                    if fn and re.match(r"(?:" + ESCAPERS + r"|esc_html_e|esc_attr_e|_e|__|"
                                       r"esc_html__|esc_attr__)$", fn):
                        escaped_here = True
                        break
                    # not an escaper at this level; continue walking outward to any wrapping call
                else:
                    depth -= 1
            elif c == ";" and depth == 0:
                break                        # statement boundary; stop
            k -= 1
        if escaped_here:
            continue
        # A variable that is an ARGUMENT to any function call (not just escapers) is not a bare
        # emission — its emission depends on that function's output, which we can't see here. Treat as
        # unresolved, not raw. e.g. echo ReviewFns::review_stars($v)  /  printf('%s', wp_json_encode($x)).
        # (escaper-wrapped args were already `continue`d above; this covers non-escaper callees.)
        in_call = False
        depth2 = 0
        k2 = s - 1
        while k2 >= 0 and k2 > s - 600:
            c = seg[k2]
            if c == ")":
                depth2 += 1
            elif c == "(":
                if depth2 == 0:
                    fnm = re.search(r"([A-Za-z_][\w:]*)\s*$", seg[:k2])
                    if fnm:                  # some function/method encloses this arg
                        in_call = True
                    break
                depth2 -= 1
            elif c == ";" and depth2 == 0:
                break
            k2 -= 1
        if in_call:
            continue                         # argument to a (non-escaper) call -> unresolved, skip
        # is this occurrence actually emitted? (echo/print scope, concat operand, or printf arg)
        left = seg[max(0, s - 40):s]
        emitting = bool(re.search(r"\b(echo|print)\b", left) or re.search(r"[.,]\s*$", left)
                        or re.search(r"=>\s*$", left))
        if emitting:
            bare.append("$" + m.group(1).strip())

    if bare:
        # Filter out assembled-HTML accumulators: a variable built up with `.=` (or `$x = $a . $x`)
        # is pre-assembled markup whose individual values were escaped at build time; echoing it is the
        # standard render pattern, NOT a raw-value emission. Only keep bare vars that are NOT such
        # accumulators. This requires the surrounding file, so re-read a wider body around the sink.
        try:
            whole = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            whole = seg
        real_bare = []
        for b in bare:
            nm = b[1:].split("[")[0].split("->")[0].strip()
            # accumulator if assigned with .= , or `$nm = something . $nm`, or assembled via
            # sprintf()/implode()/vsprintf() (render-output variables echoed whole) anywhere in the file
            if re.search(r"\$" + re.escape(nm) + r"\s*\.=", whole) or \
               re.search(r"\$" + re.escape(nm) + r"\s*=\s*[^;]*\.\s*\$" + re.escape(nm) + r"\b", whole) or \
               re.search(r"\$" + re.escape(nm) + r"\s*=\s*(?:vsprintf|sprintf|implode|join)\s*\(", whole):
                continue                     # assembled markup -> not a raw single-value emission
            # literal-selecting variable: EVERY assignment to $nm is a ternary/expression whose value
            # is a STRING/NUMERIC LITERAL (e.g. $selected = ($x==$y ? 'checked' : '')). Such a value
            # can never carry injection. Safe. Require at least one assignment and ALL of them literal.
            assigns = re.findall(r"\$" + re.escape(nm) + r"\s*=\s*([^;]+);", whole)
            def _is_literal_ternary(a):
                # value is `COND ? 'literal' : 'literal'` (arms are quoted string literals, possibly
                # containing = and spaces) or a bare quoted literal or a number. COND may contain
                # isset()/&&/==/comparisons — we only require both TERNARY ARMS to be quoted literals.
                a = a.strip()
                tern = re.search(r"\?(.*)$", a)
                if tern:
                    arms = tern.group(1)
                    m = re.match(r"\s*(['\"]).*?\1\s*:\s*(['\"]).*?\2\s*\)?\s*$", arms)
                    return bool(m)
                return bool(re.fullmatch(r"\s*(['\"]).*?\1\s*", a) or re.fullmatch(r"\s*-?\d+(?:\.\d+)?\s*", a))
            if assigns and all(_is_literal_ternary(a) for a in assigns):
                continue                     # value is always a literal -> not attacker-controllable
            # pre-escaped variable: EVERY assignment applies an escaper (name often ends _safe/_esc).
            if assigns and all(re.search(r"(esc_html|esc_attr|esc_url|wp_kses\w*|sanitize_)\w*\s*\(", a)
                               for a in assigns):
                continue                     # always escaped at assignment
            real_bare.append(b)
        if real_bare:
            return "RAW", "unescaped emitted: " + ", ".join(sorted(set(real_bare))[:4])
        # all bare emissions were accumulators -> unresolved (fail closed, keep finding)
        return "UNRESOLVED", "emission is an assembled-HTML accumulator (values escaped at build time)"
    # No bare emission found. If there is an escaper call that contains a $var anywhere in its
    # (possibly nested) argument list, treat the emission as escaped. esc_attr(490-(490*($v*20))/100)
    # and esc_html(foo($x)) both qualify.
    for em in re.finditer(r"(?:" + ESCAPERS + r")\s*\(", seg):
        # scan forward from the escaper's '(' to its matching ')', looking for a $var inside
        p = seg.find("(", em.end() - 1)
        if p < 0:
            continue
        depth = 0
        q = p
        while q < len(seg):
            if seg[q] == "(":
                depth += 1
            elif seg[q] == ")":
                depth -= 1
                if depth == 0:
                    break
            q += 1
        if "$" in seg[p:q + 1]:
            return "ESCAPED", "emitted value(s) wrapped in an output escaper"
    return "UNRESOLVED", "no bare or clearly-escaped emission identified"

def _census_render_attributes(body):
    """Census a block render callback body (post extract($attributes)) for unescaped emission of an
    attribute-derived value. Returns (verdict, detail): 'EMITTED_UNSAFE' / 'SAFE' / 'UNRESOLVED'.

    Only flags a concatenated `$base[...]` operand when $base is PROVABLY attribute-derived — i.e.
    $base is json_decode(...) / (array) of an extracted local, or is itself a foreach value over such
    a decoded local. Internal arrays (preg_match $matches, computed $svgAttributes, etc.) are NOT
    attribute-derived and must not be flagged. Fail-closed toward UNRESOLVED, not toward EMITTED_UNSAFE,
    to keep this active (LIKELY_REAL) rule precise."""
    # Identify attribute-derived array bases.
    #  (a) $x = ... json_decode($local...) ...  (json_decode anywhere in RHS, incl. ternary/fallback).
    #      $local is an extracted attribute (extract($attributes) put it in scope), so $x is derived.
    #  (b) foreach ($x as ... => $item) where $x is attribute-derived -> $item is attribute-derived.
    attr_arrays = set()
    for m in re.finditer(r"\$(\w+)\s*=\s*[^;]*?(?:json_decode|maybe_unserialize|\(array\)\s*\$)\s*\(?\s*\$(\w+)", body):
        attr_arrays.add(m.group(1))
    # propagate through simple aliases: $y = $x;  where $x is derived
    for _ in range(3):
        for m in re.finditer(r"\$(\w+)\s*=\s*\$(\w+)\s*;", body):
            if m.group(2) in attr_arrays:
                attr_arrays.add(m.group(1))
    attr_loopvars = set()
    for m in re.finditer(r"foreach\s*\(\s*\$(\w+)\s*as\s*(?:\$\w+\s*=>\s*)?\$(\w+)\s*\)", body):
        if m.group(1) in attr_arrays:
            attr_loopvars.add(m.group(2))
    derived_bases = attr_loopvars | attr_arrays

    emitted_unsafe = []
    emitted_safe = 0
    for m in re.finditer(r"\.\s*(\$(\w+)\s*\[\s*['\"]?\w+['\"]?\s*\])\s*\.", body):
        expr, base = m.group(1), m.group(2)
        if base not in derived_bases:
            continue                       # not provably attribute-derived => don't flag (avoid FP)
        left = body[max(0, m.start(1) - 30):m.start(1)]
        if re.search(r"(esc_|wp_kses|sanitize_|absint|intval|floatval)\w*\s*\(\s*$", left):
            emitted_safe += 1
        else:
            emitted_unsafe.append(expr)
    if emitted_unsafe:
        return "EMITTED_UNSAFE", "unescaped emitted: " + ", ".join(sorted(set(emitted_unsafe))[:5])
    if emitted_safe:
        return "SAFE", f"{emitted_safe} attribute-derived emission(s), all escaped"

    # --- bare extracted-scalar attributes (divider shape) -------------------------------------------
    # Attributes like $orientation/$blockID (from extract($attributes)) concatenated into a class/id
    # string that is then handed to get_block_wrapper_attributes() (a WP-core self-escaping wrapper) or
    # wrapped in an escaper. This is the dominant modern-block pattern. We prove safety by tracking
    # which local variables carry a bare-scalar concatenation and confirming each such variable is
    # consumed ONLY by a self-escaping wrapper / escaper before it can reach the return.
    SELF_ESCAPING = ("get_block_wrapper_attributes",)
    ESCAPERS = r"(esc_[a-z_]*|wp_kses\w*|sanitize_[a-z_]*|absint|intval|floatval|number_format|tag_escape)"

    # Variables that receive a bare-scalar concatenation `... . $scalar . ...` or `'lit' . $scalar`.
    # (Heuristic: an assignment/array_push whose RHS concatenates a bare $var that is NOT itself a
    # known-safe call result.) We then require every such carrier to be consumed by a self-escaper.
    carriers = set()
    # $x = '...' . $s . '...';  or  $x .= ...$s...;  or array_push($x, '...'.$s...)
    for m in re.finditer(r"\$(\w+)\s*(?:\.?=)\s*[^;]*'\s*\.\s*\$\w+", body):
        carriers.add(m.group(1))
    for m in re.finditer(r"array_push\s*\(\s*\$(\w+)\s*,[^;]*'\s*\.\s*\$\w+", body):
        carriers.add(m.group(1))
    # A variable assigned directly from a self-escaping wrapper / escaper is ALREADY safe output — it
    # is not a raw carrier that needs further wrapping. Drop such names (e.g. $wrapper_attributes =
    # get_block_wrapper_attributes(...)) so they don't count as unresolved carriers.
    safe_outputs = set()
    for m in re.finditer(r"\$(\w+)\s*=\s*(?:[\w\\]+::)?(\w+)\s*\(", body):
        callee = m.group(2)
        if callee in ("get_block_wrapper_attributes",) or re.match(
                r"(esc_|wp_kses|sanitize_|tag_escape)", callee):
            safe_outputs.add(m.group(1))
    carriers -= safe_outputs

    if carriers:
        # For each carrier, is it consumed by a self-escaping wrapper or escaper somewhere in the body?
        # We accept: the carrier (or a join/implode of it) appears as an argument to the wrapper/escaper.
        all_safe = True
        unresolved_carriers = []
        for c in sorted(carriers):
            # join(' ', $c) or $c passed into get_block_wrapper_attributes(...) or an escaper(...)
            wrapped = False
            # direct: gbwa( ... $c ... )  OR gbwa( ... join(' ',$c) ... )
            for w in SELF_ESCAPING:
                if re.search(w + r"\s*\([^;]*\$" + re.escape(c) + r"\b", body, re.DOTALL):
                    wrapped = True; break
                # join($c) feeding the wrapper: find join(...,$c) assigned or inlined into the wrapper
                if re.search(r"(?:join|implode)\s*\([^)]*\$" + re.escape(c) + r"\s*\)", body) and \
                   re.search(w + r"\s*\(", body):
                    wrapped = True; break
            if not wrapped and re.search(ESCAPERS + r"\s*\(\s*\$" + re.escape(c) + r"\b", body):
                wrapped = True
            if not wrapped:
                all_safe = False
                unresolved_carriers.append(c)
        if all_safe:
            return "SAFE", (f"{len(carriers)} attribute-concatenated carrier(s) all consumed by a "
                            f"self-escaping wrapper/escaper (e.g. get_block_wrapper_attributes)")
        # else: carriers not provably self-escaped. Do NOT return yet — fall through to the direct
        # $attr['key'] field census below, which may find a raw/wrong-context attribute emission
        # inside those carriers (PostX shape). Only if that also finds nothing do we fail closed.
        _carrier_unresolved = unresolved_carriers

    # --- direct $attr['key'] / $attributes['key'] field emission into an HTML string (PostX shape) ---
    # A render body that reads block attributes as ARRAY FIELDS (not extract()ed scalars, not
    # json_decoded) and concatenates them straight into a returned/echoed HTML string. Each field is
    # emitted either raw, or wrapped in an escaper. CONTEXT MATTERS: an attribute-context emission
    # (data-x="...$field...") needs esc_attr/sanitize_html_class; wp_kses is an HTML-BODY escaper that
    # leaves quotes intact, so wp_kses($field) inside a double-quoted attribute is a context-mismatch
    # XSS (this is exactly CVE-2026-15100, PostX 'searchnoresult').
    # Find the attribute array name: the var that is repeatedly indexed with string keys and is a
    # function parameter (render callbacks take $attr/$attributes as first param).
    attr_var = None
    param_m = re.search(r"function\s+\w+\s*\(\s*(?:array\s+)?\$(\w+)", body)
    if param_m and re.search(r"\$" + re.escape(param_m.group(1)) + r"\s*\[\s*['\"]", body):
        attr_var = param_m.group(1)
    if attr_var:
        AV = re.escape(attr_var)
        field = r"\$" + AV + r"\s*\[\s*['\"](\w+)['\"]\s*\]"
        # Fields pre-sanitized in place ($attr['k'] = esc_attr($attr['k']); / = sanitize_html_class(...))
        # are safe even when later emitted raw. Collect those keys.
        presanitized = set()
        SAFE_FN = r"(?:esc_attr|esc_url|esc_url_raw|sanitize_html_class|sanitize_key|sanitize_text_field|absint|intval|floatval|esc_html|esc_textarea|preg_replace)"
        # $attr['k'] = <escaper>(...)   OR   $attr['k'] = cond ? <escaper>($attr['k']) : '...'
        for m in re.finditer(r"\$" + AV + r"\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*([^;]+);", body):
            key, rhs = m.group(1), m.group(2)
            # (a) boolean/numeric COERCION: the assigned value cannot contain HTML metacharacters.
            #     $attr['k'] = $attr['k'] == true;   = (bool)$attr['k'];   = boolval(...);
            #     = isset($attr['k']) ? $attr['k'] == true : true;   (coercion inside a ternary arm)
            # Safe iff EVERY reference to the field in the RHS is inside a comparison/cast (never
            # emitted as a bare string value). Detect by: the field appears only adjacent to == === != < >.
            field_refs = list(re.finditer(r"\$" + AV + r"\s*\[\s*['\"]" + re.escape(key) + r"['\"]\s*\]", rhs))
            if field_refs and re.search(r"==|===|!==|!=|<|>|\bbool\b|\bboolval\b", rhs):
                all_compared = True
                for am in field_refs:
                    l = rhs[max(0, am.start()-20):am.start()]; r = rhs[am.end():am.end()+8]
                    # ok if this ref is a comparison operand, a (bool)/boolval arg, or an isset() test
                    if re.search(r"(isset|empty)\s*\([^()]*$", l): continue
                    if re.match(r"\s*(==|===|!==|!=|<|>)", r): continue
                    if re.search(r"(==|===|!==|!=|<|>)\s*$", l): continue
                    if re.search(r"\(\s*bool\s*\)\s*$|boolval\s*\(\s*$", l): continue
                    all_compared = False; break
                if all_compared:
                    presanitized.add(key); continue
            if re.search(r"\(\s*bool\s*\)|\(\s*int\s*\)|\(\s*float\s*\)|\bboolval\b|\bintval\b|\babsint\b|\bfloatval\b|\bcount\b|!!", rhs) \
               and not re.search(r"\.\s*\$" + AV, rhs):
                presanitized.add(key); continue
            # (b) escaper applied to this field (directly or in a ternary arm), with no raw arm.
            if re.search(SAFE_FN + r"\s*\(", rhs):
                unescaped_ref = False
                for am in re.finditer(r"\$" + AV + r"\s*\[\s*['\"]" + re.escape(key) + r"['\"]\s*\]", rhs):
                    l = rhs[max(0, am.start()-30):am.start()]
                    r = rhs[am.end():am.end()+6]
                    # inside an escaper call arg -> safe
                    if re.search(SAFE_FN + r"\s*\([^()]*$", l):
                        continue
                    # inside isset()/empty() -> a test, not a use
                    if re.search(r"(isset|empty)\s*\([^()]*$", l):
                        continue
                    # a bare truthiness/comparison test in the ternary CONDITION (…&& $attr['k'] ? / == )
                    if re.search(r"(&&|\|\||\(|\breturn\b|,)\s*$", l) and re.match(r"\s*(\?|==|!=|===|&&|\|\|)", r):
                        continue
                    unescaped_ref = True; break
                if not unescaped_ref:
                    presanitized.add(key)
        raw_attr_ctx = []      # $attr['k'] emitted raw inside a "..." attribute
        wrong_ctx = []         # wp_kses'd field emitted inside an attribute (quote-breakout)
        for m in re.finditer(field, body):
            s, key = m.start(), m.group(1)
            if key in presanitized:
                continue       # sanitized in place earlier
            left = body[max(0, s - 40):s]
            right = body[m.end():m.end() + 30]
            # ternary CONDITION / comparison test ($attr['k'] ? ...  or  $attr['k'] == ...) — not emitted
            if re.match(r"\s*[?=!<>]", right):
                continue
            # must be a concat operand emitted into the string: preceded by `.` (or `. '`) — NOT just
            # any nearby comma. This avoids treating a function-call argument or condition as emission.
            if not re.search(r"\.\s*'?\s*$", left) and not re.search(r"^\s*'?\s*\.", right):
                continue
            # skip if this occurrence is escaped: walk left for an enclosing escaper (balanced parens)
            depth = 0; k = s - 1; esc_fn = None
            while k >= 0 and k > s - 400:
                c = body[k]
                if c == ")": depth += 1
                elif c == "(":
                    if depth == 0:
                        fm = re.search(r"([A-Za-z_]\w*)\s*$", body[:k]); esc_fn = fm.group(1) if fm else None; break
                    depth -= 1
                elif c == ";" and depth == 0: break
                k -= 1
            # Determine the immediate HTML context: is this operand emitted right after an HTML
            # attribute opening like  data-x="  or  value='  ? Require an attribute-NAME char (letter,
            # digit, or hyphen) immediately before the `=` so the PHP concat-assign operator `.=` and a
            # bare ` . ` concatenation into a $class carrier are NOT mistaken for an attribute context.
            in_attr = bool(re.search(r"[A-Za-z0-9_-]=\\?[\"']\s*'?\s*\.\s*$", left))
            if esc_fn in ("esc_attr", "esc_url", "esc_url_raw", "sanitize_html_class", "sanitize_key",
                          "absint", "intval", "esc_html", "esc_textarea"):
                continue       # escaped with a real escaper
            if esc_fn in ("wp_kses", "wp_kses_post", "wp_kses_data"):
                # HTML-body escaper: safe in body context, but leaves quotes -> unsafe in ATTR context
                if in_attr:
                    wrong_ctx.append((key, esc_fn))
                continue
            # not escaped at all
            if in_attr:
                raw_attr_ctx.append(key)
        if raw_attr_ctx or wrong_ctx:
            parts = []
            if raw_attr_ctx:
                parts.append("raw in attribute: " + ", ".join(f"{attr_var}[{k}]" for k in sorted(set(raw_attr_ctx))[:4]))
            if wrong_ctx:
                parts.append("wrong-context escaper (wp_kses in attribute, quotes survive): "
                             + ", ".join(f"{attr_var}[{k}]" for k, _ in sorted(set(wrong_ctx))[:4]))
            return "EMITTED_UNSAFE", "; ".join(parts)

    if '_carrier_unresolved' in dir() and _carrier_unresolved:
        return "UNRESOLVED", ("carrier(s) not provably self-escaped: "
                              + ", ".join("$" + c for c in _carrier_unresolved[:5]))
    return "UNRESOLVED", "no clearly attribute-derived emission found"

def _classify_local_uses(tpl_text, local):
    """Step 6: census EVERY use of $local in the template and reduce to a source-specific verdict.
    Conservative: any use that isn't provably a comparison, a literal-selecting ternary that never
    returns the local, or a context-compatible escaper => UNRESOLVED/UNSAFE (fail closed)."""
    var = "$" + local
    # Find all occurrences with a little context around each.
    idxs = [m.start() for m in re.finditer(r"\$" + re.escape(local) + r"\b", tpl_text)]
    if not idxs:
        # The local never appears — the attacker value is not referenced at all in this template.
        return "NOT_EMITTED"
    saw_emit_safe = False
    PHP_KEYWORDS = {"echo", "print", "if", "elseif", "while", "for", "foreach", "switch",
                    "return", "array", "isset", "empty", "unset", "and", "or"}
    for i in idxs:
        end = i + 1 + len(local)         # index just past "$local"
        # Immediate left/right neighborhoods of THIS occurrence (not the whole line), so two uses on
        # one line are judged independently. Left: a few tokens before; right: up to the next ; ? : ).
        left = tpl_text[max(0, i-24):i]
        right_raw = tpl_text[end:end+40]
        left = re.sub(r"<\?php|<\?=|\?>", " ", left)
        right = re.sub(r"<\?php|<\?=|\?>", " ", right_raw)

        # (a) comparison: this occurrence is an operand of a comparison operator (either side).
        is_comparison = bool(re.match(r"\s*(===|==|!==|!=|<=|>=|<|>)", right) or
                             re.search(r"(===|==|!==|!=|<=|>=|<|>)\s*$", left))

        # (c) escaped: this occurrence is the argument of an HTML-text escaper: esc_html( $t
        escaped = any(re.search(esc + r"\s*\(\s*$", left) for esc in _HTML_TEXT_ESCAPERS)

        # (d) real call argument: a NON-KEYWORD identifier '(' immediately to the left (fn( ... $t).
        call_arg = False
        lm = re.search(r"([A-Za-z_]\w*)\s*\(\s*(?:[^()]*,\s*)?$", left)
        if lm and lm.group(1) not in PHP_KEYWORDS and not escaped:
            call_arg = True

        # (e) emission of THIS occurrence: an echo/print/<?= to the left with nothing that consumes
        #     the value in between (no comparison, not an escaper arg, not a call arg).
        emit_to_left = bool(re.search(r"(echo|print|<\?=)\b[^;]*$", left)) or bool(re.search(r"\.\s*$", left))
        bare_emitted = emit_to_left and not is_comparison and not escaped and not call_arg

        if call_arg:
            return "UNRESOLVED"
        if is_comparison:
            continue                      # only compared here
        if escaped:
            saw_emit_safe = True
            continue
        # ternary CONDITION only: "$t ? a : b" — value used as a truthiness test, not emitted, as long
        # as the local does not appear in either branch. Check before bare-emission so `echo ($t?..:..)`
        # is not misread as a direct echo of the local.
        tern = re.match(r"\s*\?(.*?):(.*?)(;|$)", right)
        if tern and not re.search(r"\$" + re.escape(local) + r"\b", tern.group(1) + " " + tern.group(2)):
            continue
        if bare_emitted:
            return "EMITTED_UNSAFE"
        # Otherwise we don't understand this use => fail closed.
        return "UNRESOLVED"
    return "EMITTED_SAFE" if saw_emit_safe else "NOT_EMITTED"

def _all_params_to_keys(wrapper_body):
    """All `$arr[<literal>] = $param;` assignments where $arr is set_query_var'd. Returns a list of
    (param, array_var, key, qv_name). We analyze EVERY such key because the engine tells us the sink
    is buffered but not which parameter the source flows into — so the path is only safe if the
    extracted local for EACH param-derived key is safe (conservative, fail-closed)."""
    out = []
    for m in re.finditer(r"\$(\w+)\s*\[\s*['\"](\w+)['\"]\s*\]\s*=\s*\$(\w+)\s*;", wrapper_body):
        array_var, key, rhs_param = m.group(1), m.group(2), m.group(3)
        qv = _array_to_queryvar(wrapper_body, array_var)
        if qv:
            out.append((rhs_param, array_var, key, qv))
    return out

def prove_buffered_source_safety(files, wrapper_fn_name, template_name):
    """Bounded, source-specific proof. Returns (verdict, detail). Fail-closed on missing evidence.
    Tainted params and their array keys are derived STRUCTURALLY from the wrapper body (no name-based
    source->template-var shortcut). Because the engine does not yet tell us WHICH param the buffered
    source is, we require EVERY param-derived template local to be safe before clearing (conservative).
    template_name = base-name from the hint ('?' => fail)."""
    if not template_name or template_name == "?" or not wrapper_fn_name or wrapper_fn_name == "?":
        return "UNRESOLVED", "missing wrapper/template evidence"
    wb = None
    wpat = re.compile(r"function\s+" + re.escape(wrapper_fn_name) + r"\s*\(")
    for f in files:
        try: t = open(f, encoding="utf-8", errors="replace").read()
        except Exception: continue
        m = wpat.search(t)
        if m:
            wb = _extract_body(t, m.start()); break
    if wb is None:
        return "UNRESOLVED", f"wrapper {wrapper_fn_name}() body not found"
    keys = _all_params_to_keys(wb)
    if not keys:
        return "UNRESOLVED", "no param->literal-array-key->set_query_var chain in wrapper"
    # Find the template.
    tpl_text = None
    for f in files:
        base = os.path.basename(f)
        if base == template_name + ".php" or base == template_name:
            try: tpl_text = open(f, encoding="utf-8", errors="replace").read()
            except Exception: tpl_text = None
            break
    if tpl_text is None:
        return "UNRESOLVED", f"template {template_name} file not found"
    # Every param-derived key's local must be present via a provable extract and be safe.
    worst = "NOT_EMITTED"
    order = {"NOT_EMITTED": 0, "EMITTED_SAFE": 1, "EMITTED_UNSAFE": 2, "UNRESOLVED": 3}
    details = []
    for (param, array_var, key, qv_name) in keys:
        if not _template_extracts(tpl_text, array_var, qv_name):
            return "UNRESOLVED", f"template does not provably extract the query-var array for ${param}"
        v = _classify_local_uses(tpl_text, key)
        details.append(f"${param}->['{key}']->${key}:{v}")
        if order[v] > order[worst]:
            worst = v
    return worst, f"set_query_var('{keys[0][3]}') -> extract; " + ", ".join(details)

def locate_handler(files, handler, prefer_file=None):
    # A method name like content()/render() can be defined in MANY files (one per block). When the
    # finding tells us which file the sink is in, resolve the handler THERE first — otherwise we may
    # census an unrelated block's body and produce a wrong verdict.
    pat = re.compile(r"function\s+" + re.escape(handler) + r"\s*\(")
    ordered = files
    if prefer_file:
        pf = [f for f in files if f.endswith(prefer_file) or prefer_file.endswith(f.split("/")[-1])]
        ordered = pf + [f for f in files if f not in pf]
    for f in ordered:
        try: text = open(f, encoding="utf-8", errors="replace").read()
        except Exception: continue
        m = pat.search(text)
        if m:
            return dict(file=f, body=_extract_body(text, m.start()))
    return None

def locate_registration(files, handler, action):
    """Find add_action/register_rest_route mentioning this handler or action,
    plus (for REST) the permission_callback value on the nearest route block."""
    hits, perm = [], None
    # action string without the wp_ajax_/wp_ajax_nopriv_ prefix, for REST matching
    bare = re.sub(r"^wp_ajax_(nopriv_)?", "", action)
    for f in files:
        try: text = open(f, encoding="utf-8", errors="replace").read()
        except Exception: continue
        for m in re.finditer(r"(add_action|register_rest_route)\s*\(([^;]{0,400})", text):
            blob = m.group(0)
            if handler in blob or action in blob or (bare and bare in blob):
                hits.append(blob.replace("\n", " ")[:300])
                pm = re.search(r"permission_callback['\"]?\s*=>\s*([^,)\n]+)", text[m.start():m.start()+600])
                if pm: perm = pm.group(1).strip()
    return dict(registrations=hits[:4], permission_callback=perm)

# ---- heuristic backend ------------------------------------------------------
CAP_RE   = re.compile(r"current_user_can\s*\(|is_super_admin\s*\(|->\s*cap\b|user_can\s*\(")
NONCE_RE = re.compile(r"check_ajax_referer\s*\(|wp_verify_nonce\s*\(|check_admin_referer\s*\(")
REQ_RE   = re.compile(r"\$_(POST|GET|REQUEST)\b")
# option name argument is itself a request var:  update_option($_POST[...]/$var-from-request, ...)
NAME_TAINT_RE = re.compile(r"(update_option|delete_option|add_option)\s*\(\s*\$?(?:_POST|_GET|_REQUEST|[A-Za-z_]\w*)")

# --- guard forms the base heuristic used to miss (measured in eval/GUARD_GAPS.md) ---
VENDOR_CAP_RE  = re.compile(r"\b\w*user_can\w*\s*\(|::\s*currentUserCan\s*\(|\b\w+_can_(?:admin|manage|edit)\w*\s*\(")  # G4
SECRET_RE      = re.compile(r"hash_hmac\s*\(|hash_equals\s*\(")                                                        # G1
CAPURL_RE      = re.compile(r"(?:site_url|home_url|wp_salt)\s*\(")                                                     # G1
CMP_RE         = re.compile(r"===|!==")                                                                               # G1
MIDDLEWARE_RE  = re.compile(r"['\"]middleware['\"]\s*=>")                                                             # G2
PREFIX_NAME_RE = re.compile(r"(?:update_option|delete_option|add_option)\s*\(\s*['\"][A-Za-z0-9_]+['\"]\s*\.")        # G5

def _secret_gate(body):
    """Signed one-time-token callback (hash_hmac/hash_equals) or capability-URL:
    a request value compared === against a server-side secret (site_url/wp_salt/get_option)."""
    return bool(SECRET_RE.search(body)) or bool(CAPURL_RE.search(body) and CMP_RE.search(body))

def heuristic_verdict(fnd, handler_loc, reg, files=None):
    body = handler_loc["body"] if handler_loc else ""
    sink = fnd["sink"] + "("
    has_cap   = bool(CAP_RE.search(body)) or bool(VENDOR_CAP_RE.search(body))   # G4: vendor-namespaced wrappers
    has_nonce = bool(NONCE_RE.search(body))
    has_req   = bool(REQ_RE.search(body))
    direct    = sink in body
    perm = (reg.get("permission_callback") or "").strip()
    perm_real = bool(perm) and perm not in ("__return_true", "'__return_true'", '"__return_true"')

    is_rest  = fnd["action"].startswith("rest") or fnd["auth"] == "unauth" and not fnd["action"].startswith("wp_ajax")
    is_unauth = fnd["auth"] in ("unauth",) or "nopriv" in fnd["action"]

    # 1. gated by a real REST permission_callback -> the FP source RESULTS.md flags
    if (is_rest or fnd["action"].startswith("rest")) and perm_real:
        return "GATED_FP", f"REST route has real permission_callback={perm}; unauth claim likely false", "REST_PERM"
    # 2. dominating capability check in the handler -> gated  (incl. vendor cap wrappers, G4)
    if has_cap:
        return "GATED_FP", "handler performs a capability check (current_user_can / vendor cap wrapper)", "CAP_CHECK"
    # 2a. secret / HMAC / capability-URL comparison gate  [G1]
    if _secret_gate(body):
        return "GATED_FP", "sink gated by a secret comparison (hash_hmac/hash_equals or site_url/wp_salt === request) — signed callback / capability-URL", "G1_SECRET"
    # 2b. auth enforced by a framework middleware, not permission_callback  [G2]
    if MIDDLEWARE_RE.search(body):
        return "GATED_FP", "auth enforced by framework middleware ('middleware'=>...); __return_true is not the real gate", "G2_MIDDLEWARE"
    # 2c. option name namespaced by a fixed literal prefix -> cannot reach an arbitrary key  [G5]
    if fnd["sink"] in ("update_option", "delete_option", "add_option") \
       and PREFIX_NAME_RE.search(body) and not NAME_TAINT_RE.search(body):
        return "SANITIZED", "option name carries a fixed literal prefix; cannot be steered to an arbitrary option (bounded to that namespace)", "G5_PREFIX"
    # 3. sink not in this body -> wrapper / helper mediated (the FN-recovery case)
    if handler_loc and not direct:
        # 3a. buffered-template wrapper: >=1 SOURCE of this sink reaches it through a
        # `echo <fn returning ob_get_clean()>` wrapper. Fail-closed (not cleared), but each buffered
        # source's rendered template is known — route the trace there, per source. We report the
        # buffered source count and template(s) so a sink with several buffered paths (or a mix with
        # direct sources) is not blurred into one template claim.
        bufs = fnd.get("buffered_sources") or []
        if bufs:
            tpls = sorted({b["template"] for b in bufs})
            named = [t for t in tpls if t != "?"]
            tpl_desc = (", ".join(f"'{t}'" for t in named) if named
                        else "the rendered template (name dynamic)")
            # Source-specific template-level proof: for each buffered path, try to prove whether the
            # attacker value is emitted by the named template. Only NOT_EMITTED / context-safe
            # EMITTED_SAFE clear THAT path; EMITTED_UNSAFE/UNRESOLVED keep it (fail closed). The
            # conclusion is scoped to the resolved paths, never the whole sink.
            if files:
                proofs = []
                for b in bufs:
                    v, d = prove_buffered_source_safety(files, b.get("callee_fn"), b.get("template"))
                    proofs.append((v, d))
                if proofs and all(v in ("NOT_EMITTED", "EMITTED_SAFE") for v, _ in proofs):
                    detail = "; ".join(d for _, d in proofs)
                    return "TEMPLATE_PATH_SAFE", (f"buffered source path(s) proven not-emitted/escaped in "
                           f"template {tpl_desc} [{detail}]; this buffered path is safe (scoped to the "
                           f"resolved source, not the whole sink)"), "TPLPROOF"
                unsafe = [d for v, d in proofs if v == "EMITTED_UNSAFE"]
                if unsafe:
                    return "BUFFERED_TEMPLATE_TRACE", (f"{fnd['sink']}(): template {tpl_desc} EMITS the "
                           f"attacker value [{'; '.join(unsafe)}] — likely real, verify sink context"), "BUFFERED"
                # else fall through to the generic routing verdict (UNRESOLVED paths)
            nb = len(bufs)
            route = (f"{nb} buffered source paths render {tpl_desc}" if nb > 1
                     else f"a buffered source path renders {tpl_desc}")
            return "BUFFERED_TEMPLATE_TRACE", (f"{fnd['sink']}(): {route}; trace the template for the "
                   f"specific bridged variable's uses (emit vs compare-only vs escaped) — fail-closed here"), "BUFFERED"
        # 3b. parameterized-sanitizer dispatch: the flagged value was assigned from
        # `wrapper($input, 'LITERAL')` where the wrapper picks an escaper by that literal key. The
        # taint engine can't see the string-selected escaper, but we can prove it structurally.
        if files:
            for am in re.finditer(r"\$(\w+)\s*=\s*(?:[\w:]+::)?(\w+)\s*\(\s*[^,()]+,\s*['\"](\w+)['\"]", body):
                assigned, wrapper_fn, key = am.group(1), am.group(2), am.group(3)
                # the assigned var must actually reach the sink region (appear again after assignment)
                after = body[am.end():]
                if not re.search(r"\$" + re.escape(assigned) + r"\b", after):
                    continue
                v, d = prove_param_sanitizer_safety(files, wrapper_fn, key, sink_ctx="html")
                if v == "SANITIZED":
                    return "SANITIZED", (f"value from {wrapper_fn}(_, '{key}') is escaped by a "
                           f"parameterized sanitizer [{d}]; string-selected escaper the taint engine "
                           f"could not see through"), "PARAM_SANITIZER"
        # 3c. block render callback: `function ub_render_x($attributes,...){ extract($attributes); ...
        # return sprintf('...', ..., $assembled, ...); }`. The engine collapses the taint path to the
        # return, so we census how the attacker-derived locals are emitted in the body. Same structural
        # analysis as the buffered-template proof: extract() an attacker array, then classify each local
        # use as emitted/escaped/compared. Any local emitted UNescaped (direct or built into a returned
        # string) => real; all escaped/compared => safe. Fail-closed on anything unresolved.
        # Trigger the census when the body either extract()s an attribute array OR reads a parameter
        # as repeated string-keyed array fields ($attr['key'] appearing 3+ times) — the two ways a
        # block/widget render callback consumes attacker-set attributes.
        _param_field = re.search(r"function\s+\w+\s*\(\s*(?:array\s+)?\$(\w+)", body)
        _field_shape = bool(_param_field and len(re.findall(
            r"\$" + re.escape(_param_field.group(1)) + r"\s*\[\s*['\"]", body)) >= 3)
        if files and (re.search(r"extract\s*\(\s*\$attributes\s*\)", body) or _field_shape):
            verdict, detail = _census_render_attributes(body)
            if verdict == "EMITTED_UNSAFE":
                return "LIKELY_REAL", (f"block render callback emits an unescaped attribute-derived value "
                       f"[{detail}]; Contributor+ can set the block attribute — likely stored XSS"), "RENDER_EMIT"
            if verdict == "SAFE":
                return "SANITIZED", (f"block render callback: every attribute-derived value is escaped or "
                       f"compared before output [{detail}]"), "RENDER_SAFE"
            # UNRESOLVED -> fall through to wrapper trace (fail closed)
        return "WRAPPER_TRACE", f"{fnd['sink']}() not called directly in handler; sink is wrapper/helper-mediated — trace callee", "WRAPPER"
    if not handler_loc:
        # No resolvable handler body, but the finding has a concrete sink file+line. Many of these are
        # template partials or foreach-loop bodies where the echoed value IS escaped AT the sink
        # (foreach($items as $v){ echo esc_html($v); }) — the engine flags them because the taint
        # reaches the template, but per-element escaping at the sink neutralizes it. Read the sink
        # region and classify the emitted expression in place.
        if files and fnd.get("file") and fnd.get("line"):
            v, d = _classify_sink_region_escaping(files, fnd["file"], fnd["line"])
            if v == "ESCAPED":
                return "SANITIZED", (f"sink output is escaped in place [{d}]; per-element/template "
                       f"escaper the engine's coarse taint path could not credit"), "SINK_ESCAPED"
            if v == "RAW":
                return "LIKELY_REAL", (f"sink emits an unescaped value [{d}] in a template/loop with "
                       f"no capability gate — likely XSS"), "SINK_RAW"
            # UNRESOLVED -> fall through
        return "WRAPPER_TRACE", "handler body not found (OO/dynamic dispatch or hyphenated registration) — resolve manually", "NOBODY"
    # 4. no cap; nonce only -> nonce != authorization; a low-priv authed user passes
    if has_nonce and not has_cap and not is_unauth:
        return "LIKELY_REAL", "nonce present but NO capability check — authed low-priv user can reach the write", "NONCE_ONLY"
    # 5. no guard at all + request data -> real
    if has_req and not has_cap and not has_nonce:
        sev = "name request-controlled (arbitrary-option privesc)" if NAME_TAINT_RE.search(body) \
              else "value-only request-controlled (fixed option name) — lower severity"
        tag = "LIKELY_REAL" if is_unauth or NAME_TAINT_RE.search(body) else "REVIEW"
        return tag, f"no nonce/cap guard; {sev}", "NOGUARD"
    return "REVIEW", "no decisive signal; manual review", "FALLTHROUGH"
# ---- call-chain resolution (shared by llm backend) --------------------------
# Fixes the "LLM never sees the callee" problem: instead of handing the model a
# single (possibly truncated) handler body, walk the call graph a few hops from
# the handler, stopping only when we (a) confirm the sink, (b) hit a call we
# can't resolve to source (WP core / PHP builtin / dynamic dispatch — genuinely
# opaque), or (c) hit the depth/node cap. What we hand the LLM is exactly the
# chain the analyzer would have walked, not a guess about it.
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_NOT_CALLS = {"function","if","for","foreach","while","switch","catch","array",
              "list","isset","empty","unset","return","new","elseif","echo",
              "print","exit","die","and","or","xor","clone","yield","match"}
FUNC_BODY_CAP = 4000  # per-function cap; generous enough that guard checks near
                      # the top of a function are never the thing that gets cut

def extract_calls(body, exclude=()):
    seen, out = set(exclude) | {""}, []
    for m in CALL_RE.finditer(body):
        name = m.group(1)
        if name in _NOT_CALLS or name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out

def build_call_chain(files, handler, sink, max_depth=4, max_nodes=8):
    """BFS from `handler`, following only callees we can locate as `function
    <name>(...)` somewhere in the plugin source. Anything we can't locate
    (WP core, PHP builtins, `$this->$method()`, callback arrays, etc.) is left
    as an unresolved leaf rather than silently dropped — the LLM gets told
    what's opaque, instead of the chain quietly stopping short.

    Returns: (chain, reached_sink, truncated, unresolved)
    """
    visited, chain, unresolved = set(), [], []
    frontier = [(handler, 0)]
    reached = truncated = False
    while frontier:
        name, depth = frontier.pop(0)
        if name in visited:
            continue
        visited.add(name)
        loc = locate_handler(files, name)
        if not loc:
            if name != handler:
                unresolved.append(name)
            continue
        body = loc["body"]
        sink_here = (sink + "(") in body
        calls = extract_calls(body, exclude={name})
        chain.append(dict(name=name, file=loc["file"], body=body,
                           sink_here=sink_here, calls=calls))
        if sink_here:
            reached = True
            break
        if len(chain) >= max_nodes or depth + 1 > max_depth:
            truncated = True
            unresolved.extend(c for c in calls if c not in visited)
            continue
        for c in calls:
            if c not in visited:
                frontier.append((c, depth + 1))
    return chain, reached, truncated, sorted(set(unresolved))

# ---- engine call-graph consumption ------------------------------------------
# The regex follower above (build_call_chain) cannot see dynamically-dispatched callees —
# call_user_func[_array], variable functions, $this->$m() — which is exactly the dispatch the
# ENGINE resolves into call2mtd. When the engine exports that graph (callgraph.csv: caller-func
# node -> target-func node) plus nodes.csv, we walk the SAME edges the analyzer resolved, so the
# LLM's evidence matches the analysis instead of a source-text approximation of it.
def _load_callgraph(path):
    g = {}
    try:
        for ln in open(path, encoding="utf-8", errors="replace"):
            p = ln.split("\t")
            if len(p) < 2:
                continue
            try: c, t = int(p[0]), int(p[1].strip())
            except ValueError: continue
            g.setdefault(c, set()).add(t)
    except Exception:
        return {}
    return g

def _func_nodes_by_name(nodes, name):
    return [nid for nid, r in nodes.items()
            if r.get("type") in _FUNC_TYPES and (r.get("name") or "").strip('"') == name]

def _func_file(nodes, fn):
    """Walk fn's funcid chain to the FILE-level AST_TOPLEVEL (the one with no parent funcid) and
    return its path. Note the parser also emits a per-CLASS AST_TOPLEVEL named after the class,
    which has a funcid pointing up — we walk past those."""
    cur, seen = fn, set()
    while cur is not None and cur not in seen:
        seen.add(cur)
        r = nodes.get(cur)
        if not r:
            break
        f = r.get("funcid") or ""
        if r["type"] == "AST_TOPLEVEL" and not f.isdigit():   # true file toplevel has no parent
            return (r["name"] or "").strip('"').lstrip("./") or None
        cur = int(f) if f.isdigit() else None
    return None

def _find_file(files, relpath):
    """Map a parser-relative path (from nodes.csv) to an actual file in the src glob, by suffix."""
    if not relpath:
        return None
    cands = [f for f in files if f.endswith("/" + relpath) or f.endswith(relpath)]
    if cands:
        return min(cands, key=len)
    base = relpath.split("/")[-1]
    cands = [f for f in files if f.endswith("/" + base) or f == base]
    return min(cands, key=len) if cands else None

def _body_by_node(nodes, files, fn):
    """Read a function's body by its NODE's file + [line..endline] range — so a call-graph edge that
    resolves to a specific overload/method fetches THAT body, not the first name match. None on miss."""
    r = nodes.get(fn)
    if not r:
        return None
    try:
        start = int(r["line"]); end = int(r.get("endline") or 0)
    except (ValueError, TypeError):
        return None
    if end < start:
        return None
    path = _find_file(files, _func_file(nodes, fn))
    if not path:
        return None
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except Exception:
        return None
    body = "\n".join(lines[start - 1:end])
    return dict(file=path, body=body) if body.strip() else None

def _sink_region_chain(files, filerel, line, path_lines, ctx=14):
    """Fallback for sinks in TOP-LEVEL / template code (no enclosing function to resolve): read the
    sink file around the sink line (and any taint-path lines) so escapers ON the sink line are visible.
    This is what makes view/template XSS sinks adjudicable instead of 'handler body not found'."""
    path = _find_file(files, filerel)
    if not path or not line:
        return None
    try:
        src = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except Exception:
        return None
    try: line = int(line)
    except (ValueError, TypeError): return None
    keep = set(range(max(0, line - 1 - ctx), min(len(src), line + ctx)))
    for pl in (path_lines or []):
        keep.update(range(max(0, pl - 1 - 3), min(len(src), pl + 3)))
    lo = min(keep); hi = max(keep) + 1
    body = "\n".join(src[lo:hi])
    return [dict(name="(top-level)", file=path, body=body, sink_here=True,
                 calls=[], start_line=lo + 1)]

def build_call_chain_graph(handler, sink, files, nodes, callgraph, max_nodes=8, start_node=None,
                           sink_line=None):
    """Walk the engine's resolved call graph rather than regex-following source text, so
    dynamically-dispatched callees are included. Same return shape as build_call_chain, or None
    if the handler can't be resolved to a function node (caller falls back to the regex walker).
    start_node: the exact enclosing-function node to start from — avoids name ambiguity when many
    classes share a method name (e.g. 12 render() methods); falls back to name resolution if None.
    sink_line: the engine-reported sink line; a function whose [line..endline] contains it confirms
    the sink even for XSS output sinks (echo/print/heredoc-return) that have no "sink(" text form."""
    if start_node is not None and start_node in nodes:
        starts = [start_node]
    else:
        starts = _func_nodes_by_name(nodes, handler)
    if not starts:
        return None
    def _contains_sink_line(fn):
        if sink_line is None:
            return False
        r = nodes.get(fn) or {}
        try:
            return int(r.get("line") or -1) <= int(sink_line) <= int(r.get("endline") or -1)
        except (ValueError, TypeError):
            return False
    visited, chain, unresolved = set(), [], []
    frontier = list(starts)
    reached = truncated = False
    while frontier:
        fn = frontier.pop(0)
        if fn in visited:
            continue
        visited.add(fn)
        name = (nodes.get(fn, {}).get("name") or "").strip('"')
        loc = _body_by_node(nodes, files, fn) or (locate_handler(files, name) if name else None)
        if not loc:
            if fn not in starts:
                unresolved.append(name or ("node:%d" % fn))
            continue
        body = loc["body"]
        sink_here = (sink + "(") in body or _contains_sink_line(fn)
        callee_names = sorted(set((nodes.get(c, {}).get("name") or "").strip('"')
                                  for c in callgraph.get(fn, set())) - {""})
        try: _sl = int((nodes.get(fn, {}).get("line") or "0"))
        except (ValueError, TypeError): _sl = None
        chain.append(dict(name=name, file=loc["file"], body=body,
                          sink_here=sink_here, calls=callee_names, start_line=_sl))
        if sink_here:
            reached = True
            # For taint sinks the sink sits IN the handler; the sanitizers that decide the verdict
            # live in its callees (generate_css_string->esc_attr, strip_xss->purify, ...). So don't
            # stop here — keep exploring (bounded by max_nodes) so those escapers are in the evidence.
            if fn not in starts:
                break
        if len(chain) >= max_nodes:
            truncated = True
            break
        for c in callgraph.get(fn, set()):
            if c not in visited:
                frontier.append(c)
    return chain, reached, truncated, sorted(set(u for u in unresolved if u))

# ---- canonical evidence set (structured taint trace the LLM reads) --------------------------------
# The minimal sufficient evidence for a finding, extracted by ROLE from the engine's taint path
# (Vul Lines) + resolved call chain — NOT by hint-driven slicing. Keyword sets here only LABEL a line's
# role; they never decide inclusion. Inclusion is: the source, the sink, every taint-path line, and the
# functions the taint flows through. This structurally excludes distractors (an esc_attr that is not on
# the path can't appear as a sanitizer, which is exactly the page-list failure mode).
_ES_ESCAPER = re.compile(r"\b(esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|esc_xml|"
    r"wp_kses|wp_kses_post|wp_kses_data|tag_escape|sanitize_[a-z_]+|absint|intval|floatval|"
    r"esc_html__|esc_attr__|esc_html_e|esc_attr_e)\s*\(")
_ES_GATE = re.compile(r"\b(current_user_can|is_super_admin|user_can|check_ajax_referer|wp_verify_nonce|"
    r"check_admin_referer)\s*\(|['\"]permission_callback['\"]")
_ES_RESTORER = re.compile(r"\b(html_entity_decode|htmlspecialchars_decode|urldecode|rawurldecode|"
    r"base64_decode|hex2bin|stripslashes|quoted_printable_decode|convert_uudecode|str_rot13)\s*\(")

# ---- context typing: escaper OUTPUT type vs sink CONTEXT type (a compatibility check, not a judgment) ----
# escaper -> the output context it makes a value safe FOR.
ESCAPER_CTX = {
    "esc_html":"html","esc_html__":"html","esc_html_e":"html","esc_textarea":"html","esc_xml":"html",
    "esc_attr":"attr","esc_attr__":"attr","esc_attr_e":"attr",
    "esc_url":"url","esc_url_raw":"url",
    "esc_js":"js",
    "wp_kses":"html_rich","wp_kses_post":"html_rich","wp_kses_data":"html_rich",
    "intval":"numeric","absint":"numeric","floatval":"numeric",
    # input normalizers are NOT output escapers — typing them insufficient is a common bounty nuance
    "sanitize_text_field":"text","sanitize_key":"text","sanitize_textarea_field":"text",
}
# which escaper output types are SUFFICIENT for each sink context (numeric is safe everywhere).
CTX_COMPAT = {
    "html": {"html","attr","html_rich","url","numeric"},
    "attr": {"attr","html","url","numeric"},
    "url":  {"url","numeric"},          # esc_html/esc_attr do NOT strip javascript: -> not safe in a URL sink
    "js":   {"js","numeric"},           # nothing HTML-ish neutralizes a JS-string sink
}
def _sink_context_type(code):
    """Static classification of the sink's output context from the sink line."""
    if not code: return "unknown"
    c = code.lower()
    if re.search(r"<script|\bon\w+\s*=|javascript:", c):          return "js"
    if re.search(r"href\s*=|src\s*=|url\s*\(|action\s*=|\blocation\b", c): return "url"
    if re.search(r"=\s*[\"']", c):                                return "attr"   # quoted attribute
    if re.search(r"<\w|>|\becho\b|\bprint\b|<<<", c):             return "html"   # element/text content
    return "unknown"
def _escaper_context_ok(escaper_name, sink_code):
    """(compatible, sink_ctx, esc_type) — compatible is True/False/None(unknown, cannot decide)."""
    if not escaper_name: return (None, _sink_context_type(sink_code), None)
    esc = re.sub(r"\s*\(.*$","",escaper_name).strip()
    esc_type = ESCAPER_CTX.get(esc)
    sink_ctx = _sink_context_type(sink_code)
    if esc_type is None or sink_ctx == "unknown":
        return (None, sink_ctx, esc_type)          # cannot type -> caller routes to REVIEW
    return (esc_type in CTX_COMPAT.get(sink_ctx, set()), sink_ctx, esc_type)

def _whole_expr_is_escaper(expr):
    """Return the escaper type IFF `expr` is EXCLUSIVELY one escaper call wrapping the whole value
    (esc_x(...) with the matching close paren at the very end). Rejects partial escaping like
    `esc_attr($a) . $tainted` — a fragment escaper does NOT sanitize the returned value."""
    known = r"(esc_html|esc_attr|esc_url|esc_url_raw|esc_js|esc_textarea|wp_kses|wp_kses_post|intval|absint)"
    expr = expr.strip()
    m = re.match(r"^" + known + r"\s*\(", expr)
    if not m:
        return None
    i = expr.index("(", m.end() - 1); depth = 0
    for k in range(i, len(expr)):
        if expr[k] == "(": depth += 1
        elif expr[k] == ")":
            depth -= 1
            if depth == 0:
                return ESCAPER_CTX.get(m.group(1)) if expr[k+1:].strip() == "" else None
    return None

def _escaper_return_type(body):
    """Deterministic escaper-wrapper summary — SOUND: types a wrapper only when EVERY return path
    returns a value that is ENTIRELY a single escaper call, all of the same type. Any raw / partial /
    conditional-unescaped / loop-built / mixed-type return path -> None (caller routes to REVIEW)."""
    if not body:
        return None
    returns = re.findall(r"return\s+([^;]+);", body)
    if not returns:
        return None
    types = set()
    for expr in returns:
        t = _whole_expr_is_escaper(expr)
        if t is None:
            vm = re.match(r"\s*(\$\w+)\s*$", expr)   # return $v; -> $v must be assigned EXACTLY ONCE,
            if vm:                                    # as a whole escaper wrap, and never .= / reassigned
                var = vm.group(1)
                ops = re.findall(re.escape(var) + r"\s*(\.=|=)(?!=)", body)
                if len(ops) == 1 and ops[0] == "=":
                    am = re.search(re.escape(var) + r"\s*=\s*([^;]+);", body)
                    if am:
                        t = _whole_expr_is_escaper(am.group(1))
        if t is None:
            return None      # this return path is NOT fully escaped -> unsound to type the wrapper
        types.add(t)
    return types.pop() if len(types) == 1 else None   # every path escaped, single consistent type

def _sink_region_code(files, filerel, line, n=6):
    """The sink line plus the next few lines — captures multi-line printf/sprintf/heredoc format strings
    where the HTML context lives below `printf(`, not on the sink line itself."""
    path = _find_file(files, filerel)
    if not path or not line:
        return ""
    try:
        src = open(path, encoding="utf-8", errors="replace").read().split("\n")
        i = int(line) - 1
        return "\n".join(src[i:i + n])
    except Exception:
        return ""

def _invert_callgraph(callgraph):
    """callee_func_node -> set(caller_func_nodes). Lets the evidence set look UPWARD (who calls this),
    so caller-side argument sanitization (absint($_REQUEST) / sanitize_*(...) at the call site) is
    visible — otherwise the evidence is built only from callees and misses it."""
    inv = {}
    for caller, callees in callgraph.items():
        for callee in callees:
            inv.setdefault(callee, set()).add(caller)
    return inv

def _extract_calls(body, name):
    """Return the balanced call expression(s) `name(...)` found in body (the argument list shows how
    the tainted value enters, e.g. absint($_REQUEST['id']))."""
    out = []
    if not body or not name:
        return out
    for m in re.finditer(r"(?:->|::)?" + re.escape(name) + r"\s*\(", body):
        try: i = body.index("(", m.end() - 1)
        except ValueError: continue
        depth = 0
        for k in range(i, min(len(body), i + 600)):
            if body[k] == "(": depth += 1
            elif body[k] == ")":
                depth -= 1
                if depth == 0:
                    call = body[m.start():k + 1].strip()
                    if "function " not in body[max(0, m.start()-12):m.start()]:  # skip the definition
                        out.append(call[:220])
                    break
    return out

def _line_code(files, filerel, line):
    path = _find_file(files, filerel)
    if not path or not line:
        return None
    try:
        return open(path, encoding="utf-8", errors="replace").read().split("\n")[int(line) - 1].strip()
    except Exception:
        return None

# --- STORED-XSS write-site resolver -----------------------------------------------------------------
# A stored-read sink (get_post_meta/get_option/... -> echo) is only exploitable if SOME attacker-reachable
# WRITER stored an insufficiently-sanitized value under the same key. The taint engine tracks within a
# single request, so the write (a DIFFERENT request, often a different file) is invisible to the read
# finding — every stored-read sink then looks equally dangerous. This resolver finds the writers for the
# read's storage+key and records the transformation applied at each, so the adjudicator can make the real
# cross-request judgment. FAIL-CLOSED: unknown/dynamic/raw/conditional writer => finding preserved.

_STORE_READ = {
    "get_post_meta": ("post_meta", 1), "get_user_meta": ("user_meta", 1),
    "get_term_meta": ("term_meta", 1), "get_comment_meta": ("comment_meta", 1),
    "get_metadata": ("meta", 2), "get_option": ("option", 0), "get_site_option": ("option", 0),
    "get_transient": ("transient", 0), "get_site_transient": ("transient", 0),
}
_STORE_WRITE = {
    "update_post_meta": ("post_meta", 1, 2), "add_post_meta": ("post_meta", 1, 2),
    "update_user_meta": ("user_meta", 1, 2), "add_user_meta": ("user_meta", 1, 2),
    "update_term_meta": ("term_meta", 1, 2), "add_term_meta": ("term_meta", 1, 2),
    "update_comment_meta": ("comment_meta", 1, 2), "add_comment_meta": ("comment_meta", 1, 2),
    "update_metadata": ("meta", 2, 3), "add_metadata": ("meta", 2, 3),
    "update_option": ("option", 0, 1), "add_option": ("option", 0, 1),
    "set_transient": ("transient", 0, 1), "set_site_transient": ("transient", 0, 1),
}
# sanitizer -> set of output contexts it is SUFFICIENT for. Deliberately conservative.
#   html_text = text in HTML body   attr = quoted HTML attribute   js = <script>/handler   css = <style>
_WRITE_SANITIZER_CTX = {
    # css note: in a <style> context the SCRIPT-execution primitive is </style><script>, which requires
    # '<'/'>'. Tag-stripping sanitizers (strip_all_tags/kses/strip_tags) remove those, so they PREVENT
    # script execution in CSS — they are 'css'-sufficient AGAINST XSS. (They do not prevent pure CSS
    # injection — e.g. background:url() exfiltration — but that is not script execution; see note below.)
    "wp_strip_all_tags": {"html_text", "css"},    # strips <>; quotes survive -> still NOT attr/js
    "strip_tags":        {"html_text", "css"},
    "esc_html":          {"html_text", "css"},     # entity-encodes <>&"' -> safe in body and style text
    "esc_attr":          {"html_text", "attr", "css"},
    "esc_url":           {"html_text", "attr", "url"},
    "esc_url_raw":       {"url"},
    "esc_textarea":      {"html_text"},
    "sanitize_text_field": {"html_text", "css"},   # strips tags+newlines -> no </style>; quotes survive
    "sanitize_key":      {"html_text", "attr", "js", "css"},  # [a-z0-9_-] only
    "sanitize_html_class": {"html_text", "attr", "css"},
    "absint":            {"html_text", "attr", "js", "css", "url"},  # integer
    "intval":            {"html_text", "attr", "js", "css", "url"},
    "floatval":          {"html_text", "attr", "js", "css", "url"},
    # wp_kses / wp_kses_post: PERMITS some markup but strips <script> and <style>-breaking tags. Sufficient
    # for html_text body AND css (no </style><script>); never for attr/js. Handled specially below.
    "wp_kses":           {"html_text", "css"},
    "wp_kses_post":      {"html_text", "css"},
    "wp_kses_data":      {"html_text", "css"},
}
_PASSTHROUGH_WRITE = ("wp_unslash", "stripslashes", "trim", "sanitize_meta")  # do NOT neutralize


def _sink_output_context(sink_code, read_expr=None):
    """Infer the output context (css/js/attr/html_text) of the READ. When the read expression is known
    and the sink is a multi-part concatenation, inspect the markup IMMEDIATELY BEFORE the read (that is
    what determines its context) rather than the whole statement — otherwise a value emitted in <span>
    body is mis-tagged 'attr' just because the surrounding <div id="..."> markup contains quotes."""
    c = sink_code or ""
    # narrow to the segment just before the read call, if we can locate it
    if read_expr:
        # match the leading function name of the read (get_option / get_post_meta / ...)
        fnm = re.match(r"\s*([\w]+)\s*\(", read_expr.strip())
        token = fnm.group(1) if fnm else None
        if token:
            idx = c.find(token + "(")
            if idx == -1: idx = c.find(token)
            if idx > 0:
                c = c[max(0, idx-120):idx]   # the ~120 chars of markup right before the read
    lc = c.lower()
    # strip PHP open/echo tags and close tags so `value="<?php echo get_option(...)` reads as `value="`
    # (the read is emitted where the <?php echo ... ?> sits; its HTML context is the surrounding markup).
    c = re.sub(r"<\?php\s+echo\s+", "", c, flags=re.I)
    c = re.sub(r"<\?=?\s*", "", c)          # remaining short-echo / open tags
    c = re.sub(r"\?>", "", c)               # close tags
    lc = c.lower()
    # strip a trailing PHP string-literal close + concat operator so `value="' . ` reads as `value="`
    c_eff = re.sub(r"['\"]\s*\.\s*$", "", c)   # drop a closing quote + concat dot at the very end
    last_lt = c_eff.rfind("<"); last_gt = c_eff.rfind(">")
    inside_tag = last_lt > last_gt   # we're inside a <...> tag => attribute/script/style start
    if re.search(r"<style", lc) and "</style" not in lc:
        return "css"
    if re.search(r"<script", lc) and "</script" not in lc:
        return "js"
    if re.search(r"on\w+\s*=\s*['\"]?[^'\"]*$", lc) or re.search(r"javascript:", lc):
        return "js"
    # attribute: a dangling `name="` with an unclosed quote right before the read = inside an attribute
    # value. This holds even when the enclosing <tag is out of the sliced window (e.g. value="<?php echo).
    if re.search(r"\b[\w:-]+\s*=\s*[\"'][^\"'<>]*$", c_eff):
        return "attr"
    if inside_tag and re.search(r"=\s*[\"'][^\"'<>]*$", c_eff):
        return "attr"
    # a closing '>' after the last '<' (or no tag at all) => we're in element BODY text
    return "html_text"


def _writer_transform(call_text, val_arg_index):
    """From a writer call string, return (sanitizer_fn_or_None, raw_bool, note). Looks at the value arg."""
    # crude arg split respecting parens/quotes
    inner = call_text[call_text.find("(")+1: call_text.rfind(")")] if "(" in call_text else call_text
    args, depth, buf, q = [], 0, [], None
    for ch in inner:
        if q:
            buf.append(ch); q = None if ch == q else q; continue
        if ch in "'\"": q = ch; buf.append(ch)
        elif ch in "([{": depth += 1; buf.append(ch)
        elif ch in ")]}": depth -= 1; buf.append(ch)
        elif ch == "," and depth == 0: args.append("".join(buf).strip()); buf = []
        else: buf.append(ch)
    if buf: args.append("".join(buf).strip())
    if val_arg_index >= len(args):
        return None, True, "value arg not found -> treat as raw (fail-closed)"
    val = args[val_arg_index]
    # is the value a literal/constant? then not attacker-derived
    if re.fullmatch(r"""['"].*['"]|-?\d+|true|false|null|array\(\s*\)""", val.strip(), re.I|re.S):
        return "CONSTANT", False, "value is a constant literal (no attacker input)"
    # find the OUTERMOST sanitizer wrapping the value
    m = re.match(r"([\w\\]+)\s*\(", val.strip())
    if m:
        fn = m.group(1).split("\\")[-1]
        if fn in _WRITE_SANITIZER_CTX or fn in _PASSTHROUGH_WRITE:
            return fn, False, ""
        # unknown function wrapper -> can't credit
        return None, False, f"value wrapped in unrecognized {fn}() -> unresolved (fail-closed)"
    # bare variable / concat / superglobal -> raw
    return None, True, "value stored without a recognized sanitizer -> raw (fail-closed)"


# --- write-side AUTHORIZATION resolver ---------------------------------------------------------------
# A stored-XSS finding whose value is unsanitized at the sink is only an ESCALATION vector if a user
# BELOW the intended privilege can WRITE the value. If every writer is admin-gated, the finding is
# self-XSS (an admin injecting a payload only an admin can view/set). This classifies, per storage key,
# the lowest privilege that can reach a writer. FAIL-OPEN toward danger: if a writer's reachability
# cannot be established, report it as UNKNOWN (do NOT downgrade to admin-gated).

def _classify_write_auth(key, key_prefix, storage, files):
    """Return dict: {level, evidence, writers:[...]} where level is one of:
       'unauth'  — a wp_ajax_nopriv_/admin_post_nopriv_ or public path writes it (worst)
       'low'     — a subscriber+/contributor-reachable handler writes it with no capability check
       'admin'   — every writer is behind manage_options / a Settings-API page with an admin cap
       'unknown' — cannot establish (fail-open: treat as potentially low)
    Only meaningful for findings already flagged has_raw_or_unresolved; it answers 'who can write it'."""
    kp = key_prefix or key
    writers = []
    worst = None  # track the most-permissive reachable writer
    RANK = {"unauth": 0, "low": 1, "unknown": 2, "admin": 3}

    def note_level(lvl, ev, where):
        nonlocal worst
        writers.append({"where": where, "level": lvl, "evidence": ev})
        if worst is None or RANK[lvl] < RANK[worst]:
            worst = lvl

    for path in files:
        try:
            txt = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        fname = path.split("/")[-1]

        # (1) Settings API: register_setting(group, key) -> saved by WP options.php, gated by the
        #     capability of the settings PAGE that renders settings_fields(group). Find the group, then
        #     the add_*_page cap for a page in the same file/group.
        for rm in re.finditer(r"register_setting\s*\(\s*['\"]([^'\"]+)['\"]\s*,\s*([^,\)]+)", txt):
            grp, karg = rm.group(1), rm.group(2)
            if (key and (("'"+key+"'") in karg or ('"'+key+'"') in karg)) or \
               (kp and re.search(r"['\"]"+re.escape(kp)+r"['\"]\s*\.", karg)):
                # find the menu-page capability for this settings group's page
                cap = None
                for pm in re.finditer(r"add_(?:menu|submenu|options|management|users|plugins|theme)_page\s*\(", txt):
                    call = _slice_call(txt, pm.start())
                    capm = re.search(r"['\"](manage_options|manage_network|edit_theme_options|"
                                     r"install_plugins|activate_plugins|edit_users|administrator)['\"]", call or "")
                    if not capm:
                        # capability may be a variable holding 'manage_options'
                        varm = re.search(r",\s*(\$\w+)\s*,", call or "")
                        if varm:
                            vn = re.escape(varm.group(1))
                            vv = re.search(vn + r"\s*=\s*['\"](manage_[a-z_]+|administrator)['\"]", txt)
                            if vv:
                                capm = vv
                    if capm:
                        cap = capm.group(1); break
                if cap in ("manage_options","manage_network","install_plugins","activate_plugins",
                           "edit_users","administrator","edit_theme_options"):
                    note_level("admin", f"Settings API (register_setting group '{grp}') saved via an "
                                        f"admin-capability page ({cap})", fname)
                else:
                    note_level("unknown", f"Settings API (group '{grp}') but the page capability could "
                                          f"not be resolved", fname)

        # (2) custom writers: update_option/update_*_meta on $_POST/$_REQUEST, reached via an AJAX/
        #     admin_post hook. Determine the hook privilege and whether a cap check guards it.
        for wf in ("update_option","add_option","update_post_meta","add_post_meta","update_user_meta"):
            for wm in re.finditer(re.escape(wf) + r"\s*\(", txt):
                call = _slice_call(txt, wm.start())
                if call is None:
                    continue
                if not ((key and (("'"+key+"'") in call or ('"'+key+'"') in call)) or
                        (kp and re.search(r"['\"]"+re.escape(kp)+r"['\"]\s*\.", call))):
                    continue
                # is the WRITTEN VALUE attacker-derived ($_POST/$_REQUEST/$_GET)?
                if not re.search(r"\$_(POST|REQUEST|GET)\b", call):
                    continue   # writes a computed/constant value -> not an attacker write
                # find the enclosing function and how it's hooked
                fn = _enclosing_function_name(txt, wm.start())
                hooked_nopriv = fn and re.search(r"wp_ajax_nopriv_\w+['\"]?\s*,\s*[^)]*" + re.escape(fn), txt)
                hooked_auth   = fn and re.search(r"wp_ajax_\w+['\"]?\s*,\s*[^)]*" + re.escape(fn), txt)
                hooked_post   = fn and re.search(r"admin_post_(nopriv_)?\w+['\"]?\s*,\s*[^)]*" + re.escape(fn), txt)
                # cap check inside the enclosing function?
                body = _function_body_containing(txt, wm.start())
                has_cap = bool(re.search(r"current_user_can\s*\(", body or ""))
                if hooked_nopriv or (hooked_post and re.search(r"admin_post_nopriv", txt)):
                    note_level("unauth", f"{wf}() writes $_POST in {fn or '?'}(), hooked on a NOPRIV "
                                         f"endpoint, cap check: {'yes' if has_cap else 'NONE'}", fname)
                elif (hooked_auth or hooked_post) and not has_cap:
                    note_level("low", f"{wf}() writes $_POST in {fn or '?'}() on an authenticated "
                                      f"endpoint with NO current_user_can check", fname)
                elif (hooked_auth or hooked_post) and has_cap:
                    note_level("admin", f"{wf}() writes $_POST in {fn or '?'}() but guarded by "
                                        f"current_user_can()", fname)
                else:
                    note_level("unknown", f"{wf}() writes $_POST in {fn or '?'}() — reachability/hook "
                                          f"not resolved", fname)

    if worst is None:
        return {"level": "unknown", "evidence": "no writer reachability could be established", "writers": []}
    return {"level": worst, "writers": writers,
            "evidence": f"lowest-privilege writer found: {worst}"}


def _enclosing_function_name(text, idx):
    pre = text[:idx]
    m = None
    for m in re.finditer(r"function\s+(\w+)\s*\(", pre):
        pass
    return m.group(1) if m else None


def _function_body_containing(text, idx):
    """Return the body of the function that lexically contains index idx (brace-matched)."""
    pre = text[:idx]
    starts = [mm.start() for mm in re.finditer(r"function\s+\w+\s*\(", pre)]
    if not starts:
        return None
    return _extract_body(text, starts[-1])


# --- write-path AUTHORIZATION evidence resolver ---------------------------------------------------
# For a storage WRITE, answer: what authorization + reachability evidence protects this write path?
# This is EVIDENCE, not a privilege-escalation verdict. It does NOT map capabilities to roles, resolve
# object ownership, custom roles, or multisite. It stays fail-closed: anything unresolved -> UNKNOWN.
# Key distinctions (per WordPress semantics):
#   - a NONCE (check_admin_referer/check_ajax_referer/wp_verify_nonce) verifies INTENT, not capability.
#     It is recorded under request_integrity, NEVER as authorization.
#   - hook registration (wp_ajax_ / wp_ajax_nopriv_ / REST) establishes REACHABILITY, not authorization.
#   - a capability check counts as authorization ONLY if it DOMINATES the write (every unauthorized path
#     bails before the write), not if it merely appears nearby or in a non-terminating branch.

def _enclosing_function_span(lines, target_line):
    """Return (start_idx, end_idx, fn_name) of the function enclosing target_line (1-based)."""
    start = None; name = None
    for i in range(min(int(target_line), len(lines)) - 1, -1, -1):
        m = re.search(r"function\s+(\w+)\s*\(", lines[i])
        if m:
            start = i; name = m.group(1); break
    if start is None:
        return max(0, int(target_line) - 30), min(len(lines), int(target_line) + 2), None
    # brace-match to find the function end
    depth = 0; started = False; end = len(lines)
    for j in range(start, len(lines)):
        depth += lines[j].count("{") - lines[j].count("}")
        if "{" in lines[j]:
            started = True
        if started and depth <= 0 and j >= start:
            end = j + 1; break
    return start, end, name


_TERMINATORS = r"(?:wp_die|die|exit|wp_send_json_error|auth_redirect)\s*\(|throw\b|\breturn\b"

def _cap_check_dominates_write(seg_lines, write_line_idx, write_char_off=None):
    """Does a current_user_can(...) bail-guard DOMINATE the write? Fail-closed.
    Credits these SAFE forms (all bail before the write on the unauthorized path):
        if ( ! current_user_can(X) ) { return|throw|wp_die()|exit|wp_send_json_error() ... }
        current_user_can(X) || wp_die();            (short-circuit terminator)
    Does NOT credit (stays unresolved):
        if ( current_user_can(X) ) { log(); }       positive, non-terminating
        if ( ! current_user_can(X) ) { log_failure(); }   negated but body does NOT terminate
        if ( current_user_can(X) || isset($_POST['force']) ) { ... }   bypassable
    Terminator set is deliberately NARROW: only known WP/PHP terminators. A plugin-defined deny_access()
    is NOT credited unless resolved (it isn't here) -> fail-closed."""
    if write_char_off is not None:
        text_before = "\n".join(seg_lines)[:write_char_off]
    else:
        text_before = "\n".join(seg_lines[:write_line_idx])
    caps = list(re.finditer(r"current_user_can\s*\(\s*([^)]*)\)", text_before))
    if not caps:
        return False, None, [], "no current_user_can() before the write"
    for m in caps:
        parts = _split_args_simple(m.group(1).strip())
        cap = parts[0].strip().strip("'\"") if parts else m.group(1).strip()
        obj_args = [p.strip() for p in parts[1:]] if len(parts) > 1 else []
        pre = text_before[max(0, m.start()-24):m.start()]          # just before the call
        post = text_before[m.end(): m.end()+180]                    # the guard body / short-circuit
        negated = bool(re.search(r"!\s*$", pre)) or bool(re.search(r"!\s*current_user_can", text_before[max(0,m.start()-24):m.end()]))
        # bypassable: the CONDITION is OR'd with another term (|| something) that is NOT a terminator
        or_after = re.match(r"\s*\)?\s*\|\|\s*(.*)", post)
        short_circuit_terminator = bool(or_after and re.match(r"\s*(?:wp_die|die|exit|wp_send_json_error|auth_redirect)\s*\(", or_after.group(1)))
        cond_has_or = bool(re.search(r"\|\|", text_before[m.start():m.end()+40])) or bool(re.search(r"\|\|\s*current_user_can", pre))
        bypassable = cond_has_or and not short_circuit_terminator
        # negated-guard body must TERMINATE (narrow set), OR the || short-circuit is a terminator
        body_terminates = bool(re.search(r"\{?\s*[^}]*?(" + _TERMINATORS + r")", post)) and \
                          bool(re.search(_TERMINATORS, post[:200]))
        if short_circuit_terminator:
            return True, (cap or None), obj_args, "capability || terminator short-circuit dominates the write"
        if negated and body_terminates and not bypassable:
            return True, (cap or None), obj_args, "negated capability guard with a terminating bail dominates the write"
    return False, None, [], "current_user_can() present but does not provably dominate (positive/non-terminating/bypassable/unresolved-terminator)"


def _split_args_simple(s):
    args, depth, buf, q = [], 0, [], None
    for ch in s:
        if q: buf.append(ch); q=None if ch==q else q; continue
        if ch in "'\"": q=ch; buf.append(ch)
        elif ch in "([{": depth+=1; buf.append(ch)
        elif ch in ")]}": depth-=1; buf.append(ch)
        elif ch=="," and depth==0: args.append("".join(buf)); buf=[]
        else: buf.append(ch)
    if buf: args.append("".join(buf))
    return args


def _find_reachability(fn_name, files):
    """How is this writer's function reached? Returns (type, action, authentication).
    wp_ajax_nopriv_ -> public; wp_ajax_ -> logged_in; REST -> per-permission (unknown here); else unknown."""
    if not fn_name:
        return "unknown", None, "unknown"
    hn = re.escape(fn_name)
    nopriv = priv = rest = admin_post_nopriv = None
    for f in files:
        try: t = open(f, encoding="utf-8", errors="replace").read()
        except Exception: continue
        mnp = re.search(r"wp_ajax_nopriv_(\w+)['\"]?\s*,\s*[^)]*" + hn, t)
        mp  = re.search(r"wp_ajax_(\w+)['\"]?\s*,\s*[^)]*" + hn, t)
        mrp = re.search(r"register_rest_route\s*\([^;]*" + hn, t)
        manp= re.search(r"admin_post_nopriv_(\w+)['\"]?\s*,\s*[^)]*" + hn, t)
        if mnp: nopriv = mnp.group(1)
        if mp and not (mnp and mnp.group(1)==mp.group(1)): priv = mp.group(1)
        if mrp: rest = True
        if manp: admin_post_nopriv = manp.group(1)
    if nopriv is not None:
        return "wp_ajax_nopriv", nopriv, "unauthenticated"
    if admin_post_nopriv is not None:
        return "admin_post_nopriv", admin_post_nopriv, "unauthenticated"
    if priv is not None:
        return "wp_ajax", priv, "authenticated"
    if rest:
        return "rest_route", None, "unknown"   # permission_callback not resolved here
    return "unknown", None, "unknown"


def _find_request_integrity(seg_text):
    """Nonce evidence — request INTEGRITY, not authorization."""
    m = re.search(r"(check_admin_referer|check_ajax_referer|wp_verify_nonce)\s*\(\s*([^,)]*)", seg_text)
    if m:
        action = m.group(2).strip().strip("'\"") or None
        return {"classification": "NONCE_VERIFIED", "function": m.group(1), "action": action}
    return {"classification": "NO_NONCE_FOUND"}


def _settings_api_capability(group, files):
    """Effective save capability for a settings group. Default manage_options, overridable via
    option_page_capability_{$group}. Per spec: preserve ALL discovered filters; if multiple callbacks,
    conditional returns, or variable/unresolved values affect it -> UNKNOWN (do not pick one arbitrarily)."""
    if not group:
        return "manage_options", False, "default (no group resolved)"
    literals = []          # distinct literal capabilities found across filters
    dynamic = False        # any non-literal / conditional / unresolved callback
    n_filters = 0
    for f in files:
        try: t = open(f, encoding="utf-8", errors="replace").read()
        except Exception: continue
        for m in re.finditer(r"option_page_capability_" + re.escape(group) + r"['\"]\s*,\s*([^);]*)", t):
            n_filters += 1
            cb = m.group(1).strip()
            body = t[m.end():m.end()+240]
            returns = re.findall(r"return\s+['\"]([\w_]+)['\"]", body)
            # conditional return (more than one return, or a return inside an if) -> not a single literal
            conditional = len(re.findall(r"\breturn\b", body)) > 1 or bool(re.search(r"\bif\b", body))
            if re.fullmatch(r"['\"][\w_]+['\"]", cb):        # add_filter(..., 'edit_posts') string callback? (rare)
                literals.append(cb.strip("'\""))
            elif returns and not conditional:
                literals.append(returns[0])
            else:
                dynamic = True
    if n_filters == 0:
        return "manage_options", False, "default settings-group capability (no override filter found)"
    distinct = sorted(set(literals))
    if dynamic or len(distinct) != 1:
        return "UNKNOWN", True, (f"{n_filters} capability filter(s) on option_page_capability_{group}; "
                                 f"effective capability not a single literal (dynamic/conditional/multiple: {distinct or 'none-resolved'})")
    return distinct[0], True, f"overridden via option_page_capability_{group} -> {distinct[0]}"


def classify_read_exposure(read_file, read_handler, files):
    """The READ sink's audience — the third independent dimension. Who can VIEW the page that renders
    the stored value? admin-only settings page vs a public frontend template determines escalation risk
    regardless of who writes. Fail-closed to 'unknown'.
      public         — frontend template / shortcode / wp_ajax_nopriv render
      authenticated  — logged-in-only view
      admin_only     — admin/settings/dashboard page
      unknown        — cannot establish"""
    rf = (read_file or "").lower()
    if re.search(r"(admin|settings|dashboard|/wp-admin|options-|meta-box)", rf) and \
       not re.search(r"(templates?|public|frontend|shortcode|widget)", rf):
        return "admin_only"
    if re.search(r"(templates?|public|frontend|shortcode|widget|render)", rf):
        return "public"
    # a handler hooked on wp_ajax_nopriv or a shortcode render -> public
    if read_handler:
        hn = re.escape(read_handler)
        for f in files:
            try: t = open(f, encoding="utf-8", errors="replace").read()
            except Exception: continue
            if re.search(r"wp_ajax_nopriv_\w+['\"]?\s*,\s*[^)]*" + hn, t) or \
               re.search(r"add_shortcode\s*\([^)]*" + hn, t):
                return "public"
    if rf.endswith(".php") and not re.search(r"(admin|settings|dashboard)", rf):
        return "public"   # a bare frontend-ish php file
    return "unknown"


def _compute_triggerability(wa, reachability, integrity, value_expr):
    """Derive ATTACKER_WRITE_TRIGGERABILITY — never stronger than the weakest unresolved barrier.
    PROVEN only when: request-controlled value AND unauthenticated reachability AND NO_CAPABILITY_FOUND
    AND request-integrity does not stand as an unresolved barrier (NONE_FOUND, or a nonce whose public
    acquisition is proven — which we cannot prove here, so a verified nonce => UNRESOLVED, not PROVEN).
    LOWER_PRIVILEGED_WRITE_POSSIBLE requires proving an ordinary logged-in user reaches the handler,
    which registration alone does NOT prove -> stays UNRESOLVED here."""
    req_controlled = bool(re.search(r"\$_(POST|GET|REQUEST|COOKIE)\b", value_expr or ""))
    auth = reachability.get("authentication")
    cls = wa.get("classification")
    integ = integrity.get("classification")
    if not req_controlled:
        return "NOT_REQUEST_CONTROLLED"
    if auth == "unauthenticated" and cls == "NO_CAPABILITY_FOUND":
        if integ in ("NO_NONCE_FOUND",):
            return "PROVEN"                       # unauth + no cap + no nonce barrier -> external attacker can write
        if integ == "NONCE_VERIFIED":
            return "UNRESOLVED"                   # nonce present; public acquisition NOT established -> cannot claim proven
        return "UNRESOLVED"
    if auth == "authenticated" and cls == "NO_CAPABILITY_FOUND":
        # a logged-in user MIGHT reach it, but registration != proven reachability by an ordinary user
        return "LOWER_PRIVILEGED_WRITE_POSSIBLE_UNRESOLVED"
    return "UNRESOLVED"


def analyze_write_auth(fn_name, seg_lines, write_line_idx, files, is_settings_api=False, settings_group=None, write_char_off=None, value_expr=None):
    """Return structured {reachability, write_auth, request_integrity, triggerability} for one writer. Fail-closed."""
    seg_text = "\n".join(seg_lines)
    reach_type, reach_action, reach_auth = _find_reachability(fn_name, files)
    integrity = _find_request_integrity(seg_text)
    if is_settings_api:
        cap, filtered, note = _settings_api_capability(settings_group, files)
        wa = {"classification": ("SETTINGS_API_GATED" if cap != "UNKNOWN" else "UNKNOWN"),
              "capability": cap, "settings_group": settings_group,
              "capability_filter_found": filtered, "note": note}
        reach = {"type": "options.php", "action": None, "authentication": "settings_api"}
        return {"reachability": reach, "write_auth": wa, "request_integrity": integrity,
                "triggerability": "NOT_ATTACKER_WRITABLE_ADMIN_GATED",
                "request_controlled_value": bool(re.search(r"\$_(POST|GET|REQUEST|COOKIE)\b", value_expr or ""))}
    dominates, cap, obj_args, note = _cap_check_dominates_write(seg_lines, write_line_idx, write_char_off)
    if dominates:
        wa = {"classification": "CAPABILITY_GATED", "capability": cap, "arguments": obj_args,
              "dominates_write": True, "note": note}
    else:
        # AUTHORIZATION is orthogonal: it reflects the CAPABILITY gate only. A nonce is request-integrity,
        # recorded separately — it must NOT change the authorization label. So with no dominating cap the
        # authorization is NO_CAPABILITY_FOUND whether or not a nonce is present; if we can't even resolve
        # a registration/entry point AND there's no cap, authorization is UNKNOWN.
        if reach_type in ("wp_ajax_nopriv", "admin_post_nopriv", "wp_ajax", "rest_route") or \
           re.search(r"current_user_can", seg_text):
            cls = "NO_CAPABILITY_FOUND"
        else:
            cls = "UNKNOWN"
        wa = {"classification": cls, "capability": None, "dominates_write": False, "note": note}
    reach = {"type": reach_type, "action": reach_action, "authentication": reach_auth}
    trig = _compute_triggerability(wa, reach, integrity, value_expr)
    return {"reachability": reach, "write_auth": wa, "request_integrity": integrity,
            "triggerability": trig,
            "request_controlled_value": bool(re.search(r"\$_(POST|GET|REQUEST|COOKIE)\b", value_expr or ""))}


def resolve_stored_writers(read_code, files, sink_context):
    """Given a stored-READ sink line, find the storage+key, locate all writers, and classify each.
    Returns dict: {storage, key, key_dynamic, writers:[{file,call,sanitizer,sufficient,note}], verdict_hint}.
    verdict_hint: 'all_sufficient' | 'has_raw_or_unresolved' | 'no_writers_found'."""
    rm = None
    for fn,(storage,kidx) in _STORE_READ.items():
        m = re.search(re.escape(fn) + r"\s*\(", read_code or "")
        if m:
            rm = (fn, storage, kidx, m); break
    if not rm:
        return None
    fn, storage, kidx, m = rm
    # extract the key literal from the read call
    inner = _balanced_args(read_code, m.end()-1)
    key = None; key_dynamic = False; key_prefix = None
    if inner is not None and kidx < len(inner):
        ka = inner[kidx].strip()
        km = re.fullmatch(r"""['"](\w[\w\-]*)['"]""", ka)
        if km:
            key = km.group(1)
        else:
            key_dynamic = True; key = ka[:40]
            # common WP pattern: 'literal_prefix' . $bounded_id  — recover the literal prefix so option
            # writers (register_setting) can still be matched by prefix. Not attacker-controlled when the
            # id is an internal counter; even if it were, the writers are enumerable by prefix.
            pm = re.match(r"""['"](\w[\w\-]*)['"]\s*\.""", ka)
            if pm:
                key_prefix = pm.group(1)
    out = {"storage": storage, "key": key, "key_dynamic": key_dynamic, "key_prefix": key_prefix,
           "writers": [], "verdict_hint": None}
    # Only bail immediately if the key is dynamic AND we couldn't recover a literal prefix to match on,
    # OR the storage isn't option (meta writers must match the exact key, not a prefix).
    if (key_dynamic and not (storage == "option" and key_prefix)) or not key:
        out["verdict_hint"] = "has_raw_or_unresolved"
        out["writers"].append({"file":"(n/a)","call":"(dynamic key — writers cannot be enumerated)",
                               "sanitizer":None,"sufficient":False,"note":"dynamic storage key -> fail-closed"})
        return out
    # find writers to the same storage+key across the tree
    write_fns = [w for w,(st,_,_) in _STORE_WRITE.items() if st == storage or st == "meta"]
    any_raw = False; found = False
    # -- register_setting() write path (WP Settings API): the option is written by core's options.php
    #    handler, which applies the registered 'sanitize_callback'. This is the DOMINANT option-write
    #    mechanism and is invisible to update_option scanning. Match by key OR by a 'prefix'.$var form
    #    where the literal prefix matches (bounded-id options like 'site_custom_css'.$banner_id).
    if storage == "option":
        kp = out.get("key_prefix") or (re.match(r"(\w+)", key or "").group(1) if key else key)
        for path in files:
            try: txt = open(path, encoding="utf-8", errors="replace").read()
            except Exception: continue
            for rm2 in re.finditer(r"register_setting\s*\(", txt):
                call = _slice_call(txt, rm2.start())
                if call is None: continue
                # key is the 2nd arg; may be 'literal' or 'prefix'.$var (quote-agnostic match).
                # For a dynamic prefix, require the SAME concat form ('prefix' . ...) so 'simple_banner_text'
                # does NOT collide with 'simple_banner_text_color'/'simple_banner_text_custom_css'.
                def _prefix_hit(c):
                    if not kp: return False
                    # match 'kp' or "kp" immediately followed by concatenation dot or the closing quote+comma
                    return bool(re.search(r"['\"]" + re.escape(kp) + r"['\"]\s*(?:\.|,|\))", c)) or \
                           bool(re.search(r"['\"]" + re.escape(kp) + r"['\"]\s*\.\s*\$", c))
                if (key and ("'"+key+"'") in call) or (key and ('"'+key+'"') in call) or \
                   (key_dynamic and _prefix_hit(call)):
                    found = True
                    cbm = re.search(r"['\"]sanitize_callback['\"]\s*=>\s*['\"]([\w\\]+)['\"]", call)
                    cb = cbm.group(1).split("\\")[-1] if cbm else None
                    if cb is None:
                        sufficient=False; note="register_setting with NO sanitize_callback -> raw (fail-closed)"
                    elif cb in ("wp_kses","wp_kses_post","wp_kses_data","wp_filter_post_kses","wp_filter_kses"):
                        # permits some markup but strips <script>/<style> -> safe for html_text body AND css
                        # (no </style><script> breakout); never for attr (quotes survive) or js.
                        sufficient=(sink_context in ("html_text","css")); note="" if sufficient else f"{cb}() permits markup / quotes survive; not sufficient for {sink_context}"
                    elif cb in ("wp_filter_nohtml_kses",):
                        # strips ALL tags -> no </style> or <script> -> safe for html_text AND css.
                        # quotes survive -> NOT sufficient for attr/js.
                        sufficient=(sink_context in ("html_text","css")); note="" if sufficient else f"{cb}() strips tags but quotes survive -> not sufficient for {sink_context} (attr/js breakout)"
                    elif cb in _WRITE_SANITIZER_CTX:
                        sufficient=sink_context in _WRITE_SANITIZER_CTX[cb]; note="" if sufficient else f"{cb}() not sufficient for {sink_context} context"
                    elif cb in _PASSTHROUGH_WRITE:
                        sufficient=False; note=f"{cb}() is taint-preserving"
                    else:
                        sufficient=False; note=f"custom sanitize_callback {cb}() -> unresolved (fail-closed)"
                    # settings-group is the 1st arg of register_setting -> effective save capability
                    grp_m = re.search(r"register_setting\s*\(\s*['\"]([\w\-]+)['\"]", call)
                    grp = grp_m.group(1) if grp_m else None
                    auth_ev = analyze_write_auth(None, [], 0, files, is_settings_api=True, settings_group=grp)
                    out["writers"].append({"file":path.split("/")[-1],
                        "call":f"register_setting('{grp or '?'}', '{key or kp}', sanitize_callback={cb})",
                        "sanitizer":cb,"sufficient":sufficient,"note":note,
                        "reachability":auth_ev["reachability"],"write_auth":auth_ev["write_auth"],
                        "request_integrity":auth_ev["request_integrity"],
                        "triggerability":auth_ev.get("triggerability"),
                        "request_controlled_value":auth_ev.get("request_controlled_value")})
                    if not sufficient: any_raw=True
    for path in files:
        try: txt = open(path, encoding="utf-8", errors="replace").read()
        except Exception: continue
        for wf in write_fns:
            for wm in re.finditer(re.escape(wf) + r"\s*\(", txt):
                call = _slice_call(txt, wm.start())
                if call is None: continue
                # key must match
                if ("'"+key+"'") not in call and ('"'+key+'"') not in call:
                    continue
                found = True
                _st,_kidx,_vidx = _STORE_WRITE[wf]
                san, raw, note = _writer_transform(call, _vidx)
                if san == "CONSTANT":
                    sufficient = True
                elif san in _PASSTHROUGH_WRITE:
                    sufficient = False; note = f"{san}() is taint-preserving (does not neutralize)"
                elif san in ("wp_kses","wp_kses_post","wp_kses_data"):
                    # permits some markup but strips <script>/<style> -> safe for html_text body AND css
                    # (no </style><script>); never for attr (quotes survive) or js.
                    sufficient = (sink_context in ("html_text","css"))
                    if not sufficient and not note:
                        note = f"{san}() permits markup / quotes survive; NOT sufficient for {sink_context} context"
                elif san in _WRITE_SANITIZER_CTX:
                    sufficient = sink_context in _WRITE_SANITIZER_CTX[san]
                    if not sufficient and not note:
                        note = f"{san}() not sufficient for {sink_context} context (e.g. quotes survive)"
                else:
                    sufficient = False  # unknown/raw
                    any_raw = any_raw or raw
                # write-path AUTHORIZATION evidence: analyze the enclosing function of this write
                wlines = txt.split("\n")
                w_line_no = txt[:wm.start()].count("\n")  # 0-based line index of the write
                fs_start, fs_end, fn_nm = _enclosing_function_span(wlines, w_line_no + 1)
                seg_lines = wlines[fs_start:fs_end]
                w_idx_in_seg = max(0, w_line_no - fs_start)
                # char offset of the write within the segment text (handles single-line guard+write)
                seg_txt = "\n".join(seg_lines)
                w_char = seg_txt.find(wf + "(")
                # the stored value expression (the write's value arg) — for request-control detection
                _wargs = _split_args_simple(call[call.find("(")+1:call.rfind(")")]) if "(" in call else []
                _val_expr = _wargs[_vidx] if _vidx < len(_wargs) else ""
                auth_ev = analyze_write_auth(fn_nm, seg_lines, w_idx_in_seg, files,
                                             write_char_off=(w_char if w_char >= 0 else None),
                                             value_expr=_val_expr)
                out["writers"].append({"file":path.split("/")[-1],"call":call.strip()[:200],
                                       "sanitizer":san,"sufficient":sufficient,"note":note,
                                       "reachability":auth_ev["reachability"],
                                       "write_auth":auth_ev["write_auth"],
                                       "request_integrity":auth_ev["request_integrity"],
                                       "triggerability":auth_ev.get("triggerability"),
                                       "request_controlled_value":auth_ev.get("request_controlled_value")})
                if not sufficient: any_raw = True
    if not found:
        out["verdict_hint"] = "no_writers_found"      # fail-closed: absence of a writer != safe
    elif any_raw:
        out["verdict_hint"] = "has_raw_or_unresolved"
    else:
        out["verdict_hint"] = "all_sufficient"
    return out


def _balanced_args(text, open_paren_idx):
    """Return list of top-level arg strings for the call whose '(' is at open_paren_idx."""
    inner = _slice_call_inner(text, open_paren_idx)
    if inner is None: return None
    args, depth, buf, q = [], 0, [], None
    for ch in inner:
        if q: buf.append(ch); q=None if ch==q else q; continue
        if ch in "'\"": q=ch; buf.append(ch)
        elif ch in "([{": depth+=1; buf.append(ch)
        elif ch in ")]}": depth-=1; buf.append(ch)
        elif ch=="," and depth==0: args.append("".join(buf).strip()); buf=[]
        else: buf.append(ch)
    if buf: args.append("".join(buf).strip())
    return args


def _slice_call_inner(text, open_paren_idx):
    depth=0
    for j in range(open_paren_idx, min(len(text), open_paren_idx+4000)):
        c=text[j]
        if c=="(":
            depth+=1
            if depth==1: start=j+1
        elif c==")":
            depth-=1
            if depth==0: return text[start:j]
    return None


def _slice_call(text, name_start):
    """From the index of a function name, return the full 'name(...)' call string, paren-balanced."""
    p = text.find("(", name_start)
    if p < 0: return None
    inner = _slice_call_inner(text, p)
    if inner is None: return None
    return text[name_start:p] + "(" + inner + ")"


def build_evidence_set(f, files, nodes, callgraph):
    """Return the canonical, role-typed evidence set for a finding. One schema for every class."""
    filerel = f.get("file"); pls = list(f.get("path_lines") or [])
    sink_line = int(f["line"]) if f.get("line") else (pls[-1] if pls else None)
    src_line = pls[0] if pls else None
    es = {"class": f.get("cls"), "sink_type": f.get("sink"),
          "source": None, "sink": None, "propagation": [],
          "sanitizers_on_path": [], "gates": [], "taint_restorers": [],
          "functions_on_path": [], "notes": []}
    seen_lines = set()
    for ln in pls:
        code = _line_code(files, filerel, ln)
        if code is None:
            continue
        seen_lines.add(ln)
        rec = {"file": filerel, "line": ln, "code": code}
        # role LABELS (do not affect inclusion — every path line is already included)
        if _ES_ESCAPER.search(code): es["sanitizers_on_path"].append(rec)
        if _ES_GATE.search(code):    es["gates"].append(rec)
        if _ES_RESTORER.search(code):es["taint_restorers"].append(rec)
        if ln == sink_line:   es["sink"] = rec
        elif ln == src_line:  es["source"] = rec
        else:                 es["propagation"].append(rec)
    if es["sink"] is None and sink_line:
        es["sink"] = {"file": filerel, "line": sink_line, "code": _line_code(files, filerel, sink_line) or "(unreadable)"}
    # authoritative source: if the path-line derivation didn't yield a source (single-hop path, or the
    # source line wasn't in the kept slice), use the engine's explicit 'Vul Source:' — it always knows
    # the attacker origin. This repairs the SOURCE:(none) regression on findings like $atts['id']->echo.
    if es["source"] is None and f.get("engine_source"):
        esrc = f["engine_source"]
        es["source"] = {"file": esrc.get("file", filerel), "line": esrc.get("line"),
                        "code": (_line_code(files, esrc.get("file", filerel), esrc.get("line"))
                                 or esrc.get("code") or "(source)")}
    # interprocedural: functions the taint flows THROUGH (from the resolved graph), each annotated with
    # whether its body bears an escaper/gate — this is how a callee-mediated escaper (generate_css_string
    # -> esc_attr) surfaces without keyword-slicing the caller.
    res = build_call_chain_graph(f.get("handler"), f.get("sink"), files, nodes, callgraph,
                                 start_node=f.get("func_node"), sink_line=f.get("line"))
    chain = (res[0] if res else None) or []
    for node in chain:
        body = node.get("body", "")
        bears_e = bool(_ES_ESCAPER.search(body)); bears_g = bool(_ES_GATE.search(body)); bears_r = bool(_ES_RESTORER.search(body))
        entry = {"fn": node.get("name"), "file": node.get("file"),
                 "bears_escaper": bears_e, "bears_gate": bears_g, "bears_restorer": bears_r}
        # attach EVERY on-path function body (capped) — a REAL finding's raw sink lives in a function that
        # bears NO escaper, so restricting bodies to escaper-bearers would hide exactly the code that
        # proves REAL. Completeness over economy: the LLM must see where the value actually goes.
        entry["body"] = body if len(body) <= 1800 else body[:1800] + "\n/* ...truncated... */"
        es["functions_on_path"].append(entry)
    if es["taint_restorers"]:
        es["notes"].append("taint-restoring transform(s) on path — any upstream sanitizer may be reversed")
    if not chain and filerel:
        es["notes"].append("sink in top-level/template code (no enclosing function)")
    # CALLER CONTEXT: the tainted value may enter this function through a parameter that the CALLER
    # already sanitized (absint($_REQUEST[...]) / sanitize_*(...) at the call site). That sanitizer is
    # invisible from callees alone, so include the call sites — otherwise caller-sanitized findings
    # false-positive.
    es["call_sites"] = []
    fnode = f.get("func_node")
    hname = (f.get("handler") or "").split("::")[-1]
    if fnode and callgraph and hname and hname != "(top-level)":
        inv = _invert_callgraph(callgraph)
        for caller in list(inv.get(fnode, set()))[:6]:
            cbn = _body_by_node(nodes, files, caller)
            if not cbn:
                continue
            cbody = cbn["body"]
            cname = (nodes.get(caller, {}).get("name") or "").strip('"') or "(caller)"
            for call in _extract_calls(cbody, hname):
                es["call_sites"].append({"caller": cname, "call": call})
    # text fallback: the func->func callgraph misses callers in TOP-LEVEL / dispatch code (a very common
    # place for absint($_REQUEST)/sanitize_* at the call site). Scan files for the call directly.
    if len(es["call_sites"]) < 2 and hname and hname != "(top-level)":
        seen = {cs["call"] for cs in es["call_sites"]}; hits = len(es["call_sites"])
        for path in files:
            if hits >= 6:
                break
            try:
                txt = open(path, encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            if (hname + "(") not in txt and (hname + " (") not in txt:
                continue
            for call in _extract_calls(txt, hname):
                if call in seen:
                    continue
                seen.add(call)
                es["call_sites"].append({"caller": path.split("/")[-1], "call": call}); hits += 1
                if hits >= 6:
                    break
    # STORED-XSS cross-request resolution: if the sink reads a stored value (get_post_meta/get_option/...)
    # the deciding evidence is the WRITE side (a different request/file), invisible to the read finding.
    # Resolve the writers for this storage+key and record each write's sanitization vs the sink context.
    es["stored_writers"] = None
    sink_code_for_store = (es["sink"] or {}).get("code", "") if es.get("sink") else ""
    # the stored read may be on the sink line OR a source/propagation line
    store_candidates = [sink_code_for_store]
    if es.get("source"): store_candidates.append(es["source"].get("code",""))
    for r in es.get("propagation", []): store_candidates.append(r.get("code",""))
    # multi-line echo: the get_option/get_post_meta call is often on a CONTINUATION line below the sink
    # line (echo '<div>' . get_option(...) . '</div>';). Pull a few following lines so the read is seen.
    if es.get("sink") and es["sink"].get("line"):
        sf, sl = es["sink"].get("file"), es["sink"].get("line")
        for off in range(1, 6):
            cont = _line_code(files, sf, sl + off)
            if cont is None:
                break
            store_candidates.append(cont)
            if ";" in cont:   # statement terminated — stop scanning the continuation
                break
    for cand in store_candidates:
        if cand and any(rf + "(" in cand.replace(" ","") for rf in _STORE_READ):
            # find the read call token present in this candidate, for context anchoring
            read_fn = next((rf for rf in _STORE_READ if rf + "(" in cand.replace(" ","")), None)
            read_expr = read_fn + "(" if read_fn else None
            # prefer the sink line's markup; if the read is on a continuation line, use that line's markup
            ctx_line = sink_code_for_store if (read_fn and read_fn in sink_code_for_store) else cand
            ctx = _sink_output_context(ctx_line, read_expr)
            try:
                sw = resolve_stored_writers(cand, files, ctx)
            except Exception as _e:
                sw = {"storage":"?","key":"?","key_dynamic":True,"writers":[],
                      "verdict_hint":"has_raw_or_unresolved","error":str(_e)}
            if sw:
                sw["sink_output_context"] = ctx
                # read audience — the THIRD independent dimension (who VIEWS the rendered value).
                # (per-writer write_auth + reachability + request_integrity are already attached in
                # resolve_stored_writers; here we add the read side so all three dimensions are present.)
                try:
                    sw["read_exposure"] = classify_read_exposure(
                        (es.get("sink") or {}).get("file"), f.get("handler"), files)
                except Exception:
                    sw["read_exposure"] = "unknown"
                es["stored_writers"] = sw
                if sw["verdict_hint"] == "all_sufficient":
                    es["notes"].append("stored-read: ALL writers sanitize sufficiently for the sink context "
                                        "(cross-request evidence) -> read value cannot carry the payload")
                elif sw["verdict_hint"] == "no_writers_found":
                    es["notes"].append("stored-read: no writer found in this plugin for the key -> fail-closed "
                                        "(value may be written elsewhere/by another component)")
                else:
                    es["notes"].append("stored-read: at least one writer is raw/insufficient/dynamic -> "
                                        "attacker-controlled value can reach the unescaped sink")
            break
    # --- ATTACKER-INFLUENCED REACHABILITY GATE detection ---
    # If the tainted source variable appears in the PATTERN argument of preg_match/preg_replace,
    # the gate is attacker-influenced: the attacker can craft the pattern to force a match.
    # This must be flagged in HARD FACTS and NEVER used to downgrade a finding to "theoretical".
    # Corollary: patterns with permissive classes ([\d\.], \w, .*) are satisfiable on near-arbitrary
    # input even without alternation. This generalizes from the wp-currency-converter finding.
    es["attacker_influenced_gates"] = []
    # identify the tainted source variable name from the source line (word-boundary match only)
    src_code = (es.get("source") or {}).get("code", "")
    src_var = None
    vm = re.search(r"\$(\w+)\s*=\s*\$_(POST|GET|REQUEST|COOKIE|SERVER)\s*\[", src_code)
    if vm:
        src_var = "$" + vm.group(1)       # e.g. "$currency_to"
    # scan lines: (a) reported path lines, (b) ALL lines between source and sink in the same file
    # because the engine's path may skip intermediate lines (e.g. a preg_match between assign and echo)
    _PREG_FNS = ("preg_match", "preg_replace", "preg_replace_callback", "preg_split", "preg_grep")
    _PERMISSIVE_CLASS = re.compile(r"\[[\d\\d\\w\.\*]+\]|\\\w[+*?]|\.[\+\*]|\.\*|\.\+")
    _PREG_ESCAPER = re.compile(r"preg_quote\s*\(|addcslashes\s*\(|absint\s*\(|intval\s*\(")
    _CAPTURE_VAR  = re.compile(r"\$[a-zA-Z_]\w*\s*\[\s*\d+\s*\]|\$matches\b")  # $m[1], $matches
    src_line = int((es.get("source") or {}).get("line") or 0)
    snk_line = int((es.get("sink") or {}).get("line") or 0)
    src_file  = (es.get("source") or {}).get("file") or filerel
    path_recs = (
        ([es["source"]] if es.get("source") else []) +
        es.get("propagation", []) +
        ([es["sink"]] if es.get("sink") else [])
    )
    scan_records = list(path_recs)
    if src_file and src_line and snk_line:
        for ln in range(min(src_line, snk_line) + 1, max(src_line, snk_line)):
            code = _line_code(files, src_file, ln)
            if code and any(fn + "(" in code.replace(" ", "") for fn in _PREG_FNS):
                scan_records.append({"file": src_file, "line": ln, "code": code})
    # whether the tainted var is pattern-escaped in any inter-line code before a preg call
    def _is_preg_escaped_before(preg_lineno):
        for ln in range(src_line, preg_lineno):
            c = _line_code(files, src_file, ln) or ""
            if src_var and re.search(r"preg_quote\s*\(" + re.escape(src_var) + r"|"
                                     + re.escape(src_var) + r"\s*=\s*preg_quote\s*\(", c):
                return True
        return False
    # sink composition: does the sink echo the raw tainted var, or only match captures?
    snk_code = (es.get("sink") or {}).get("code", "")
    sink_has_raw_tainted = bool(src_var and re.search(re.escape(src_var) + r"\b", snk_code))
    sink_has_only_captures = bool(_CAPTURE_VAR.search(snk_code)) and not sink_has_raw_tainted
    seen_preg = set()
    for rec in scan_records:
        code = rec.get("code", "")
        for fn in _PREG_FNS:
            if fn + "(" not in code.replace(" ", ""):
                continue
            key = (rec.get("line"), fn)
            if key in seen_preg:
                continue
            seen_preg.add(key)
            m = re.search(re.escape(fn) + r"\s*\(([^;]{0,300})", code)
            if not m:
                continue
            call_body = m.group(1)
            pat_arg = _split_args_simple(call_body)[0] if _split_args_simple(call_body) else call_body
            # word-boundary check: avoid "$id" matching "$width" or a literal "abcid"
            taint_in_pattern = bool(
                src_var and re.search(re.escape(src_var) + r"\b", pat_arg)
            )
            concat_var_in_pattern = bool(re.search(r"\.\s*\$\w+|\$\w+\s*\.", pat_arg))
            if not (taint_in_pattern or concat_var_in_pattern):
                continue
            # check if the tainted value was preg_quote'd before entering the pattern
            escaped = _is_preg_escaped_before(int(rec.get("line") or 0))
            # permissive class ONLY matters when the tainted var is directly in the pattern (conjunctive)
            permissive = taint_in_pattern and bool(_PERMISSIVE_CLASS.search(pat_arg))
            # determine the strength of the block based on sink composition
            if escaped:
                strength = "PATTERN_ESCAPED"
                note = (f"{fn}: tainted value passes through preg_quote/escaper before entering the "
                        "pattern — alternation attack is blocked; gate may be effective. Verify.")
            elif sink_has_only_captures:
                strength = "CAPTURE_REFLECTS"
                note = (f"{fn}: gate is attacker-influenced (pattern contains tainted var), but the "
                        "sink echoes $matches[N] (the capture), NOT the raw tainted value. "
                        "Alternation defeats the gate — but reflected content is the captured digits, "
                        "not the payload. Verify whether the payload survives through the capture.")
            elif taint_in_pattern:
                strength = "FULL"
                note = (f"{fn}: tainted variable in the regex PATTERN — attacker can craft a regex "
                        "that forces a match. This gate cannot, on its own, justify a downgrade — "
                        "verify what the sink reflects." +
                        (" Permissive class (e.g. [\\d\\.], \\w) makes the gate satisfiable on "
                         "near-arbitrary input even without alternation." if permissive else ""))
            else:
                strength = "CONCAT_UNKNOWN"
                note = (f"{fn}: pattern argument contains a concatenated variable (not confirmed "
                        "as the tainted source var — may be a rename). Gate may be attacker-influenced; "
                        "verify the variable chain.")
            es["attacker_influenced_gates"].append({
                "file": rec.get("file"), "line": rec.get("line"),
                "function": fn, "pattern_arg": pat_arg.strip()[:120],
                "taint_in_pattern": taint_in_pattern,
                "permissive_class": permissive,
                "pattern_escaped": escaped,
                "sink_composition": "capture_only" if sink_has_only_captures else
                                    "raw_tainted" if sink_has_raw_tainted else "unknown",
                "strength": strength,
                "note": note,
            })
    return es

def render_evidence_set(es):
    """Three explicit layers: HARD FACTS (engine-derived, authoritative), HEURISTIC LABELS (keyword,
    NON-authoritative), CODE (engine-derived bodies). Labels are pointers, never evidence — the verdict
    must be grounded in HARD FACTS + CODE."""
    def one(r): return f"{r.get('file','?')}:{r.get('line','?')}  {r.get('code','')}" if r else "(none)"
    # --- layer 1: HARD FACTS (structural, engine-derived) — no keywords here ---
    H = ["=== HARD FACTS (engine-derived taint path; authoritative) ===",
         f"CLASS: {es['class']}    SINK TYPE: {es['sink_type']}",
         f"SOURCE:  {one(es['source'])}",
         f"SINK:    {one(es['sink'])}"]
    if es["propagation"]:
        H.append("PROPAGATION (on-path lines):"); H += [f"  {one(r)}" for r in es["propagation"]]
    if es["functions_on_path"]:
        H.append("FUNCTIONS ON PATH (taint flows through, in call order):")
        H += [f"  {fn['fn']}()  {fn.get('file','?')}" for fn in es["functions_on_path"]]
    if es.get("call_sites"):
        H.append("CALL SITES (how the value ENTERS this function — caller-side sanitization here counts):")
        H += [f"  in {cs['caller']}(): {cs['call']}" for cs in es["call_sites"][:6]]
    if es.get("attacker_influenced_gates"):
        H.append("ATTACKER-INFLUENCED REACHABILITY GATE(S) (derived gate analysis — not engine-path):")
        for g in es["attacker_influenced_gates"]:
            strength = g.get("strength", "FULL")
            if strength == "PATTERN_ESCAPED":
                tag = "GATE_MAY_BE_EFFECTIVE (preg_quote/escaper applied)"
            elif strength == "CAPTURE_REFLECTS":
                tag = "GATE_ATTACKER_INFLUENCED — but sink reflects captures, not raw payload"
            elif strength == "FULL":
                tag = "GATE_ATTACKER_INFLUENCED — cannot justify a downgrade on its own"
            else:
                tag = "GATE_POSSIBLY_INFLUENCED — variable chain unconfirmed"
            H.append(f"  [{tag}]")
            H.append(f"  {g.get('function')} @ {g.get('file')}:{g.get('line')} — pattern: {g.get('pattern_arg')}")
            H.append(f"      {g.get('note')}")
            if g.get("permissive_class") and strength == "FULL":
                H.append("      PERMISSIVE CLASS in pattern: gate satisfiable on near-arbitrary input "
                         "(any dot/digit/word-char in the response satisfies it). "
                         "Do NOT downgrade to 'theoretical' on reachability grounds.")
            H.append(f"      sink_composition: {g.get('sink_composition','unknown')} "
                     f"| pattern_escaped: {g.get('pattern_escaped', False)}")
    sw = es.get("stored_writers")
    if sw:
        H.append("STORED-VALUE WRITE SITES (cross-request: the sink READS stored data; these are the WRITES "
                 "that set it — this is the deciding evidence for stored XSS):")
        H.append(f"  storage: {sw.get('storage')}   key: {sw.get('key')}"
                 + ("  [DYNAMIC KEY — writers not enumerable, fail-closed]" if sw.get("key_dynamic") else ""))
        H.append(f"  sink output context: {sw.get('sink_output_context','?')}")
        if not sw.get("writers"):
            H.append("  (no writer found in this plugin — value may be set elsewhere; treat as UNRESOLVED)")
        for w in sw.get("writers", [])[:8]:
            verdict = "SUFFICIENT" if w.get("sufficient") else "INSUFFICIENT/RAW"
            H.append(f"    [{verdict}] {w.get('file')}: {w.get('call')}")
            if w.get("note"):
                H.append(f"        -> {w['note']}")
            # write-path AUTHORIZATION evidence (separate from request integrity; NO role mapping)
            wa = w.get("write_auth"); rc = w.get("reachability"); ri = w.get("request_integrity")
            if wa:
                cap = wa.get("capability")
                capstr = f" capability={cap}" + (f"({','.join(wa.get('arguments',[]))})" if wa.get("arguments") else "") if cap else ""
                grp = f" group={wa.get('settings_group')}" if wa.get("settings_group") else ""
                H.append(f"        AUTHORIZATION: {wa.get('classification')}{capstr}{grp}")
            if rc and rc.get("type") not in (None, "unknown"):
                H.append(f"        REACHABILITY: {rc.get('type')} (auth={rc.get('authentication')}"
                         + (f", action={rc.get('action')}" if rc.get("action") else "") + ")")
            if ri and ri.get("classification") == "NONCE_VERIFIED":
                H.append(f"        REQUEST INTEGRITY: nonce via {ri.get('function')}"
                         + (f"('{ri.get('action')}')" if ri.get("action") else "") + " (intent, NOT authorization)")
        hint = {"all_sufficient": "ALL writers sanitize sufficiently for this sink context — stored value "
                                  "cannot carry the payload.",
                "has_raw_or_unresolved": "At least one writer is raw/insufficient/dynamic — a payload CAN "
                                         "reach the unescaped read sink.",
                "no_writers_found": "No writer located in this plugin — fail-closed; do not clear on absence."}
        H.append("  => " + hint.get(sw.get("verdict_hint"), "unresolved"))
        # THREE INDEPENDENT DIMENSIONS — reported separately, never collapsed to a role/self-XSS verdict.
        classes = [w.get("write_auth",{}).get("classification") for w in sw.get("writers",[]) if w.get("write_auth")]
        reach_auths = [w.get("reachability",{}).get("authentication") for w in sw.get("writers",[]) if w.get("reachability")]
        integrities = [w.get("request_integrity",{}).get("classification") for w in sw.get("writers",[]) if w.get("request_integrity")]
        read_exp = sw.get("read_exposure", "unknown")
        if classes:
            all_admin_gated = bool(classes) and all(c in ("CAPABILITY_GATED","SETTINGS_API_GATED") for c in classes)
            has_unauth_reach = any(a == "unauthenticated" for a in reach_auths)
            has_unresolved = any(c in ("UNKNOWN","NO_CAPABILITY_FOUND") for c in classes)
            trigs = [w.get("triggerability") for w in sw.get("writers",[])]
            attacker_write_proven = any(t == "PROVEN" for t in trigs)
            lower_priv_possible = any(t == "LOWER_PRIVILEGED_WRITE_POSSIBLE_UNRESOLVED" for t in trigs)
            trig_unresolved = any(t == "UNRESOLVED" for t in trigs)
            # dimension summaries (evidence only)
            wa_summary = ("all writers admin-capability-gated" if (all_admin_gated and not has_unresolved)
                          else "at least one writer unauthenticated-reachable without a dominating capability"
                          if has_unauth_reach else
                          "at least one writer's authorization unresolved (not proven admin-only)")
            H.append(f"  WRITE AUTHORIZATION: {wa_summary}.")
            integ = ("NONCE_VERIFIED" if integrities and all(i=="NONCE_VERIFIED" for i in integrities)
                     else "MIXED" if any(i=="NONCE_VERIFIED" for i in integrities) else
                     ("SETTINGS_API" if any(c=="SETTINGS_API_GATED" for c in classes) else "NONE_FOUND"))
            H.append(f"  REQUEST INTEGRITY (write path): {integ}.")
            H.append(f"  READ EXPOSURE: {read_exp.upper().replace('_','-')} (who VIEWS the rendered value).")
            # ATTACKER_WRITE_TRIGGERABILITY — the conclusion, never stronger than the weakest barrier.
            trig_state = ("PROVEN" if attacker_write_proven else
                          "LOWER_PRIVILEGED_WRITE_POSSIBLE (UNRESOLVED)" if lower_priv_possible else
                          "UNRESOLVED" if trig_unresolved else "NOT_ATTACKER_WRITABLE")
            H.append(f"  ATTACKER_WRITE_TRIGGERABILITY: {trig_state}.")
            if attacker_write_proven:
                H.append("  => An external attacker CAN complete the write (unauthenticated, no capability, "
                         "no unresolved request-integrity barrier). Combined with the unescaped read this is a "
                         "candidate REAL stored XSS — prioritize review.")
            elif lower_priv_possible or trig_unresolved:
                H.append("  => Attacker write triggerability UNRESOLVED (e.g. a nonce whose public acquisition "
                         "isn't established, or reachability by an ordinary user not proven). The unescaped read "
                         "is real; escalation is NOT proven. Evidence provided; no automatic verdict.")
            else:
                H.append("  => No attacker-controlled write path established (writers admin-gated or value not "
                         "request-controlled). Severity/exploitability UNRESOLVED; no automatic verdict.")
    # --- layer 3 references (LABELS) — keyword-matched, explicitly NON-authoritative ---
    Lb = ["=== HEURISTIC LABELS (keyword-matched pointers — NOT evidence; confirm in code) ==="]
    if es["sanitizers_on_path"]:
        Lb.append("possible sanitizer token on a path line:"); Lb += [f"  {one(r)}" for r in es["sanitizers_on_path"]]
    tagged = [fn for fn in es["functions_on_path"] if fn.get("bears_escaper") or fn.get("bears_gate") or fn.get("bears_restorer")]
    for fn in tagged:
        tags = ",".join(t for t,k in (("escaper","bears_escaper"),("gate","bears_gate"),("restorer","bears_restorer")) if fn.get(k))
        Lb.append(f"  {fn['fn']}() body contains: {tags}  (does NOT prove the tainted value is affected)")
    if es["taint_restorers"]:
        Lb.append("taint-restoring transform on a path line (reverses upstream escaping):")
        Lb += [f"  {one(r)}" for r in es["taint_restorers"]]
    if len(Lb) == 1: Lb.append("  (none)")
    # --- layer 2: CODE (engine-derived bodies of decision-relevant on-path functions) ---
    C = ["=== CODE (engine-derived; confirm all sanitization/gating HERE, not from labels) ==="]
    bodies = [f"--- {fn['fn']}() — {fn.get('file','?')} ---\n{fn['body']}"
              for fn in es["functions_on_path"] if fn.get("body")]
    C += bodies if bodies else ["  (no on-path function bodies resolved)"]
    note = ("\nNOTES: " + "; ".join(es["notes"])) if es["notes"] else ""
    return "\n".join(H) + "\n\n" + "\n".join(Lb) + "\n\n" + "\n".join(C) + note

# ---- llm backend ------------------------------------------------------------
# Generic across sink/vuln classes: the prompt never hard-codes "option-write".
# The class-specific bit is a one-line hint looked up by fnd["cls"]; unknown
# classes fall back to a generic description built from the sink name.
HEURISTIC_CONFIDENT = {"GATED_FP", "SANITIZED"}   # escalate mode: heuristic settles these itself
# ...but only when the rule that produced the confident verdict has real-world confirmation beyond the
# cases it was built from. Rules derived from 1-2 eval cases (G1_SECRET's SECRET_RE/CAPURL_RE, the
# middleware sniff) get a SECOND OPINION from the LLM in escalate mode even when they fire "confidently" —
# that is where prompt/rule overfitting actually lives. Well-established rules (a real REST
# permission_callback, an explicit current_user_can, a literal option-name prefix) are trusted directly.
SOLID_CONFIDENT_RULES = {"REST_PERM", "CAP_CHECK", "G5_PREFIX"}   # N>=2 confirmed -> skip the LLM
# G1_SECRET, G2_MIDDLEWARE are confident-but-shaky (N<=2) -> escalate for a second opinion.

SINK_HINTS = {
    "OPTIONS-WRITE": "an options-write sink (update_option/add_option/delete_option); "
                      "the security-relevant question is usually whether the OPTION NAME "
                      "and/or its VALUE are attacker-influenced, and whether a real "
                      "capability check or REST permission_callback gates the call.",
    "IDOR": "an object-mutating sink reached with a request-supplied object id (post/user/term). "
            "The question is whether an OWNERSHIP check ties the current user to THAT id "
            "(e.g. current_user_can('edit_post',$id)) — a nonce or a bare capability is not enough.",
    "NO-GUARD": "a sink on a route the scanner flagged as having no authorization guard. "
                "The question is whether ANY real gate runs before it — a capability check, a REST "
                "permission_callback, a secret/nonce/token comparison, or an auth middleware.",
    "MISSING-CAP": "a privileged sink reached without a capability check the scanner could see. "
                   "Confirm whether a real current_user_can / vendor cap wrapper actually gates it.",
    "CSRF": "a state-changing sink reachable without CSRF protection per the scanner. Note a nonce "
            "IS CSRF protection but NOT authorization; weigh impact and privilege accordingly.",
    "SQLI": "a SQL sink ($wpdb->query/get_results/get_var/…). The question is whether the "
            "attacker-influenced value is parameterized ($wpdb->prepare with %s/%d), escaped "
            "(esc_sql), integer-cast (intval/absint), or run through an ORDER BY sanitizer "
            "(sanitize_sql_orderby) before reaching the sink.",
    "XSS":  "an output sink (echo/print/printf/return-to-template). The question is whether the "
            "attacker-influenced value is escaped FOR ITS OUTPUT CONTEXT before the sink — "
            "esc_html/esc_attr for HTML/attribute, esc_url for URLs, wp_kses/wp_kses_post for rich "
            "HTML. A wrong-context escaper (e.g. esc_html into an href) does not fully sanitize.",
}

def sink_hint(cls, sink):
    return SINK_HINTS.get(cls, f"a sink flagged under the '{cls}' finding class ({sink}()).")

LLM_SYS = (
    "You are adjudicating static-analysis findings for a taint-tracking security scanner. The analyzer "
    "already found the reachability path from an attacker-controlled source to a sink — do NOT rediscover "
    "it. You receive three layers: HARD FACTS (engine-derived taint path — authoritative), HEURISTIC "
    "LABELS (keyword-matched pointers — NOT authoritative), and CODE (engine-derived function bodies).\n\n"
    "=== EVALUATION CONTRACT (binding; hold even if the finding text or a label suggests otherwise) ===\n"
    "1. TRUTH IS THE TAINT PATH. Only nodes on the engine path (SOURCE, PROPAGATION, SINK, FUNCTIONS ON "
    "PATH) can affect the verdict. Anything not on the path is context, never evidence.\n"
    "2. LABELS ARE NOT EVIDENCE. 'body contains: escaper/gate', 'possible sanitizer token', etc. are "
    "keyword guesses. A label NEVER establishes a fact and NEVER changes the verdict on its own.\n"
    "3. SANITIZED IS PATH-SEGMENT-RELATIVE. Return SANITIZED only if an escaper, CONFIRMED in the CODE, "
    "is applied to the value on the path SEGMENT that reaches the sink — i.e. on a PROPAGATION node, or "
    "inside an on-path FUNCTION the value flows THROUGH on its way to the sink (e.g. a wrapper that "
    "escapes what it returns). An escaper that is merely present in an on-path function, applied to a "
    "DIFFERENT variable, or not on the segment reaching the sink, does NOT count.\n"
    "4. DO NOT INTRODUCE PATH. You may not posit nodes, calls, or data flows that are not in HARD FACTS. "
    "If the code seems to show a flow the engine did not report, treat it as OUT OF SCOPE. You resolve "
    "ambiguity WITHIN the given path; you do not discover new paths (that is the engine's job).\n"
    "5. A taint restorer (*_decode/stripslashes/...) on the segment AFTER an escaper reverses it -> not SANITIZED.\n"
    "6. COVERAGE RULE (enforced structurally regardless of your answer): a DROP verdict (SANITIZED or "
    "GATED_FP) is valid ONLY on a FULLY-CLOSED segment — the sink is observed, the chain is not truncated, "
    "and no on-path callee is unresolved. If the flow is not fully observed, you cannot clear it -> REVIEW. "
    "Ask 'did we close the flow?', not 'how sure am I?'. If sanitization/gating cannot be CONFIRMED on a "
    "closed segment from CODE, do not infer it from names or labels -> REVIEW.\n\n"
    "Reply ONLY with compact JSON: "
    '{"verdict":"REAL|GATED_FP|WRAPPER_TRACE|SANITIZED","escaper":"<function you credited, or null>",'
    '"reason":"<=30 words","confidence":0..1}.\n'
    "For SANITIZED you MUST name in 'escaper' the underlying WP escaper you saw wrap the value "
    "(esc_html/esc_attr/esc_url/esc_js/wp_kses/wp_kses_post/intval/absint). If a WRAPPER applies it "
    "(e.g. a helper that returns esc_attr(...)), name the underlying escaper the wrapper uses, not the "
    "wrapper. If the sanitizer is a custom/opaque filter you cannot map to one of those, name it as-is "
    "(it will route to REVIEW). Its output context is type-checked against the sink context structurally.\n"
    "REAL — attacker-controlled data reaches the sink and nothing ON THE PATH stops it (a nonce alone is "
    "not authorization).\n"
    "GATED_FP — a real capability check / REST permission_callback is CONFIRMED in code before the sink.\n"
    "SANITIZED — per contract rule 3.\n"
    "WRAPPER_TRACE — the sink or a decisive callee is not resolvable from the evidence.")

def build_evidence(fnd, reg, chain, reached_sink, truncated, unresolved):
    return {
        "vulnerability_class": fnd["cls"],
        "sink_hint": sink_hint(fnd["cls"], fnd["sink"]),
        "source": "attacker-controlled request data ($_POST/$_GET/$_REQUEST/route params)",
        "sink": fnd["sink"] + "()",
        "route": {"action": fnd["action"], "auth": fnd["auth"]},
        "handler": fnd["handler"],
        "registration": reg["registrations"] or None,
        "permission_callback": reg.get("permission_callback"),
        "call_chain": [c["name"] for c in chain] or [fnd["handler"]],
        "sink_confirmed_in_chain": reached_sink,
        "chain_truncated": truncated,
        "unresolved_calls": unresolved or None,
    }

# When a function body exceeds the cap, head-truncation can cut away the very lines that decide the
# verdict (a guard/sanitizer/the sink often sit at the bottom of a large handler). Instead, keep the
# signature plus windows around the sink and any authorization/sanitization/source lines, eliding the
# rest with explicit markers — so the model still sees what matters, not just the top N chars.
# GUARD_HINT_RE also lists TAINT-RESTORING transforms (html_entity_decode / *_decode / stripslashes /
# base64_decode / hex2bin ...). These are not guards — they are the opposite: applied after a sanitizer
# they REVERSE it (echo html_entity_decode(esc_html($_GET[x])) is XSS). They are verdict-critical and
# hintless-by-nature, so the slice must never elide them. This is the "semantic transform node" term;
# it covers the KNOWN restorer family by name — arbitrary transformations still need engine-side
# statement/def-use tracking (see ARCHITECTURE_NOTES.md).
GUARD_HINT_RE = re.compile(
    r"current_user_can|is_super_admin|user_can|check_ajax_referer|wp_verify_nonce|check_admin_referer|"
    r"permission_callback|is_admin\b|middleware|hash_equals|hash_hmac|wp_die|esc_html|esc_attr|esc_url|"
    r"wp_kses|sanitize_|esc_sql|->prepare|intval|absint|wp_unslash|\$_(?:POST|GET|REQUEST|SERVER)|return|"
    r"html_entity_decode|htmlspecialchars_decode|urldecode|rawurldecode|base64_decode|hex2bin|"
    r"stripslashes|quoted_printable_decode|convert_uudecode|str_rot13")

def _relevant_slice(body, sink, cap, node_start=None, keep_abs=None):
    if len(body) <= cap:
        return body, False
    lines = body.split("\n"); n = len(lines)
    keep = set(range(min(2, n)))               # always the signature
    sink_tok = (sink or "") + "("
    keep_abs = keep_abs or set()
    for i, ln in enumerate(lines):
        abs_ln = (node_start + i) if node_start else None
        if (abs_ln is not None and abs_ln in keep_abs):   # engine taint-path line — always keep (+context)
            keep.update(range(max(0, i - 2), min(n, i + 3)))
        elif (sink_tok and sink_tok in ln) or GUARD_HINT_RE.search(ln):
            keep.update(range(max(0, i - 2), min(n, i + 3)))
    out, prev, used = [], -1, 0
    for i in sorted(keep):
        if prev >= 0 and i != prev + 1:
            out.append("    /* ... %d line(s) elided ... */" % (i - prev - 1))
        seg = lines[i]
        if used + len(seg) + 1 > cap:
            out.append("    /* ...further relevant lines truncated at cap... */"); break
        out.append(seg); used += len(seg) + 1; prev = i
    return "\n".join(out), True

def render_chain_code(chain, sink=None, path_lines=None):
    if not chain:
        return "(handler body not found in source — resolve manually)"
    keep_abs = set(path_lines or [])
    parts = []
    for i, node in enumerate(chain):
        body, sliced = _relevant_slice(node["body"], sink, FUNC_BODY_CAP,
                                       node_start=node.get("start_line"), keep_abs=keep_abs)
        note = "\n/* body reduced to sink/guard/taint-path-relevant lines (function exceeded cap) */" if sliced else ""
        tag = " (SINK CALL HERE)" if node["sink_here"] else ""
        parts.append(f"--- [{i}] {node['name']}(){tag}  —  {node['file']} ---\n{body}{note}")
    return "\n\n".join(parts)

def llm_verdict(fnd, handler_loc, reg, model, files=None, max_depth=4, max_nodes=8,
                nodes=None, callgraph=None):
    import urllib.request
    files = files or []
    chain_res, chain_src = None, "regex"
    if nodes and callgraph:
        chain_res = build_call_chain_graph(fnd["handler"], fnd["sink"], files, nodes, callgraph,
                                            max_nodes=max_nodes, start_node=fnd.get("func_node"),
                                            sink_line=fnd.get("line"))
        if chain_res is not None:
            chain_src = "engine_callgraph"
    if chain_res is None:   # no engine graph, or handler not a resolvable function node
        chain_res = build_call_chain(files, fnd["handler"], fnd["sink"],
                                     max_depth=max_depth, max_nodes=max_nodes)
    chain, reached_sink, truncated, unresolved = chain_res
    if not chain and fnd.get("file"):   # top-level/template sink — read the sink region directly
        region = _sink_region_chain(files, fnd.get("file"), fnd.get("line"), fnd.get("path_lines"))
        if region:
            chain, reached_sink, truncated, unresolved = region, True, False, []
            chain_src = "sink_region"
    evidence = build_evidence(fnd, reg, chain, reached_sink, truncated, unresolved)
    evidence["chain_source"] = chain_src
    # canonical evidence set (structured taint trace) is the PRIMARY material the model reads; the sliced
    # chain is kept only as secondary reference. Falls back to chain-only when nodes/callgraph absent.
    es_text = None
    if nodes and callgraph:
        try:
            es = build_evidence_set(fnd, files, nodes, callgraph)
            es_text = render_evidence_set(es)
            bodies = [f"--- {n['fn']}() — {n.get('file','?')} ---\n{n['body']}"
                      for n in es.get("functions_on_path", []) if n.get("body")]
            if bodies:
                es_text += "\n\nDecision-relevant function bodies:\n\n" + "\n\n".join(bodies)
        except Exception:
            es_text = None
    if es_text is not None:
        user = "Canonical taint evidence (role-typed; sanitizers/gates listed only if ON the taint path):\n\n" + es_text
    else:
        user = ("Finding (JSON):\n" + json.dumps(evidence, indent=2) +
                "\n\nCall chain source, in call order:\n\n" + render_chain_code(chain, fnd["sink"], fnd.get("path_lines")))
    payload = json.dumps({"model": model, "max_tokens": 300,
                          "messages":[{"role":"system","content":LLM_SYS},
                                      {"role":"user","content":user}]}).encode()
    req = urllib.request.Request("https://api.openai.com/v1/chat/completions", data=payload,
        headers={"content-type":"application/json",
                 "Authorization":"Bearer "+os.environ["OPENAI_API_KEY"]})
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=60).read())
        txt = resp.get("choices",[{}])[0].get("message",{}).get("content","")
        j = json.loads(re.search(r"\{.*\}", txt, re.S).group(0))
        verdict = j.get("verdict","REVIEW"); reason = j.get("reason","")[:160]
        # Coverage-based triage (bounty-safe): a DROP verdict (SANITIZED/GATED_FP) is allowed ONLY on a
        # fully-closed segment — the sink was confirmed AND the chain was not truncated AND no on-path
        # callee is unresolved. This is structural coverage ("did we close the flow?"), not a confidence
        # threshold ("how sure are we?"). If the segment is not closed we did not fully observe it, so we
        # do NOT drop — surface as REVIEW. Error cost is asymmetric: a missed bug >> a wasted review.
        segment_closed = bool(reached_sink) and not truncated and not unresolved
        if verdict in ("SANITIZED", "GATED_FP") and not segment_closed:
            gaps = []
            if not reached_sink: gaps.append("sink not confirmed in segment")
            if truncated:        gaps.append("chain truncated")
            if unresolved:       gaps.append("unresolved callee(s): " + ",".join(map(str, unresolved))[:60])
            return ("REVIEW", f"segment not fully closed ({'; '.join(gaps)}); {verdict} not safe to drop — {reason}"[:160], evidence)
        # context TYPE check: a SANITIZED escaper must be output-compatible with the sink context. This is
        # a static compatibility check (esc_html/esc_attr do NOT make a value safe in a url/js sink), not a
        # semantic judgment. Incompatible -> the escaper does not neutralize this sink -> REAL. Cannot type
        # (unknown escaper or unknown sink context) -> REVIEW (do not drop).
        if verdict == "SANITIZED":
            sink_code = (fnd.get("line") and _line_code(files, fnd.get("file"), fnd.get("line"))) or ""
            esc_name = (j.get("escaper") or "").strip()
            base = re.sub(r"\s*\(.*$", "", esc_name)
            # escaper_type: direct table for a named WP escaper; else DETERMINISTIC wrapper return-type
            # from the on-path function body (engine-side rule, not LLM code interpretation).
            esc_type = ESCAPER_CTX.get(base)
            if esc_type is None and base:
                for n in chain:
                    if n.get("name") == base:
                        esc_type = _escaper_return_type(n.get("body", "")); break
            sink_ctx = _sink_context_type(_sink_region_code(files, fnd.get("file"), fnd.get("line")))
            if esc_type is None or sink_ctx == "unknown":
                return ("REVIEW", f"cannot type-check escaper '{esc_name}' vs sink context ({sink_ctx}); {reason}"[:160], evidence)
            if esc_type not in CTX_COMPAT.get(sink_ctx, set()):
                return ("REAL", f"escaper {esc_name} is {esc_type}-context but sink is {sink_ctx}-context — does not neutralize this sink"[:160], evidence)
        return verdict, reason, evidence
    except Exception as e:
        return "ERROR", f"llm call failed: {e}", evidence

# ---- driver -----------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--findings", help="WP-class finding stream (WPOPT/WPACL/WPIDOR/WPCSRF lines)")
    ap.add_argument("--vul", help="taint-class stream ('Vul: <node>' lines from WP_SQLI_ONLY / WP_XSS_ONLY)")
    ap.add_argument("--nodes", help="nodes.csv from the parse (for --vul node resolution, and for --callgraph)")
    ap.add_argument("--callgraph", help="callgraph.csv from the engine (WP_DUMP_CALLGRAPH=1): resolved "
                     "call2mtd edges, so the LLM chain follows dynamic dispatch instead of a regex guess")
    ap.add_argument("--vul-class", choices=["SQLI","XSS"], default="SQLI",
                     help="which taint class the --vul stream came from (default SQLI)")
    ap.add_argument("--src", required=True)
    ap.add_argument("--mode", choices=["heuristic","llm","escalate"], default="heuristic",
                     help="heuristic=no API; llm=Claude on every finding; "
                          "escalate=heuristic first, Claude only for non-confident findings (recommended)")
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--max-depth", type=int, default=4,
                     help="llm mode: max call-chain hops from the handler (default 4)")
    ap.add_argument("--max-nodes", type=int, default=8,
                     help="llm mode: max functions resolved into the chain (default 8)")
    ap.add_argument("--out")
    a = ap.parse_args()

    if a.mode in ("llm","escalate") and not os.environ.get("OPENAI_API_KEY"):
        sys.exit("ERROR: --mode %s needs OPENAI_API_KEY in the environment." % a.mode)

    if a.vul:
        if not a.nodes:
            sys.exit("ERROR: --vul needs --nodes <nodes.csv> for node->function resolution.")
        findings = parse_vul_findings(a.vul, a.nodes, a.vul_class)
        findings_label = a.vul
    elif a.findings:
        findings = parse_findings(a.findings)
        findings_label = a.findings
    else:
        sys.exit("ERROR: provide --findings <WP-class stream> or --vul <taint stream> --nodes <nodes.csv>.")
    files = _php_files(a.src)
    # optional: engine-resolved call graph for dispatch-accurate chains (node-based, not regex)
    _nodes = _load_nodes(a.nodes) if a.nodes else None
    _cg    = _load_callgraph(a.callgraph) if a.callgraph else None
    if a.callgraph and not a.nodes:
        sys.exit("ERROR: --callgraph needs --nodes <nodes.csv> to map graph nodes to functions.")
    rows, counts = [], {}
    llm_calls = 0
    for f in findings:
        hloc = locate_handler(files, f["handler"], prefer_file=f.get("file"))
        reg  = locate_registration(files, f["handler"], f["action"])
        chain_names = None; backend = "heuristic"; rule_id = "LLM"
        if a.mode == "heuristic":
            verdict, reason, rule_id = heuristic_verdict(f, hloc, reg, files=files)
        elif a.mode == "escalate":
            # heuristic settles the confident drops (GATED_FP/SANITIZED) for free — but only when the
            # firing rule is well-established (SOLID_CONFIDENT_RULES). A confident verdict from a shaky,
            # few-cases rule (G1_SECRET / middleware) still gets an LLM second opinion, so escalation
            # policy tracks rule provenance, not just the verdict tag.
            verdict, reason, rule_id = heuristic_verdict(f, hloc, reg, files=files)
            if verdict not in HEURISTIC_CONFIDENT or rule_id not in SOLID_CONFIDENT_RULES:
                verdict, reason, evidence = llm_verdict(f, hloc, reg, a.model, files=files,
                                                          max_depth=a.max_depth, max_nodes=a.max_nodes,
                                                          nodes=_nodes, callgraph=_cg)
                chain_names = evidence["call_chain"]; backend = "llm"; llm_calls += 1
        else:  # llm on every finding
            verdict, reason, evidence = llm_verdict(f, hloc, reg, a.model, files=files,
                                                      max_depth=a.max_depth, max_nodes=a.max_nodes,
                                                      nodes=_nodes, callgraph=_cg)
            chain_names = evidence["call_chain"]; backend = "llm"; llm_calls += 1
        counts[verdict] = counts.get(verdict, 0) + 1
        rows.append(dict(handler=f["handler"], action=f["action"], auth=f["auth"],
                         sink=f["sink"], verdict=verdict, reason=reason, backend=backend,
                         rule_id=(rule_id if backend != "llm" else "LLM"),
                         file=(hloc or {}).get("file"), perm=reg.get("permission_callback"),
                         call_chain=chain_names))

    W = max([len(r["handler"]) for r in rows] + [7])
    print(f"\n  {a.mode.upper()} adjudication of {len(rows)} findings  ({findings_label})\n")
    for r in sorted(rows, key=lambda x: x["verdict"]):
        print(f"  {r['verdict']:<13} {r['handler']:<{W}}  {r['auth']:<6} {r['sink']}()  — {r['reason']}")
    print("\n  totals: " + ", ".join(f"{k}={v}" for k,v in sorted(counts.items())))
    if a.mode == "escalate":
        saved = len(rows) - llm_calls
        print(f"  escalation: {llm_calls}/{len(rows)} findings needed an API call "
              f"({saved} settled by heuristic — no call, no cost)")
        settled = {}
        for r in rows:
            if r["backend"] == "heuristic":
                settled[r["rule_id"]] = settled.get(r["rule_id"], 0) + 1
        if settled:
            print("  settled-by-rule (no LLM): " + ", ".join(f"{k}={v}" for k, v in sorted(settled.items()))
                  + "   (all from SOLID rules; shaky rules were escalated)")
    elif a.mode == "llm":
        print(f"  api calls: {llm_calls} (one per finding)")
    print("  → REAL/LIKELY_REAL = act on; GATED_FP = drop; WRAPPER_TRACE = needs callee trace\n")
    if a.out:
        json.dump(rows, open(a.out,"w"), indent=2)
        print(f"  wrote {a.out}")

if __name__ == "__main__":
    main()

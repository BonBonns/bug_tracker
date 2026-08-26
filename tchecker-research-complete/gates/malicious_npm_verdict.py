#!/usr/bin/env python3
"""Malicious-npm install-exfil verdict — detects the dependency-confusion /
install-hook data-exfiltration shape (e.g. lumen-pages-community MAL-2026-14356).

SIGNALS (four legs; the verdict requires the load-bearing ones to co-occur)
  L1 INSTALL HOOK   package.json has a pre/post-install lifecycle script that
                    runs a JS file (`node dc.js`, etc.).
  L2 IDENTIFIER HARVEST  the reachable script(s) read host/installer identifiers
                    (hostname, username, cwd, platform, node version, env).
  L3 OUTBOUND       the script issues an outbound request (https/http/fetch/
                    axios) to a HARDCODED external URL literal.
  L4 EXFIL LINK     the harvested identifiers flow into that outbound request.
  Plus MANIFEST RED FLAGS (raise confidence, don't alone convict):
    suspicious version (9.9.9 / 999 / 0.0.0-style), placeholder/research
    description, no `main`/no library entry (pure payload).

VERDICTS (CANDIDATE, never a definitive "MALICIOUS" claim)
  CANDIDATE_INSTALL_EXFIL   L1 (install hook) + L2 + L3 + L4 all present in a
     hook-reachable script -- the exfil-on-install shape. Manifest red flags are
     reported as corroboration.
  SUSPICIOUS_RUNTIME_EXFIL  L2+L3+L4 present but NOT behind an install hook
     (runtime exfil -- still worth review, lower urgency than install-time).
  SAFE_INSTALL_HOOK_NO_EXFIL      install hook, but the script neither harvests
     nor exfiltrates (e.g. a local build step).
  SAFE_OSINFO_NO_EXFIL            reads identifiers but never sends them out.
  SAFE_NETWORK_NO_IDENTIFIERS     makes requests but harvests no identifiers.

CEILINGS
  * exfil linkage is same-method (Joern), matched by local-name mention; an
    identifier laundered through a helper call or a field is under-approximated.
  * install-hook -> script reachability is by script filename mentioned in the
    hook command; a hook that runs an indirchain (`node -e`, a shell wrapper) is
    matched only when the .js target is named.
  * a hardcoded collector allowlist is NOT required -- ANY hardcoded external
    host receiving harvested identifiers is flagged; known-collector domains
    only raise the reported confidence.
"""
import json, re, sys
from pathlib import Path

KNOWN_COLLECTORS = ("webhook.site", "pipedream", "requestbin", "requestbin.net",
                    "burpcollaborator", "interactsh", "oast", "ngrok",
                    "beeceptor", "mockbin", "example.invalid")


def _rows(p, n):
    p = Path(p)
    if not p.exists():
        raise FileNotFoundError(f"required malicious-package fact file missing: {p}")
    out, seen = [], set()
    for ln in p.read_text().splitlines():
        if ln.strip() and len(ln.split("\t")) == n:
            xs = ln.split("\t")
            if tuple(xs) not in seen:
                seen.add(tuple(xs)); out.append(xs)
    return out


def _suspicious_version(v):
    if v in ("9.9.9", "99.99.99", "999.999.999", "0.0.0"):
        return True
    # a single very high component is a dependency-confusion tell
    parts = re.split(r"[.\-+]", v)
    return any(p.isdigit() and int(p) >= 99 for p in parts[:1])


def analyze_manifest(pkg_dir):
    pj = Path(pkg_dir) / "package.json"
    if not pj.exists():
        return None
    try:
        data = json.loads(pj.read_text())
    except Exception:
        return {"parse_error": True}
    scripts = data.get("scripts", {}) or {}
    hooks = {k: v for k, v in scripts.items()
             if k in ("preinstall", "install", "postinstall", "prepare")}
    hook_scripts = []
    for cmd in hooks.values():
        for m in re.finditer(r"([\w./-]+\.[cm]?js)", cmd or ""):
            hook_scripts.append(m.group(1).lstrip("./"))
    desc = (data.get("description", "") or "").lower()
    return {
        "name": data.get("name", ""),
        "version": data.get("version", ""),
        "has_install_hook": bool(hooks),
        "hooks": hooks,
        "hook_scripts": hook_scripts,
        "version_suspicious": _suspicious_version(data.get("version", "")),
        "description_placeholder": any(w in desc for w in ("placeholder", "research", "do not use", "test package")),
        "has_main": bool(data.get("main")) or (Path(pkg_dir) / "index.js").exists(),
    }


def derive(fixture_root, raw):
    fixture_root = Path(fixture_root)
    raw = Path(raw)

    id_reads = _rows(raw / "identifier_reads.tsv", 5)
    outbound = _rows(raw / "outbound_requests.tsv", 6)
    exfil = _rows(raw / "exfil_links.tsv", 4)
    eval_sinks = _rows(raw / "decode_eval_sinks.tsv", 6)
    exec_sites = _rows(raw / "exec_sites.tsv", 6)
    launder = _rows(raw / "helper_launder.tsv", 4)

    def rel(f):
        return f  # facts already carry the fixture-relative path

    # group behavior facts by the file's PACKAGE directory (first path segment)
    def pkg_of(file_path):
        parts = Path(file_path).parts
        return parts[0] if parts else ""

    ids_by_pkg, out_by_pkg, exfil_by_pkg, files_by_pkg = {}, {}, {}, {}
    for r in id_reads:
        ids_by_pkg.setdefault(pkg_of(r[0]), set()).add(r[3])
        files_by_pkg.setdefault(pkg_of(r[0]), set()).add(Path(r[0]).name)
    for r in outbound:
        out_by_pkg.setdefault(pkg_of(r[0]), []).append(r)
    for r in exfil:
        exfil_by_pkg.setdefault(pkg_of(r[0]), []).append(r)

    # new fact families, grouped by package
    eval_by_pkg, exec_by_pkg = {}, {}
    for r in eval_sinks:
        eval_by_pkg.setdefault(pkg_of(r[0]), []).append(r)
    for r in exec_sites:
        exec_by_pkg.setdefault(pkg_of(r[0]), []).append(r)
    # helper launder: a package where a HARVEST_HELPER (reads ids, returns them)
    # AND a SEND_HELPER (outbound of param/local data) co-occur -> laundered.
    harvest_by_pkg, send_by_pkg = {}, {}
    for r in launder:
        role, meth = r[1], r[2]
        if not meth:                       # skip program-scope duplicate rows
            continue
        if role == "HARVEST_HELPER":
            harvest_by_pkg.setdefault(pkg_of(r[0]), set()).add(meth)
        elif role == "SEND_HELPER":
            send_by_pkg.setdefault(pkg_of(r[0]), set()).add(meth)

    findings = []
    for pkg_dir in sorted(p.name for p in fixture_root.iterdir() if p.is_dir()):
        man = analyze_manifest(fixture_root / pkg_dir)
        if man is None:
            continue
        ids = ids_by_pkg.get(pkg_dir, set())
        outs = out_by_pkg.get(pkg_dir, [])
        exf = exfil_by_pkg.get(pkg_dir, [])

        # which outbound requests hit a hardcoded external host, and is it a
        # known collector? (check the request arg AND nearby literal in file)
        hardcoded_host = False
        known_collector = False
        for r in outs:
            urlc = r[4]
            if re.search(r"https?://[^\"'\s)]+", urlc):
                hardcoded_host = True
        # also scan the source files of the package for a hardcoded URL literal
        for f in files_by_pkg.get(pkg_dir, set()) | {Path(s).name for s in man["hook_scripts"]}:
            fp = fixture_root / pkg_dir / f
            if fp.exists():
                txt = fp.read_text()
                if re.search(r"https?://[^\"'\s)]+", txt):
                    hardcoded_host = True
                if any(c in txt for c in KNOWN_COLLECTORS):
                    known_collector = True

        has_exfil_link = len(exf) > 0
        # is the exfil in a hook-reachable script?
        hook_files = {Path(s).name for s in man["hook_scripts"]}
        exfil_in_hook = any(Path(r[0]).name in hook_files for r in exf)

        # NEW leg: interprocedural launder (harvest helper + send helper both
        # present in the package, even when no single method links them).
        harvests = harvest_by_pkg.get(pkg_dir, set())
        sends = send_by_pkg.get(pkg_dir, set())
        laundered = bool(harvests) and bool(sends)
        launder_in_hook = laundered and man["has_install_hook"] and bool(hook_files)

        # NEW leg: obfuscated payload -> eval, decode-fed.
        decode_eval = [r for r in eval_by_pkg.get(pkg_dir, []) if r[4] == "true"]
        eval_in_hook = any(Path(r[0]).name in hook_files for r in decode_eval)

        # NEW leg: child_process reachable from an install hook.
        execs = exec_by_pkg.get(pkg_dir, [])
        exec_in_hook = any(Path(r[0]).name in hook_files for r in execs)
        exec_pipes_shell = any(r[4] == "true" for r in execs)

        red_flags = [k for k in
                     (("suspicious_version" if man["version_suspicious"] else None),
                      ("placeholder_description" if man["description_placeholder"] else None),
                      ("no_library_entry" if not man["has_main"] else None))
                     if k]

        # verdict precedence: install-time payload behaviors are the worst.
        if man["has_install_hook"] and eval_in_hook:
            verdict = "CANDIDATE_INSTALL_OBFUSCATED_EVAL"
        elif man["has_install_hook"] and exec_in_hook:
            verdict = "CANDIDATE_INSTALL_CHILD_EXEC"
        elif man["has_install_hook"] and (has_exfil_link and exfil_in_hook) and hardcoded_host:
            verdict = "CANDIDATE_INSTALL_EXFIL"
        elif man["has_install_hook"] and launder_in_hook and hardcoded_host:
            verdict = "CANDIDATE_INSTALL_EXFIL"          # laundered variant
        elif (has_exfil_link or laundered) and hardcoded_host:
            verdict = "SUSPICIOUS_RUNTIME_EXFIL"
        elif decode_eval:
            verdict = "SUSPICIOUS_RUNTIME_OBFUSCATED_EVAL"
        elif man["has_install_hook"] and not ids and not outs and not execs and not decode_eval:
            verdict = "SAFE_INSTALL_HOOK_NO_EXFIL"
        elif ids and not has_exfil_link and not laundered:
            verdict = "SAFE_OSINFO_NO_EXFIL"
        elif outs and not ids:
            verdict = "SAFE_NETWORK_NO_IDENTIFIERS"
        elif execs and not exec_in_hook:
            verdict = "SAFE_RUNTIME_CHILD_EXEC"
        else:
            verdict = "SAFE_NO_SIGNALS"

        findings.append({
            "package": man["name"] or pkg_dir, "dir": pkg_dir,
            "version": man["version"],
            "install_hook": man["hooks"] if man["has_install_hook"] else None,
            "identifier_kinds": sorted(ids),
            "outbound_count": len(outs),
            "hardcoded_host": hardcoded_host,
            "known_collector": known_collector,
            "exfil_link": has_exfil_link,
            "exfil_in_install_hook": exfil_in_hook,
            "laundered_exfil": laundered,
            "decode_eval": bool(decode_eval),
            "eval_in_install_hook": eval_in_hook,
            "child_exec": bool(execs),
            "exec_in_install_hook": exec_in_hook,
            "exec_pipes_shell": exec_pipes_shell,
            "manifest_red_flags": red_flags,
            "verdict": verdict,
        })

    return {
        "schema": "malicious-npm-install-exfil/0.1",
        "note": ("CANDIDATE, never a definitive malicious claim. Flags the "
                 "dependency-confusion / install-hook data-exfil shape: a "
                 "lifecycle-hook script that harvests host/installer identifiers "
                 "and sends them to a hardcoded external collector. Identifier->"
                 "request linkage comes from Joern; manifest red flags corroborate."),
        "findings": findings,
    }


if __name__ == "__main__":
    root = sys.argv[1] if len(sys.argv) > 1 else "mal-fixture"
    raw = sys.argv[2] if len(sys.argv) > 2 else "mal-out/raw"
    print(json.dumps(derive(root, raw), indent=2))

#!/usr/bin/env python3
"""Scope-freeze precondition for ESCAPE-PARITY-BOUNDARY corpus scans.

The operating rule for this corpus is: *before every scan, freeze the
program's current scope and exclusions*.  A repository being public does not
make a finding in it payable, and program scope changes without notice, so a
scan is only permitted against a target whose scope text has been captured
and pinned at a known timestamp.

This script performs the capture.  It does not judge eligibility, does not
assess impact, and does not decide what to report.  It records four things
per target:

  1. which policy/scope URL was consulted,
  2. what the fetch actually returned (status, byte length, sha256),
  3. whether the returned bytes are usable as a scope record at all, and
  4. whether scanning is consequently permitted.

Capture statuses
----------------
SCOPE_FROZEN               server-rendered policy text captured and hashed
SCOPE_NOT_MACHINE_READABLE endpoint reachable but yields no scope text
                           (client-rendered shell, no public JSON, API 401)
PROGRAM_HANDLE_UNRESOLVED  the program endpoint does not resolve (404)
FETCH_FAILED               transport/status error

Only SCOPE_FROZEN permits scanning, and only when the target's languages are
also supported by the current engine.  Every other status blocks the scan and
names what a human must do to unblock it.  A blocked target is not a failure
of the target; it is an unverified precondition.
"""
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
EVIDENCE = os.path.join(HERE, "scope_evidence")

# Languages the ESCAPE-PARITY-BOUNDARY engine currently has a frontend and a
# frozen parser layer for.  Anything else blocks the scan on capability, not
# on scope.
SUPPORTED_LANGUAGES = {"JAVASCRIPT", "C_CPP"}

TARGETS = [
    {
        "key": "mozilla-gecko-dev",
        "priority": 1,
        "repo": "mozilla/gecko-dev",
        "program": "Mozilla Client Bug Bounty",
        "policy_urls": [
            "https://www.mozilla.org/en-US/security/client-bug-bounty/",
            "https://www.mozilla.org/en-US/security/bug-bounty/",
        ],
        "languages": ["C_CPP", "JAVASCRIPT"],
        "parser_surface": [
            "MIME type parsing", "HTTP header parsing", "cookie parsing",
            "certificate/name parsing", "URL and protocol parsing",
        ],
    },
    {
        "key": "nodejs-node",
        "priority": 2,
        "repo": "nodejs/node",
        "program": "Node.js (HackerOne)",
        "policy_urls": ["https://hackerone.com/nodejs"],
        "languages": ["C_CPP", "JAVASCRIPT"],
        "parser_surface": [
            "HTTP header parsing (llhttp callers)", "URL parsing (ada bindings)",
            "querystring", "JS-side header and MIME handling",
        ],
    },
    {
        "key": "rocketchat",
        "priority": 3,
        "repo": "RocketChat/Rocket.Chat",
        "program": "Rocket.Chat (HackerOne handle unconfirmed)",
        "policy_urls": ["https://hackerone.com/rocketchat"],
        "languages": ["JAVASCRIPT"],
        "parser_surface": [
            "message/markup text transforms", "import pipelines",
            "webhook payload handling",
        ],
    },
    {
        "key": "nextcloud-server",
        "priority": 4,
        "repo": "nextcloud/server",
        "program": "Nextcloud (HackerOne)",
        "policy_urls": ["https://hackerone.com/nextcloud"],
        "languages": ["PHP", "JAVASCRIPT"],
        "parser_surface": ["PHP text/import pipelines", "JS front-end transforms"],
    },
    {
        "key": "wordpress-develop",
        "priority": 5,
        "repo": "WordPress/wordpress-develop",
        "program": "WordPress (HackerOne)",
        "policy_urls": ["https://hackerone.com/wordpress"],
        "languages": ["PHP", "JAVASCRIPT"],
        "parser_surface": ["import/restore pipelines", "serialized text transforms"],
    },
    {
        "key": "gitlab",
        "priority": 6,
        "repo": "gitlabhq/gitlabhq",
        "program": "GitLab (HackerOne)",
        "policy_urls": ["https://hackerone.com/gitlab"],
        "languages": ["RUBY", "JAVASCRIPT"],
        "parser_surface": ["import/export pipelines", "markup transforms"],
    },
]

# Targets kept deliberately OUTSIDE the bounty corpus.  They are detector
# regression and precision material only.  Being open source does not make
# them bounty eligible, and nothing found in them is submitted anywhere.
NON_BOUNTY_REGRESSION_TARGETS = [
    {"repo": "taozhi8833998/node-sql-parser", "role": "precision", "languages": ["JAVASCRIPT"]},
    {"repo": "nene/sql-parser-cst", "role": "precision", "languages": ["JAVASCRIPT"]},
    {"repo": "mholt/PapaParse", "role": "regression", "languages": ["JAVASCRIPT"]},
    {"repo": "nodemailer/mailparser", "role": "regression", "languages": ["JAVASCRIPT"]},
]



# Anchor phrases whose surrounding sentence is the operative eligibility or
# exclusion rule for a target.  Each anchor is looked up *in the captured
# bytes*; an anchor that is not present is recorded as MISSING rather than
# quoted from memory, so this block cannot drift away from what was fetched.
SCOPE_ANCHORS = {
    "mozilla-gecko-dev": [
        ("eligibility", "Submissions must be either a security bug demonstrating"),
        ("severity_bar", "in order for it to be eligible for a bounty"),
        ("report_criteria", "must include a simple, reproducible test case"),
        ("not_actionable", "Bounties are not paid for issues which cannot be identified"),
        ("versions_in_scope", "Eligible security bugs may be present in any of the main development"),
        ("third_party_exclusion", "not to pay bounties for security bugs in or caused by additional third party software"),
        ("patch_gap_exclusion", "will not pay bounties that point out a patch gap"),
        ("submission_channel", "bugzilla client bug bounty form"),
    ],
}


def _plain_text(path):
    html = open(path, "r", encoding="utf-8", errors="replace").read()
    html = re.sub(r"(?is)<(script|style|noscript)\b.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return re.sub(r"\s+", " ", text).strip()


def extract_criteria(key, evidence_path):
    """Quote the operative scope rules directly out of the captured page."""
    anchors = SCOPE_ANCHORS.get(key)
    if not anchors or not evidence_path or not os.path.exists(evidence_path):
        return None
    text = _plain_text(evidence_path)
    out = []
    for label, anchor in anchors:
        i = text.find(anchor)
        if i < 0:
            out.append({"rule": label, "status": "ANCHOR_MISSING", "quote": None})
            continue
        # Bound the quote to a window around the anchor so a long bulleted
        # section does not drag in unrelated preceding text.
        floor = max(0, i - 240)
        start = text.rfind(". ", floor, i)
        start = floor if start < 0 else start + 2
        end = text.find(". ", i + len(anchor))
        end = len(text) if end < 0 else end + 1
        out.append({"rule": label, "status": "QUOTED",
                    "quote": text[start:end].strip()})
    return out


def fetch(url, dest):
    """Fetch url, writing the body to dest. Returns (status, nbytes, sha256)."""
    try:
        proc = subprocess.run(
            ["curl", "-sSL", "-o", dest, "-w", "%{http_code}", "--max-time", "60", url],
            capture_output=True, text=True, timeout=90,
        )
    except subprocess.TimeoutExpired:
        return ("TIMEOUT", 0, "")
    status = proc.stdout.strip() or "ERROR"
    if not os.path.exists(dest):
        return (status, 0, "")
    body = open(dest, "rb").read()
    return (status, len(body), hashlib.sha256(body).hexdigest())


def visible_text_length(path):
    """Bytes of visible text after stripping script/style/markup.

    A client-rendered page returns a large HTML body carrying essentially no
    readable scope text; that distinction is what separates a usable capture
    from an unusable one, so it is measured rather than assumed.
    """
    try:
        html = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return 0
    html = re.sub(r"(?is)<(script|style|noscript)\b.*?</\1>", " ", html)
    text = re.sub(r"(?s)<[^>]+>", " ", html)
    return len(re.sub(r"\s+", " ", text).strip())


# A capture carrying less readable text than this is a rendering shell, not a
# scope document.  Real policy pages run to thousands of characters.
MIN_SCOPE_TEXT = 2000


def capture(target):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    attempts = []
    frozen = None
    for i, url in enumerate(target["policy_urls"]):
        dest = os.path.join(EVIDENCE, "%s.%d.html" % (target["key"], i))
        status, nbytes, digest = fetch(url, dest)
        vis = visible_text_length(dest) if nbytes else 0
        att = {
            "url": url, "http_status": status, "bytes": nbytes,
            "sha256": digest, "visible_text_chars": vis,
            "evidence_file": os.path.relpath(dest, HERE) if nbytes else None,
        }
        attempts.append(att)
        if status == "200" and vis >= MIN_SCOPE_TEXT and frozen is None:
            frozen = att

    if frozen is not None:
        st = "SCOPE_FROZEN"
        note = "Policy text captured and hashed; scope pinned at fetch time."
        unblock = None
    elif any(a["http_status"] == "404" for a in attempts):
        st = "PROGRAM_HANDLE_UNRESOLVED"
        note = "Program endpoint returns 404; the assumed handle does not resolve."
        unblock = ("Confirm the program's real location (or that no public "
                   "program exists) before any scan of this repository.")
    elif any(a["http_status"] == "200" for a in attempts):
        st = "SCOPE_NOT_MACHINE_READABLE"
        note = ("Endpoint reachable but returns a client-rendered shell with no "
                "scope text; no public JSON view; the vendor API requires "
                "authentication.")
        unblock = ("A human must read the program scope in a browser and record "
                   "the in-scope assets and exclusions here before any scan.")
    else:
        st = "FETCH_FAILED"
        note = "No successful fetch of any policy URL."
        unblock = "Retry capture, or record the scope manually, before any scan."

    criteria = None
    if frozen is not None:
        criteria = extract_criteria(
            target["key"], os.path.join(HERE, frozen["evidence_file"]))

    unsupported = [l for l in target["languages"] if l not in SUPPORTED_LANGUAGES]
    engine_ready = any(l in SUPPORTED_LANGUAGES for l in target["languages"])

    blocked = []
    if st != "SCOPE_FROZEN":
        blocked.append("SCOPE_NOT_FROZEN")
    if not engine_ready:
        blocked.append("NO_SUPPORTED_LANGUAGE_FRONTEND")

    return {
        "key": target["key"],
        "priority": target["priority"],
        "repo": target["repo"],
        "program": target["program"],
        "languages": target["languages"],
        "unsupported_languages": unsupported,
        "parser_surface": target["parser_surface"],
        "captured_at_utc": ts,
        "scope_capture": st,
        "capture_note": note,
        "scope_criteria": criteria,
        "unblock_requirement": unblock,
        "attempts": attempts,
        "engine_ready": engine_ready,
        "scan_allowed": not blocked,
        "scan_blocked_by": blocked,
    }


def main():
    os.makedirs(EVIDENCE, exist_ok=True)
    records = [capture(t) for t in TARGETS]
    out = {
        "property": "ESCAPE-PARITY-BOUNDARY",
        "artifact": "bounty scope freeze",
        "frozen_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "rule": ("A scan of a bounty-corpus target is permitted only against a "
                 "target whose program scope was captured and hashed in this "
                 "record. Public source availability is not eligibility."),
        "supported_languages": sorted(SUPPORTED_LANGUAGES),
        "min_scope_text_chars": MIN_SCOPE_TEXT,
        "targets": records,
        "non_bounty_regression_targets": NON_BOUNTY_REGRESSION_TARGETS,
        "reportable": False,
    }
    path = os.path.join(HERE, "SCOPE_FREEZE.json")
    with open(path, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=False)
        fh.write("\n")

    print("SCOPE FREEZE  %s" % out["frozen_at_utc"])
    print("-" * 72)
    for r in records:
        print("%d. %-24s %-26s scan_allowed=%s"
              % (r["priority"], r["repo"], r["scope_capture"], r["scan_allowed"]))
        if r["scan_blocked_by"]:
            print("     blocked by: %s" % ", ".join(r["scan_blocked_by"]))
        for a in r["attempts"]:
            print("     %s -> %s (%s bytes, %s visible chars)"
                  % (a["url"], a["http_status"], a["bytes"], a["visible_text_chars"]))
    allowed = [r["repo"] for r in records if r["scan_allowed"]]
    print("-" * 72)
    print("scannable now: %s" % (", ".join(allowed) if allowed else "(none)"))
    print("wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

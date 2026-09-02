# ESCAPE-PARITY-BOUNDARY — bounty-scoped corpus

`reportable=false` for this revision. Nothing in this corpus is submitted
anywhere. This document defines *which repositories the property is pointed
at*, *what must be true before any of them is scanned*, and *what is
explicitly not a bounty target*.

## Operating rule

> Before every scan, freeze the program's current scope and exclusions.

Program scope changes without notice, and a repository being public does not
make a finding in it payable. `bounty_scope.py` implements this as a
precondition: it fetches each target's policy page, records the HTTP status,
byte length, sha256 and UTC timestamp, saves the raw body under
`scope_evidence/`, quotes the operative eligibility and exclusion sentences
directly out of the captured bytes, and emits `SCOPE_FREEZE.json`. A target
is scannable only when its scope was actually captured **and** the engine has
a frontend for at least one of its languages.

A scope capture is not a claim that a finding would be eligible. It is a
record of what the program said at a moment in time.

## Capture status (freeze of 2026-09-02T04:53Z)

| # | Repository | Languages | Scope capture | Scan allowed |
|---|---|---|---|---|
| 1 | mozilla/gecko-dev | C/C++, JS | `SCOPE_FROZEN` | **yes** |
| 2 | nodejs/node | C/C++, JS | `SCOPE_NOT_MACHINE_READABLE` | no |
| 3 | RocketChat/Rocket.Chat | JS | `PROGRAM_HANDLE_UNRESOLVED` | no |
| 4 | nextcloud/server | PHP, JS | `SCOPE_NOT_MACHINE_READABLE` | no |
| 5 | WordPress/wordpress-develop | PHP, JS | `SCOPE_NOT_MACHINE_READABLE` | no |
| 6 | gitlabhq/gitlabhq | Ruby, JS | `SCOPE_NOT_MACHINE_READABLE` | no |

Two distinct reasons sit behind those blocks, and they should not be
conflated:

**Scope could not be captured (2, 4, 5, 6).** The HackerOne program pages
return HTTP 200 but are client-rendered: the body is ~3.5 KB of shell
carrying **9 characters** of readable text ("HackerOne" plus a JavaScript-
disabled notice). There is no public JSON view — `hackerone.com/nodejs.json`
returns 404 — and `api.hackerone.com/v1/hackers/programs/nodejs` returns 401.
So the scope text exists but is not retrievable here. This is recorded as a
failed capture rather than waved through; a human must read the program scope
and record the in-scope assets and exclusions before any of these is scanned.

**The program handle does not resolve (3).** `hackerone.com/rocketchat`
returns **404**. The handle was assumed, not verified. Whether Rocket.Chat
runs a public program at another location — or at all — is unknown from here.
This is exactly the case the operating rule exists to catch: without the
freeze step, Rocket.Chat would have been scanned on the assumption that a
program existed.

**Engine capability is a separate axis.** Targets 4 and 5 need a PHP frontend
and 6 needs Ruby modelling for their primary language; each would remain
partially blocked on capability even with scope frozen. Their JS surface is
in reach today, their PHP/Ruby surface is not.

Net effect: **mozilla/gecko-dev is the only target scannable right now**, and
it is scannable because its policy is served as ordinary server-rendered HTML,
not because it is more likely to yield anything.

## What the Mozilla capture actually says

Quoted from the captured bytes (`scope_evidence/mozilla-gecko-dev.0.html`,
sha256 recorded in `SCOPE_FREEZE.json`), not from recollection:

- *"Submissions must be either a security bug demonstrating the ability to
  perform an unauthorized action or obtain access to otherwise-restricted
  information or an exploit mitigation bypass."*
- *"Typically, the security rating given by the Bounty Committee for a bug
  must be rated a "sec-high" or "sec-critical" in order for it to be eligible
  for a bounty."*
- *"A report should provide sufficient information to diagnose the
  vulnerability and produce a fix, and must include a simple, reproducible
  test case demonstrating the issue…"*
- *"Bounties are not paid for issues which cannot be identified or fixed from
  the report."*
- *"We reserve the right not to pay bounties for security bugs in or caused by
  additional third party software…"*
- *"We typically will not pay bounties that point out a patch gap between
  Firefox and a third party library we vendor…"*

These are the program's own words and they set the bar this property's output
does not currently clear.

## Standing instruction: the SplitMimetype result is not to be submitted

The `MimeType::SplitMimetype` result in `study/mozilla_probe/` **is not
submitted in its current state.** It establishes that Gecko's splitter and the
WHATWG Fetch specification disagree on an even-length escape run; it does not
establish a reachable security consequence, and no security assessment of it
has been made or should be inferred from this repository.

The captured policy above independently matches that instruction: it asks for
a security bug demonstrating an unauthorized action or restricted-information
access, a reproducible test case, and typically a sec-high or sec-critical
rating. A parser-correctness deviation, on its own, is none of those.

What would have to change before that position is revisited is a matter for a
separate decision, not for this document.

## Non-bounty regression and precision targets

These are detector-quality material only. They are **not** bounty targets, no
scope freeze applies to them, and nothing found in them is submitted:

| Repository | Role |
|---|---|
| taozhi8833998/node-sql-parser | precision |
| nene/sql-parser-cst | precision |
| mholt/PapaParse | regression |
| nodemailer/mailparser | regression |

They are dense in quoted-string boundary handling, which makes them good at
exposing detector defects — the same way real Gecko code exposed two of them
(the `BOOLEAN_TOGGLE` over-acceptance and the extracted-char pairing gap). Use
them to improve the analyzer, never as a source of submissions.

## Status of the npm 494-package pilot

The blind npm pilot is **stopped at 1 of 20 packages of its restarted run**,
and it is stopped because the research target changed to this bounty-scoped
corpus — not because of anything the pilot found or failed to find. Its
pre-registered selection (`study/PILOT_SELECTION_R04.json`) and its first-run
outcomes remain on record as development evidence. If it is resumed, it
resumes as its own revision with its own blind set; its partial results are
not folded into any corpus result here.

## Order of work

1. mozilla/gecko-dev — scope frozen, C/C++ and JS supported: scannable now,
   over the parser surface (MIME, HTTP headers, cookies, certificate/name
   parsing, URL and protocol parsing).
2. nodejs/node — blocked on scope capture only; engine is ready.
3. RocketChat/Rocket.Chat — blocked until the program's existence and location
   are confirmed.
4. nextcloud/server, WordPress/wordpress-develop — blocked on scope capture and
   on a PHP frontend.
5. gitlabhq/gitlabhq — blocked on scope capture and on Ruby modelling.

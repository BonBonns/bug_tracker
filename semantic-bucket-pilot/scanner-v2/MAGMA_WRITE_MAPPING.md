# Magma source-based write mapping — result (no build, no model calls)

Source-mapped **all** pre-registered candidates (no early stop) at pinned commits, plus
the recall-recovered ones. Full evidence per bug (commit, canary function+condition, actual
write, operand→length/capacity mapping, capacity provenance, vuln/fixed diff, status,
excerpt+file hash) is archived in `study/magma/write_mapping.json`. `pair_available` is
recorded **structurally only** — compilation and oracle execution remain build-stage.

## Recall sensitivity check (validates the candidate screen, does NOT change the frozen rule)

Re-screened the 105 canary-bearing bugs the frozen property filter rejected. It **missed
genuine destination-capacity write bugs** because its `CAP` regex did not match bare
`size`/`len` or subtraction forms: **TIF013** (`decodedSize > size` → `_TIFFmemcpy`),
**XML001** (`(size-len-strlen(prefix)) < strlen(name)+10` → `strcat`), **XML006**
(`size - strlen(buf) <= 2` → `strcat`); **XML011** (`size < 0`) is ambiguous (a sign
precondition, not a capacity comparison). Recorded as a recall gap in the screen; the
recovered bugs were added to the mapping set. The frozen 8-point **eligibility** rule is
unchanged.

## Mapping outcome (15 candidates: 11 frozen + 4 recall-recovered)

| status | n | bugs |
|--------|--:|------|
| **mapped** (source-confirmed destination-capacity write) | **7** | SND010, SND012, SND013, SSL004, TIF013, PNG003, TIF002 |
| not_mapped — read/precondition, not a dest write | 4 | SND025 (source over-read), PHP006 (over-read), SSL018 (validation; write interprocedural), SSL020 (min-length precondition) |
| not_mapped — source_unavailable here | 4 | XML001, XML006, XML011 (gitlab.gnome.org 403), PDF017 (gitlab.freedesktop.org 403) |

`source_available` is therefore FALSE for libxml2/poppler in this environment (proxy-blocked
hosts) — correcting the manifest's optimistic assumption from `fetch.sh` presence.

## The 7 mapped bugs span genuinely different proof obligations (the diversity Juliet lacked)

1. `offset(indx) + length(size) <= buffer_len` — SND010/012/013 (heap `header.ptr` sized
   `header.len`): a **positioned** write bound, absent from Juliet.
2. `length(num) <= sizeof(fixed_buf)` — SSL004 (`ebcdic_buf[1024]`): the classic fixed-buffer
   case, but in real code.
3. `length(decodedSize) <= param_capacity(size)` — TIF013 (`buffer`/`size` are **caller
   parameters**): interprocedural capacity.
4. `count(num) <= fixed_array_len` — PNG003 (`palette[PNG_MAX_PALETTE_LENGTH]`): array-index
   write.
5. `write_extent(avail_out) <= tbuf_size` — TIF002 (external `inflate` into `sp->tbuf`):
   write via a decoder call.

## Scanner-recognizability of the 7 mapped writes (feeds the build-stage `scanner_recognized`)

- standard `memcpy` (scanner-ready): SND010, SND012, SND013.
- library/wrapper copy needing a sink alias: SSL004 (`ascii2ebcdic`), TIF013 (`_TIFFmemcpy`).
- non-copy write needing new handling: PNG003 (pointer-walk struct write), TIF002 (`inflate`).

So even the 7 mapped bugs are not uniformly scanner-ready: 3/7 use standard `memcpy`, the
other 4 need sink-alias or non-copy-write support before `scanner_recognized` can pass. And
capacity is a caller parameter for TIF013 (needs the packet-expansion machinery). These are
the concrete build-stage tasks, now itemized per bug rather than assumed.

## Honest advancement

11 candidates → recall-corrected candidate set of 15 → **7 verified source-mapped
destination-capacity write bugs** across 4 real targets, spanning ~5 distinct proof
obligations. This already exceeds Juliet's ~1 review topology on genuine diversity, but 7
is below the 12 gate and every later stage (`scanner_recognized`, `packet_valid`,
`eligible`) still depends on the build-integration phase. No model calls.

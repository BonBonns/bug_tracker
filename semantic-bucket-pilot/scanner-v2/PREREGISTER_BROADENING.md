# Pre-registration — broadening to independent flow families (frozen BEFORE yields)

Committed **before** running the scanner on the new suites or examining any yield. The
goal is genuinely *independent* flow families for the destination-capacity accuracy
study, not more copies of the CWE806 reasoning pattern. We need **3 more** confirmatory
independent families to reach the 12-family gate (currently 8 baseline + 1 from
interprocedural expansion = 9), but we scan the **entire** predeclared set — we do not
stop after finding three.

## Fixed semantic property (unchanged)

> **Does the write length exceed the destination capacity?**

Only cases testing this exact property, via a **copy operation**, are eligible. Cases
testing a *different* property are excluded even if they live in a buffer-overflow
suite: source-buffer sufficiency, pointer underwrite, buffer under/over-read, array
index-out-of-bounds, format-string length, and integer-overflow-to-buffer-overflow all
introduce a different reasoning dimension and would inflate the family count dishonestly.

## Predeclared suites (mirror `arichardson/juliet-test-suite-c` @ `f88433e`)

Present in this C mirror and IN SCOPE:

| suite | destination-capacity mechanism | status |
|-------|--------------------------------|--------|
| `CWE121_Stack_Based_Buffer_Overflow` | fixed stack array `T dest[N]` | **in scope** (incl. nested `CWE805`/`CWE806` sub-idioms) |
| `CWE122_Heap_Based_Buffer_Overflow`  | heap allocation `malloc(N)`     | **in scope** (a genuinely distinct capacity provenance) |

Predeclared but **ABSENT** in this C mirror (documented; contribute 0, not silently dropped):

| suite | note |
|-------|------|
| `CWE805_Buffer_Access_with_Incorrect_Length` | no top-level C dir; its idiom appears **nested** under CWE121/CWE122, so it is covered there |
| `CWE787_Out_of_bounds_Write` | no C directory in this Juliet mirror |

Excluded by **property** (present in mirror but out of scope — different property):

- `CWE124_Buffer_Underwrite` (write before start — underwrite, not capacity overflow)
- `CWE126_Buffer_Overread`, `CWE127_Buffer_Underread` (reads, not writes)
- `CWE680_Integer_Overflow_to_Buffer_Overflow` (compound: integer-overflow reasoning)
- within CWE121/CWE122: source-buffer-sufficiency, pointer-underwrite, array-index
  (`CWE129`), format-string (`sprintf`/`snprintf`), char-by-char `loop`, and input
  (`fgets`/`fscanf`) sub-idioms — not copy operations / different property.

## Mechanical selection rule (frozen; a superset filter + the existing inclusion rule)

1. **File scope**: `.c` files under an in-scope suite whose filename contains a
   copy-operation idiom token: `memcpy | memmove | cpy | cat` (superset of the eligible
   copy sinks; `cpy` covers `strcpy/strncpy/wcscpy/wcsncpy`, `cat` covers
   `strcat/wcscat/strncat`). This is only an efficiency scope; it never admits anything
   the inclusion rule below rejects.
2. **Sanitize oracle leakage** (`juliet_sanitize.py`, unchanged broadened token set).
3. **Run the frozen scanner** (`c2cpg 4.0.608 → export_c_cpp_facts_v03.sc →
   normalize_c_cpp_facts_v03.py → oob_runtime_capacity_v2`).
4. **Inclusion rule** (unchanged from the CWE806 corpus): exact copy sink
   (`memcpy|memmove|strcpy|strncpy|wcscpy|wcsncpy|strcat|wcscat`) at the POTENTIAL-FLAW
   line, destination is the bound-capacity buffer and appears in the sink statement, no
   ambiguous multi-sink line, symbolic write width, route ==
   `semantic_relationship_review`.
5. **Partition** packet-identifiable vs packet-insufficient (identical enclosing-function
   packet on both sides = insufficient).
6. **Sufficiency proof** (`juliet_packet_expansion.py` machinery): mechanically establish
   destination capacity, source write length, and their relationship — all structure-only.
7. **Collapse** pass-through and superficial variants by flow topology
   (`flow_skeleton`, storage-class-normalized, inert-forwarder-excluded).
8. **Recalculate** the confirmatory independent-family count on the pooled
   packet-identifiable set (CWE806 baseline + new suites).

## Analysis commitments (frozen)

- Same seeds/salts/gate as the frozen corpus: `MIN_FAMILIES = 12`, `DEV_FRACTION = 0.30`,
  `SPLIT_SALT = "juliet-cwe806-v1"` (the salt name is historical; it is the study-wide
  family-split salt and is not changed).
- The oracle/label is never read during selection, expansion, or sufficiency extraction;
  it is read only to (a) partition vulnerable/safe for the both-sided family test and
  (b) cross-check the exceeds/within verdict.
- Report **all** yields for the entire predeclared set, including zeros (e.g. if CWE122
  heap capacity is not bound by the current V2 producer, that is reported, not hidden).
- The remaining **56** CWE806 packet-insufficient cases are **not** chased here; they are
  a documented future coverage-extension population.
- No model calls at any point.

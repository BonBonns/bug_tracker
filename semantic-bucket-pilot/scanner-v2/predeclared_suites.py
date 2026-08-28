#!/usr/bin/env python3
"""Machine-readable pre-registration (frozen BEFORE yields). See PREREGISTER_BROADENING.md.

Fixed property: does the write length exceed the DESTINATION capacity (via a copy op)?
"""

PINNED_COMMIT = "f88433e3443648a17671398797a04ea1f8e1a274"
MIRROR = "arichardson/juliet-test-suite-c"

# Suites in scope AND present in this C mirror.
IN_SCOPE_SUITES = [
    "CWE121_Stack_Based_Buffer_Overflow",   # fixed stack-array capacity
    "CWE122_Heap_Based_Buffer_Overflow",    # heap malloc(N) capacity (distinct provenance)
]

# Predeclared but absent in this C mirror (documented; contribute 0).
PREDECLARED_ABSENT = {
    "CWE805_Buffer_Access_with_Incorrect_Length":
        "no top-level C dir; idiom nested under CWE121/CWE122",
    "CWE787_Out_of_bounds_Write": "no C directory in this mirror",
}

# Present in mirror but excluded by PROPERTY (not the destination-capacity copy property).
EXCLUDED_BY_PROPERTY = {
    "CWE124_Buffer_Underwrite": "underwrite (write before start)",
    "CWE126_Buffer_Overread": "read, not write",
    "CWE127_Buffer_Underread": "read, not write",
    "CWE680_Integer_Overflow_to_Buffer_Overflow": "compound integer-overflow property",
}

# Filename copy-idiom tokens (efficiency superset of the eligible copy sinks).
COPY_IDIOM_TOKENS = ["memcpy", "memmove", "cpy", "cat"]

# Within-suite sub-idioms excluded by property/mechanism (enforced by inclusion rule too).
EXCLUDED_SUBIDIOM_TOKENS = ["loop", "snprintf", "sprintf", "fgets", "fscanf", "CWE129"]

# Frozen analysis constants (study-wide; unchanged).
MIN_FAMILIES = 12
DEV_FRACTION = 0.30
SPLIT_SALT = "juliet-cwe806-v1"
FILE_EXT = ".c"

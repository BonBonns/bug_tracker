# Historical parser-correctness differential

Scope: **parser correctness only.** This record covers a published before/after change to
one quoted-string boundary rule. It is used solely to confirm that the property's
correctness rule distinguishes the two forms. No broader operational scenario associated
with the original report is reproduced, described, or evaluated here. This fixture is
**outside the npm evaluation totals**.

## Source identity (published, pinned)

| form | published version | file |
|---|---|---|
| historical faulty parser | all-in-one-wp-migration **7.109** | `lib/vendor/servmask/database/class-ai1wm-database.php` |
| historical corrected parser | all-in-one-wp-migration **7.110** | `lib/vendor/servmask/database/class-ai1wm-database.php` |

Retrieved from the published plugin archive (`downloads.wordpress.org/plugin/...`).
sha256 of the two published files as retrieved:

```
ce141050397789ca08e4ee2dad6385eb178f3f3b70008619490775953bc6d011  7.109 class-ai1wm-database.php
034bb692c099ff381d391bf747b07fd11d94fe9490f2810fc5e84b81669cc930  7.110 class-ai1wm-database.php
```

The change boundary was located mechanically by probing published versions
(7.40/7.60/7.78/7.85/7.95/7.96/7.97/7.98/7.99/7.100/7.104/7.106/7.108/**7.109**/**7.110**);
every probed version at or below 7.109 carries the faulty form, 7.110 carries the
corrected form.

## The two boundary rules (as actually compiled, after PHP string-literal processing)

```
historical faulty parser     /'(.*?)(?<!\\)'/S
historical corrected parser  /'((?:[^'\\]++|\\.)*+)'/sS
```

- The **faulty** form ends the quoted value at the first quote whose *single* immediately
  preceding character is not the escape character. It never establishes the parity of the
  full consecutive escape run.
- The **corrected** form consumes the body as an alternation of non-escape runs and
  escape-pairs, so every escape character is consumed in a pair. Escape-run parity is
  established by construction.

## Behavioural confirmation (`differential.php`, output in `differential_output.txt`)

Synthetic quoted-text inputs only; the two published patterns are applied directly and
nothing else from either version is executed.

**Input A — even-length escape run (2) before the quote.** Parity rule: an even run means
the quote *terminates* the string.

| form | matches | captured contents |
|---|---|---|
| faulty | 1 | `abc\\', ` |
| corrected | 2 | `abc\\` and `next` |

The faulty form consumed straight through the true closing quote, the separator, and the
next value's opening quote — the quoted-value boundary is not preserved. **Confirmed:
the faulty form mishandles an even-length escape run.**

**Input B — odd-length escape run (1) before the quote.** Parity rule: an odd run means
the quote is *escaped* and the string continues.

| form | matches | captured contents |
|---|---|---|
| faulty | 1 | `abc\', ` |
| corrected | 1 | `abc\', ` |

Identical. **Confirmed: the corrected form preserves quote boundaries**, including on the
odd-run case that the one-character rule already happened to handle correctly.

(Contents above are shown unescaped; `differential_output.txt` prints them via
`var_export`, which doubles each backslash and escapes each quote.)

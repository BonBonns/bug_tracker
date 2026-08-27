# Freeze reference — frozen-scanner-corpus-v1

This is the durable, in-repo freeze marker. (A git tag
`frozen-scanner-corpus-v1` was created locally but the remote integration for
this session accepts only branch refs, not tag refs, so the marker is recorded
here where it pushes with the branch.)

| what | commit |
|------|--------|
| **Scanner + builder machinery frozen** | `b704aab26e3b7872d21350816ac9d60aaf0e4d3f` |
| **Complete freeze (scanner + corpus outputs)** | `0a6703aecc76dcc312e529442ab596d9a53a36c3` |

`manifest.json → scanner_commit` is `b704aab` — the commit whose builder +
producers + schema produced every record in this corpus. The corpus outputs
were committed on top at `0a6703a` (byte-identical across two builds).

## Version policy

This is **v1**. Future scanner changes (new producers, new reason codes, schema
v1.1/v2, taxonomy edits) produce a **new** corpus version at a new commit and a
new marker; the v1 corpus at `0a6703a` is **not modified in place**. Anything
consuming the frozen corpus should pin to these commits.

To recreate the tag locally:

```sh
git tag -a frozen-scanner-corpus-v1 0a6703a -m "Frozen TChecker scanner + corpus v1"
```

#!/usr/bin/env python3
"""Regression controls for scan_repo.engine's process boundary."""
import importlib.util
import pathlib
import subprocess
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('scan_repo', HERE / 'scan_repo.py')
scan_repo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scan_repo)


def exercise(completed, expect_failure):
    original = scan_repo.subprocess.run
    scan_repo.subprocess.run = lambda *a, **kw: completed
    try:
        with tempfile.TemporaryDirectory() as td:
            out = pathlib.Path(td) / 'engine.out'
            try:
                result = scan_repo.engine('build', 'program.json', [], out)
            except SystemExit as exc:
                assert expect_failure, f'unexpected failure: {exc}'
                assert 'ENGINE FAILED' in str(exc)
                assert out.read_text() == completed.stdout + completed.stderr
            else:
                assert not expect_failure, 'non-zero engine exit was accepted'
                assert result == completed.stdout
                assert out.read_text() == completed.stdout + completed.stderr
    finally:
        scan_repo.subprocess.run = original


exercise(subprocess.CompletedProcess([], 0, 'SUMMARY ok\n', ''), False)
exercise(subprocess.CompletedProcess([], 17, '', 'synthetic engine failure\n'), True)

duplicate_functions = [
    {'id': 1, 'name': 'get', 'is_external': False},
    {'id': 2, 'name': 'get', 'is_external': False},
]
duplicate_output = (
    'SUMMARY get resolution=EXACT proven=[0] may=[] unknown=false completeness=COMPLETE\n'
    'SUMMARY get resolution=UNRESOLVED proven=[] may=[] unknown=true completeness=UNKNOWN\n'
)
bound = scan_repo.bind_summaries_to_functions(duplicate_output, duplicate_functions)
assert bound[1]['proven'] == [0] and not bound[1]['unknown']
assert bound[2]['proven'] == [] and bound[2]['unknown']
try:
    scan_repo.bind_summaries_to_functions(duplicate_output.replace('SUMMARY get', 'SUMMARY put', 1), duplicate_functions)
except ValueError as exc:
    assert 'order mismatch' in str(exc)
else:
    raise AssertionError('summary/function order contamination was accepted')

with tempfile.TemporaryDirectory() as td:
    # The repository itself may live below a directory named "tests"; only
    # repository-relative directory policy is allowed to exclude files.
    repo = pathlib.Path(td) / 'tests' / 'repo'
    (repo / 'a').mkdir(parents=True)
    (repo / 'b').mkdir()
    (repo / 'vendor').mkdir()
    (repo / 'a' / 'same.js').write_text('const source = 1;\n')
    (repo / 'b' / 'same.js').write_text('const sink = 2;\n')
    (repo / 'vendor' / 'excluded.js').write_text('throw new Error();\n')
    selected = scan_repo.collect(repo, {'.js'}, cap=None)
    assert len(selected) == 2, selected
    staged = pathlib.Path(td) / 'staged'
    scan_repo.stage(selected, staged, repo)
    assert (staged / 'a' / 'same.js').read_text() == 'const source = 1;\n'
    assert (staged / 'b' / 'same.js').read_text() == 'const sink = 2;\n'
    ca = repo / 'a' / 'same.cpp'
    cb = repo / 'b' / 'same.cpp'
    assert scan_repo.preprocessed_target(repo, ca, staged) != scan_repo.preprocessed_target(repo, cb, staged)

with tempfile.TemporaryDirectory() as td:
    # SCAN-SIDECAR-R01: the repository front door must load every fact family
    # produced for origins/expressions.  The direct frontend gates already passed
    # these files manually, so this exact integration omission previously escaped.
    doc = pathlib.Path(td) / 'program.json'
    doc.write_text('{}')
    for suffix in ('.memory.json', '.expression.json', '.reachingdef.json', '.source.json'):
        pathlib.Path(str(doc) + suffix).write_text('{}')
    c_extras = scan_repo.program_sidecars('c_cpp', doc)
    assert [p.name for p in c_extras] == [
        'program.json.memory.json', 'program.json.expression.json',
        'program.json.reachingdef.json', 'program.json.source.json']
    js_extras = scan_repo.program_sidecars('js_ts', doc)
    assert [p.name for p in js_extras] == [
        'program.json.expression.json', 'program.json.source.json']
    pathlib.Path(str(doc) + '.source.json').unlink()
    assert [p.name for p in scan_repo.program_sidecars('js_ts', doc)] == [
        'program.json.expression.json']
    try:
        scan_repo.program_sidecars('unknown', doc)
    except ValueError as exc:
        assert 'unknown scan side' in str(exc)
    else:
        raise AssertionError('unknown scan side was accepted')

print('SCAN_REPO_CONTROLS=14/14')

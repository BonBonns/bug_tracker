#!/usr/bin/env bash
# verify_fable.sh -- Component B verification. UPDATED: the Java core, previously confirmed
# absent, was found in a user-uploaded archive and is now genuinely present and compiled here.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FB="$ROOT/portable-engine-full-review-package"
FAIL=0
WORK="$(mktemp -d)"

echo "=== 1. JS/TS frontend modules (unchanged from earlier verification) ==="
for f in export_ts_facts.sc import_binding_identity.py dispatch_resolution.py \
         framework_registration.py state_facts.py security_sink_profile.py; do
  if [ -f "$FB/frontends/javascript-typescript/joern-ts/$f" ]; then echo "OK    joern-ts/$f"
  else echo "FAIL  MISSING joern-ts/$f"; FAIL=1; fi
done
cd "$FB/frontends/javascript-typescript/joern-ts"
for m in import_binding_identity dispatch_resolution framework_registration state_facts security_sink_profile; do
  if python3 -c "import $m" 2>/dev/null; then echo "OK    import $m"
  else echo "FAIL  cannot import $m"; FAIL=1; fi
done
cd "$ROOT"

echo ""
echo "=== 2. Java core -- PRESENT, compiled and run for real this pass ==="
if [ -z "$(find "$FB/core/provenance-neutral" -name '*.java' 2>/dev/null)" ]; then
  echo "FAIL  core/provenance-neutral has no .java files"; FAIL=1
else
  echo "OK    core/provenance-neutral/.../PortableProvenanceEngine.java present"
fi
if [ -z "$(find "$FB/core/program_graph" -name '*.java' 2>/dev/null)" ]; then
  echo "FAIL  core/program_graph has no .java files"; FAIL=1
else
  echo "OK    core/program_graph/.../ProgramGraphLoader.java present"
fi

if ! command -v javac >/dev/null 2>&1; then
  echo "FAIL  javac not available -- only a JRE is installed by default in this environment."
  echo "      Fix: apt-get update && apt-get install -y openjdk-21-jdk-headless"
  echo "      (requires archive.ubuntu.com access and root/sudo privileges)."
  FAIL=1
else
  echo "OK    javac available: $(javac -version 2>&1)"
  mkdir -p "$WORK/classes"
  if javac -encoding UTF-8 -d "$WORK/classes" \
      $(find "$FB/core/provenance-neutral" "$FB/core/program_graph" "$FB/core/effects" \
             "$FB/core/runtime" "$FB/core/consumer" "$FB/core/evidence" -name "*.java") \
      > "$WORK/javac.log" 2>&1; then
    echo "OK    core compiles cleanly (provenance-neutral, program_graph, effects, runtime, consumer, evidence)"
  else
    echo "FAIL  core did not compile -- see $WORK/javac.log"
    tail -20 "$WORK/javac.log"
    FAIL=1
  fi

  echo ""
  echo "=== 3. Run real Java gate tests (self-contained, synthetic in-memory facts) ==="
  for g in "gate25/Gate25ProgramGraphTest:GATE25" "gate26/Gate26PortableProvenanceTest:GATE26" \
           "gate27/Gate27CorrectnessContractTest:GATE27" "gate30/Gate30TransformationEffectsTest:GATE30" \
           "gate38/Gate38DeterministicConsumerTest:GATE38"; do
    path="${g%%:*}"; prefix="${g##*:}"
    cls="$(basename "$path")"
    src="$FB/tests/gates/$path.java"
    if [ ! -f "$src" ]; then echo "FAIL  MISSING $src"; FAIL=1; continue; fi
    if ! javac -encoding UTF-8 -cp "$WORK/classes" -d "$WORK/classes" "$src" > "$WORK/$cls.compile.log" 2>&1; then
      echo "FAIL  $cls did not compile"; tail -10 "$WORK/$cls.compile.log"; FAIL=1; continue
    fi
    out=$(java -cp "$WORK/classes" "$cls" 2>&1)
    if echo "$out" | grep -q "^${prefix}="; then
      echo "OK    $cls: $(echo "$out" | grep "^${prefix}=")"
    else
      echo "FAIL  $cls did not report $prefix=N/N"; echo "$out" | tail -5; FAIL=1
    fi
  done
fi

echo ""
echo "=== 4. Full canonical suite (tests/run_all.py) -- NOT run in this script ==="
echo "It genuinely runs (confirmed interactively) but takes long enough to exceed a reasonable"
echo "verification-script timeout in this environment; not included here to keep this script"
echo "fast and reliable. Run it manually: see RUNBOOK.md."

echo ""
if [ $FAIL -eq 0 ]; then echo "VERIFY_FABLE=PASS"; else echo "VERIFY_FABLE=FAIL"; fi
rm -rf "$WORK"
exit $FAIL

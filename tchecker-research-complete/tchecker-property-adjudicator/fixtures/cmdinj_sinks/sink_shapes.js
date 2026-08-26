// Command injection sink-semantics characterization fixtures. Each function isolates ONE call
// shape. No property-propagation logic here -- pure sink characterization, exactly matching the
// discipline used for SSRF Stage 1 and path-traversal Stage 1.
const { exec, execSync, execFile, execFileSync, spawn, spawnSync } = require('child_process');

// --- exec/execSync: ALWAYS runs through a shell -- the whole command string is COMMAND_SYNTAX ---
function exec_basic(userInput) {
  return exec('tool ' + userInput);
}
function exec_withCallback(userInput) {
  return exec('tool ' + userInput, (err, stdout) => {});
}
function execSync_basic(userInput) {
  return execSync('tool ' + userInput);
}

// --- execFile/execFileSync: NO shell by default -- args array elements are ARGUMENT_ONLY, no
// shell metacharacter interpretation ---
function execFile_noShellOption(userInput) {
  // shell option not set at all -- defaults to false
  return execFile('tool', [userInput]);
}
function execFile_explicitShellFalse(userInput) {
  return execFile('tool', [userInput], { shell: false });
}
function execFileSync_basic(userInput) {
  return execFileSync('tool', [userInput]);
}

// --- execFile WITH shell:true: per Node's own documented warning, ANY input (including args
// array elements) becomes subject to shell metacharacter interpretation -- the "array doesn't
// save you" trap ---
function execFile_withShellTrue(userInput) {
  return execFile('tool', [userInput], { shell: true });
}

// --- spawn/spawnSync: same structure as execFile -- shell defaults to false ---
function spawn_noShellOption(userInput) {
  return spawn('tool', [userInput]);
}
function spawn_explicitShellFalse(userInput) {
  return spawn('tool', [userInput], { shell: false });
}
function spawnSync_basic(userInput) {
  return spawnSync('tool', [userInput]);
}

// --- spawn WITH shell:true, single command-string form (no separate args array) ---
function spawn_commandStringShellTrue(userInput) {
  return spawn('tool ' + userInput, { shell: true });
}

// --- spawn WITH shell:true, array args form -- same trap as execFile ---
function spawn_arrayArgsShellTrue(userInput) {
  return spawn('tool', [userInput], { shell: true });
}

// --- spawn with a custom shell path (string, not boolean) -- still shell mode ---
function spawn_customShellString(userInput) {
  return spawn('tool', [userInput], { shell: '/bin/bash' });
}

// --- negative-ish structural control: the FILE/PROGRAM argument itself, not args -- a
// different operand entirely (EXECUTABLE_PATH component, not COMMAND_SYNTAX or ARGUMENT) ---
function execFile_attackerControlsProgram(userProgram) {
  return execFile(userProgram, ['--version']);
}

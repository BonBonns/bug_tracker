// CMDINJ-PROP-R01 (Stage 2A): known semantic effects for ATTACKER_CONTROL_OF_COMMAND_SYNTAX.
// Explicit finite allowlists and well-defined shell-word quoting ONLY -- no generic regex
// metacharacter stripping here (that is Stage 2B, characterized separately, never trusted the
// same way).
const Meteor = { methods: (obj) => obj };
const { exec, spawn, execFile } = require('child_process');
const { quote } = require('shell-quote');

// --- COMMAND_SYNTAX, no transform: UNSAFE ---
async function commandSyntax_noTransform(x) {
  return exec(`echo ${x}`);
}

// --- COMMAND_SYNTAX, shell-quote as a whole shell word, used verbatim: SHELL_SYNTAX_NEUTRALIZED ---
async function commandSyntax_shellQuoted(x) {
  return exec(`echo ${quote([x])}`);
}

// --- COMMAND_SYNTAX, shell-quote's output RE-WRAPPED in another pair of quotes: per shell-quote's
// own documentation, this corrupts the escaping (backslash escapes become literal characters) --
// must NOT be claimed sanitized ---
async function commandSyntax_shellQuotedThenRewrapped(x) {
  return exec(`echo '${quote([x])}'`);
}

// --- ARGUMENT_ONLY, no transform: no shell-injection property at all (different sink shape) ---
async function argumentOnly_noTransform(x) {
  return spawn('echo', [x]);
}

// --- COMMAND_SYNTAX via spawn+shell:true, no transform: UNSAFE ---
async function commandSyntax_spawnShellTrue_noTransform(x) {
  return spawn('echo', [x], { shell: true });
}

// --- COMMAND_SYNTAX via spawn+shell:true, array element correctly shell-quoted: candidate
// neutralization (same underlying mechanism as the exec case -- shell mode is on, so this array
// element IS shell-interpreted, per Stage 1's frozen "array doesn't save you" finding; quoting it
// properly is the correct, matching countermeasure) ---
async function commandSyntax_spawnShellTrue_quoted(x) {
  return spawn('echo', [quote([x])], { shell: true });
}

// --- EXECUTABLE_PATH, shell-quote applied: quoting does NOT solve attacker control of WHICH
// executable runs -- still executable-controlled ---
async function executablePath_shellQuoted_stillControlled(x) {
  return spawn(quote([x]), []);
}

// --- EXECUTABLE_PATH, finite allowlist lookup: CONTROLLED (constrained to a known-safe set) ---
async function executablePath_allowlisted(x) {
  const allowlist = { ls: '/bin/ls', cat: '/bin/cat', echo: '/bin/echo' };
  return spawn(allowlist[x], []);
}

// --- ARGUMENT_ONLY, argument-count check only: constrained args, NOT "shell sanitized" (there
// was never a shell-syntax risk here to begin with -- the count check is a different kind of
// constraint entirely) ---
async function argumentOnly_argCountChecked(x) {
  const args = [x].slice(0, 1);
  return execFile('/bin/tool', args);
}

// --- COMMAND_SYNTAX via execFile+shell:true, argument-count check only: still unsafe -- an
// arg-count constraint does nothing to address shell metacharacter risk ---
async function commandSyntax_execFileShellTrue_argCountOnly(x) {
  const args = [x].slice(0, 1);
  return execFile('/bin/tool', args, { shell: true });
}

Meteor.methods({
  commandSyntax_noTransform, commandSyntax_shellQuoted, commandSyntax_shellQuotedThenRewrapped,
  argumentOnly_noTransform, commandSyntax_spawnShellTrue_noTransform,
  commandSyntax_spawnShellTrue_quoted, executablePath_shellQuoted_stillControlled,
  executablePath_allowlisted, argumentOnly_argCountChecked,
  commandSyntax_execFileShellTrue_argCountOnly,
});

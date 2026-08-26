// Path traversal sink-semantics characterization fixtures. Each function isolates ONE call shape.
// No property-propagation logic is exercised here -- pure sink characterization, exactly matching
// the discipline used for SSRF Stage 1.
const fs = require('fs');
const path = require('path');
const express = require('express');

// --- fs.readFile / readFileSync family ---
function readFile_basic(userPath) {
  return fs.readFile(userPath, (err, data) => {});
}
function readFileSync_basic(userPath) {
  return fs.readFileSync(userPath);
}
function readFile_withEncoding(userPath) {
  return fs.readFile(userPath, 'utf8', (err, data) => {});
}
function readFile_withOptionsObject(userPath) {
  // options object present, but has NO path-bearing field -- must not treat every field as
  // path-bearing the same way SSRF's axios case required distinguishing baseURL/url
  return fs.readFile(userPath, { encoding: 'utf8', flag: 'r' }, (err, data) => {});
}

// --- fs.writeFile / writeFileSync family: path is arg0, DATA is arg1 -- must not conflate ---
function writeFile_basic(userPath, attackerData) {
  return fs.writeFile(userPath, attackerData, (err) => {});
}
function writeFileSync_basic(userPath, attackerData) {
  return fs.writeFileSync(userPath, attackerData);
}

// --- fs.createReadStream / createWriteStream family ---
function createReadStream_basic(userPath) {
  return fs.createReadStream(userPath);
}
function createWriteStream_basic(userPath) {
  return fs.createWriteStream(userPath);
}
function createReadStream_withOptions(userPath) {
  return fs.createReadStream(userPath, { start: 0, end: 100 });
}

// --- fs.unlink / unlinkSync (delete) ---
function unlink_basic(userPath) {
  return fs.unlink(userPath, (err) => {});
}

// --- fs.open / openSync ---
function open_basic(userPath) {
  return fs.open(userPath, 'r', (err, fd) => {});
}

// --- fs.stat / existsSync ---
function stat_basic(userPath) {
  return fs.stat(userPath, (err, stats) => {});
}
function existsSync_basic(userPath) {
  return fs.existsSync(userPath);
}

// --- Express res.sendFile: TWO forms, exactly analogous to SSRF's axios baseURL/url split ---
function sendFile_noRoot(userPath, res) {
  // NO root option: userPath is used AS-IS, full traversal control (including absolute paths)
  return res.sendFile(userPath);
}
function sendFile_withRoot(userPath, res) {
  // root option present: userPath is resolved RELATIVE TO root -- traversal is constrained to
  // stay within root (Express validates this internally), the exact analogue of axios's
  // baseURL+url split where url becomes path-relative rather than the full destination
  return res.sendFile(userPath, { root: '/var/www/public' });
}
function sendFile_rootFromAttacker(attackerRoot, res) {
  // the ROOT itself is attacker-controlled -- root is the path-bearing operand here, not any
  // fixed literal path
  return res.sendFile('report.pdf', { root: attackerRoot });
}

// --- Express res.download: same two-argument shape as sendFile ---
function download_noOptions(userPath, res) {
  return res.download(userPath);
}
function download_withFilename(userPath, res) {
  // second arg here is a DOWNLOAD FILENAME (what the browser shows), NOT a root/options object --
  // must not be confused with sendFile's options-object second argument
  return res.download(userPath, 'report.pdf');
}

// --- unresolved wrapper: must ABSTAIN, not guess ---
function callsUnresolvedWrapper(userPath) {
  return someFileLibrary.readSomehow(userPath);
}

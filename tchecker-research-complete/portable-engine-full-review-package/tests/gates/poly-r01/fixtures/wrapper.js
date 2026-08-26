const native = require('./build/native.node');

// EXACT crossing: JS param -> native dbl -> returns its param -> back to JS.
function wrap(a) {
	return native.dbl(a);
}

// position shuffle across the boundary: native returns param 1.
function wrapShuffle(a, b) {
	return native.shuffled(a, b);
}

// native side returns a computed value: no positional provenance survives.
function wrapOpaque(a) {
	return native.opaque(a);
}

// no registration for this name: must stay unlinked and non-EXACT.
function wrapMissing(a) {
	return native.missing(a);
}

module.exports = { wrap, wrapShuffle, wrapOpaque, wrapMissing };

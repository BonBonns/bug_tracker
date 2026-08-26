const native = require('./build/native.node');

// marshalling: JS positional args cross into CallbackInfo slot reads.
function callFirst(a, b) {
	return native.first(a, b);
}

// the discriminator: C++ reads info[1], engine must project JS arg 1.
function callSecond(a, b) {
	return native.second(a, b);
}

// slot value flows through a C++ local before returning.
function callVia(a, b) {
	return native.via_local(a, b);
}

// variable slot index: must abstain, never guess.
function callVar(a, b) {
	return native.var_idx(a, b);
}

module.exports = { callFirst, callSecond, callVia, callVar };

// N-API-marshalling fixture: callees take a single CallbackInfo and read
// positional slots. c2cpg parses Napi:: without headers.
int first(Napi::CallbackInfo info) {
	return info[0];
}

int second(Napi::CallbackInfo info) {
	return info[1];
}

int viaLocal(Napi::CallbackInfo info) {
	int v = info[1];
	return v;
}

int varIdx(Napi::CallbackInfo info) {
	return info[info.Length()];
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "first"), Napi::Function::New(env, first));
	exports.Set(Napi::String::New(env, "second"), Napi::Function::New(env, second));
	exports.Set(Napi::String::New(env, "via_local"), Napi::Function::New(env, viaLocal));
	exports.Set(Napi::String::New(env, "var_idx"), Napi::Function::New(env, varIdx));
	return exports;
}

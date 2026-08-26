// Mini N-API-shaped native module (c2cpg parses this without headers).
int dbl(int x) {
	return x;
}

int shuffled(int a, int b) {
	return b;
}

int opaque(int x) {
	return x + 1;
}

Napi::Object init(Napi::Env env, Napi::Object exports) {
	exports.Set(Napi::String::New(env, "dbl"), Napi::Function::New(env, dbl));
	exports.Set(Napi::String::New(env, "shuffled"), Napi::Function::New(env, shuffled));
	exports.Set(Napi::String::New(env, "opaque"), Napi::Function::New(env, opaque));
	return exports;
}

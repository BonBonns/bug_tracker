// BLIND TEST (real npm package, NOT tuned to before this run): Automattic/node-canvas,
// src/Canvas.cc, function streamPDF (HEAD as of this mining pass, a real, widely-used npm
// native addon -- millions of weekly downloads). Cairo's C PDF-writing machinery invokes
// this callback with a raw byte chunk; the real code wraps it into a Napi::Buffer via the
// 3-argument EXTERNAL-DATA overload (Napi::Buffer<T>::New(env, T* data, size_t length) --
// napi.h's own real overload, NOT the plain 2-arg allocating one this session's R02
// contract initially curated) and passes the result DIRECTLY to a JS callback with NO
// IsEmpty()/env.IsExceptionPending() check at all. The real source's own comment
// (preserved verbatim below) flags an UNRELATED lifetime concern about the same line, not
// this one -- the missing validity check is not something node-canvas's own authors
// called out.
//
// Constructor call, guard (absent), and use are copied VERBATIM from the real function;
// surrounding machinery (Napi::AsyncContext/HandleScope/FunctionReference, PdfStreamInfo,
// cairo_status_t) is stubbed to the minimum needed to parse.
struct napi_env__; using napi_env = napi_env__*;
struct Env { napi_env raw; };

template <typename T>
class Buffer {
 public:
  static Buffer<T> New(napi_env env, T* data, unsigned long length);
  bool IsEmpty() const;
};

class Value {
 public:
  Value();
  Value(Buffer<unsigned char> b);
};

class HandleScope { public: HandleScope(Env env); };
class AsyncContext { public: AsyncContext(Env env, const char* name); };

class Global {};

class FunctionReference {
 public:
  Env Env_() const;
  void MakeCallback(Global global, Value args[3], AsyncContext& async);
};

struct PdfStreamInfo {
  FunctionReference fn;
  unsigned int len;
  unsigned char* data;
};

typedef int cairo_status_t;
#define CAIRO_STATUS_SUCCESS 0

/*
 * Canvas::StreamPDF callback.
 */
static cairo_status_t
streamPDF(void *c, const unsigned char *data, unsigned len) {
  PdfStreamInfo* streaminfo = static_cast<PdfStreamInfo*>(c);
  Env env = streaminfo->fn.Env_();
  HandleScope scope(env);
  AsyncContext async(env, "canvas:StreamPDF");
  // TODO this is technically wrong, we're returning a pointer to the data in a
  // vector in a class with automatic storage duration. If the canvas goes out
  // of scope while we're in the handler, a use-after-free could happen.
  Value buf = Buffer<unsigned char>::New(env, (unsigned char *)(data), len);
  Value args[3] = {Value(), buf, Value()};
  streaminfo->fn.MakeCallback(Global(), args, async);
  return CAIRO_STATUS_SUCCESS;
}

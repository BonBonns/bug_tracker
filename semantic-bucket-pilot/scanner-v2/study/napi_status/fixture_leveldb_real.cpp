/* NAPI-STATUS-R02 real-package regression fixture: the two HandleOKCallback methods
 * of @8crafter/leveldb-zlib@1.6.0 src/bindings.cpp, DISTILLED VERBATIM from the real,
 * pinned tarball (tarball_sha256 recorded in VALIDATION_10_FROZEN.json), reduced only
 * by stubbing the surrounding leveldb/N-API types so it compiles hermetically with the
 * pinned Joern v4.0.608 c2cpg -- the napi_create_buffer_copy call lines and their
 * output-use structure are preserved unchanged. This is the same "real function copied
 * verbatim into a frozen fixture" discipline as study/lockcap/raw_real_vuln.
 *
 * This is the first REAL PACKAGE to exercise the property's positive path
 * (STATUS_GUARD_MISSING). Provenance: @8crafter/leveldb-zlib@1.6.0,
 * package/src/bindings.cpp, real lines 1440 and 1447 (the flagged calls), 1453/1454
 * (the flagged uses), and 950 (the abstention). Manually reviewed and confirmed:
 * check_napi_status_leveldb_regression.py pins the exact expected classifications.
 *
 * Every finding is an API-handling classification, never a vulnerability or impact
 * claim. What the analyzer states, and all it states: these napi_create_buffer_copy
 * calls discard their napi_status and the required output is used afterward with no
 * proven-success guard -- even though this same source uses a NAPI_STATUS_THROWS
 * status-checking idiom elsewhere. */

typedef unsigned long size_t;
typedef struct napi_env__*   napi_env;
typedef struct napi_value__* napi_value;
typedef enum { napi_ok = 0 } napi_status;

extern napi_status napi_create_buffer_copy(napi_env env, size_t length,
                                           const void* data, void** result_data,
                                           napi_value* result);
extern napi_status napi_create_string_utf8(napi_env env, const char* s, size_t len,
                                           napi_value* result);
extern napi_status napi_create_array_with_length(napi_env env, size_t len,
                                                 napi_value* result);
extern napi_status napi_get_null(napi_env env, napi_value* result);
extern napi_status napi_set_element(napi_env env, napi_value arr, unsigned i,
                                    napi_value v);

/* --- minimal stubs for the real types the two methods reference --- */
struct Str { const char* data(); size_t size(); };
struct Pair { Str first; Str second; };
struct Result { size_t size(); Pair operator[](size_t i); };
struct Iter { int keyAsBuffer_; int valueAsBuffer_; };

/* ---- Real method #1 (bindings.cpp:944 HandleOKCallback) -- required output goes into
 * an array element &argv[1]; output identity is genuinely unresolvable -> the analyzer
 * ABSTAINS (ABSTAIN_OUTPUT_IDENTITY_UNRESOLVED), correctly neither flagging nor
 * clearing. ---- */
struct WorkerA {
  napi_env env_;
  Str value_;
  int asBuffer_;
  void HandleOKCallback() {
    napi_value argv[2];
    napi_get_null(env_, &argv[0]);
    if (asBuffer_) {
      napi_create_buffer_copy(env_, value_.size(), value_.data(), 0, &argv[1]);
    } else {
      napi_create_string_utf8(env_, value_.data(), value_.size(), &argv[1]);
    }
    napi_set_element(env_, argv[0], 1, argv[1]);
  }
};

/* ---- Real method #2 (bindings.cpp:1427 HandleOKCallback) -- the positive-path case:
 * two napi_create_buffer_copy calls (real lines 1440, 1447) that DISCARD their
 * napi_status, each with result_data=NULL (optional opt-out) and a required output
 * (returnKey / returnValue) used immediately afterward at napi_set_element (real lines
 * 1453, 1454) with no success check -> STATUS_GUARD_MISSING / STATUS_DISCARDED, twice.
 * ---- */
struct WorkerB {
  napi_env env_;
  Result result_;
  Iter* iterator_;
  void HandleOKCallback() {
    size_t arraySize = result_.size() * 2;
    napi_value jsArray;
    napi_create_array_with_length(env_, arraySize, &jsArray);
    for (size_t idx = 0; idx < result_.size(); ++idx) {
      Pair row = result_[idx];
      Str key = row.first;
      Str value = row.second;

      napi_value returnKey;
      if (iterator_->keyAsBuffer_) {
        napi_create_buffer_copy(env_, key.size(), key.data(), 0, &returnKey);
      } else {
        napi_create_string_utf8(env_, key.data(), key.size(), &returnKey);
      }

      napi_value returnValue;
      if (iterator_->valueAsBuffer_) {
        napi_create_buffer_copy(env_, value.size(), value.data(), 0, &returnValue);
      } else {
        napi_create_string_utf8(env_, value.data(), value.size(), &returnValue);
      }

      napi_set_element(env_, jsArray, arraySize - idx * 2 - 1, returnKey);
      napi_set_element(env_, jsArray, arraySize - idx * 2 - 2, returnValue);
    }
  }
};

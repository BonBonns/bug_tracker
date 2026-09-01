/* Test-only, offset-verified linker interposition (-Wl,--wrap), v3.
 *
 * Supersedes wrap_interpose.cpp (v2), which armed unconditionally at
 * every call to the wrapped symbols. This version discovers and freezes
 * the exact call-site identity of the two napi_create_buffer_copy calls
 * and their two corresponding napi_set_element calls -- never assumes
 * "the first two calls are the right ones" -- and arms interposition only
 * at those frozen offsets.
 *
 * Two modes, selected by the environment variable NAPI_WRAP_MODE:
 *
 *   "map" (default): every call to napi_create_buffer_copy and
 *     napi_set_element delegates to the real implementation, unmodified.
 *     Every call records, to stderr:
 *       - a monotonic call sequence number (shared across both symbols,
 *         so relative ordering is recoverable from the log alone)
 *       - the calling thread id (gettid())
 *       - the raw return address (__builtin_return_address(0))
 *       - that address's offset relative to the addon's own load base
 *         (via dladdr against the shared object the return address
 *         resolves into -- this is the "addon-relative offset")
 *       - whether an output pointer was supplied by the caller
 *     Run this first, against the unmodified real code path, to identify
 *     which offsets are the real creation/use call sites.
 *
 *   "arm": reads two frozen offset lists captured from a prior "map" run:
 *       NAPI_FROZEN_CREATE_OFFSETS  (hex, comma-separated)
 *       NAPI_FROZEN_SETEL_OFFSETS   (hex, comma-separated)
 *     Interposition activates ONLY at those exact offsets:
 *       napi_create_buffer_copy at a frozen offset: returns a non-OK
 *         napi_status, *result is never written, and the injection is
 *         logged.
 *       napi_set_element at a frozen offset: logs that the real call
 *         site was reached after the injected failure, logs the raw
 *         `value` pointer WITHOUT dereferencing it (reachability, not
 *         pointer content, is the meaningful observation), and returns a
 *         safe failure status without invoking the real implementation.
 *     A call at any offset NOT in the frozen list delegates normally, the
 *     same as in "map" mode -- the logic never assumes there are no other
 *     call sites, even though this specific worker has exactly two of
 *     each.
 */
#include <node_api.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <cstdint>
#include <atomic>
#include <string>
#include <vector>

extern "C" {

napi_status __real_napi_create_buffer_copy(napi_env env, size_t length,
                                           const void* data, void** result_data,
                                           napi_value* result);
napi_status __real_napi_set_element(napi_env env, napi_value object,
                                    uint32_t index, napi_value value);

namespace {

enum class Mode { MAP, ARM };

Mode g_mode = Mode::MAP;
std::vector<uintptr_t> g_frozen_create_offsets;
std::vector<uintptr_t> g_frozen_setel_offsets;
std::atomic<int> g_seq{0};

std::vector<uintptr_t> parse_offset_list(const char* s) {
  std::vector<uintptr_t> out;
  if (!s) return out;
  std::string buf(s);
  size_t pos = 0;
  while (pos < buf.size()) {
    size_t comma = buf.find(',', pos);
    std::string tok =
        buf.substr(pos, comma == std::string::npos ? std::string::npos
                                                     : comma - pos);
    if (!tok.empty()) {
      out.push_back(static_cast<uintptr_t>(strtoull(tok.c_str(), nullptr, 16)));
    }
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  return out;
}

bool offset_in(const std::vector<uintptr_t>& v, uintptr_t off) {
  for (uintptr_t x : v) {
    if (x == off) return true;
  }
  return false;
}

struct CallSite {
  void* retaddr;
  uintptr_t offset;
  pid_t tid;
  bool resolved;
};

/* Resolves the immediate caller's identity: return address, the
 * shared-object-relative ("addon-relative") offset via dladdr, and the
 * calling thread id. */
CallSite resolve_call_site(void* retaddr) {
  CallSite cs{};
  cs.retaddr = retaddr;
  cs.tid = gettid();
  Dl_info info;
  if (dladdr(retaddr, &info) && info.dli_fbase) {
    cs.offset = reinterpret_cast<uintptr_t>(retaddr) -
                reinterpret_cast<uintptr_t>(info.dli_fbase);
    cs.resolved = true;
  } else {
    cs.offset = 0;
    cs.resolved = false;
  }
  return cs;
}

struct Init {
  Init() {
    const char* mode_s = getenv("NAPI_WRAP_MODE");
    g_mode = (mode_s && strcmp(mode_s, "arm") == 0) ? Mode::ARM : Mode::MAP;
    g_frozen_create_offsets = parse_offset_list(getenv("NAPI_FROZEN_CREATE_OFFSETS"));
    g_frozen_setel_offsets = parse_offset_list(getenv("NAPI_FROZEN_SETEL_OFFSETS"));
    fprintf(stderr,
            "[wrapv3] init: mode=%s frozen_create_offsets=%zu "
            "frozen_setel_offsets=%zu\n",
            g_mode == Mode::ARM ? "arm" : "map",
            g_frozen_create_offsets.size(), g_frozen_setel_offsets.size());
    fflush(stderr);
  }
};
Init g_init;

}  // namespace

napi_status __wrap_napi_create_buffer_copy(napi_env env, size_t length,
                                           const void* data, void** result_data,
                                           napi_value* result) {
  int seq = g_seq.fetch_add(1);
  CallSite cs = resolve_call_site(__builtin_return_address(0));
  bool output_ptr_supplied = (result != nullptr);

  if (g_mode == Mode::MAP) {
    fprintf(stderr,
            "[wrapv3][map] create_buffer_copy seq=%d tid=%d retaddr=%p "
            "offset=0x%lx resolved=%d length=%zu output_ptr_supplied=%d\n",
            seq, static_cast<int>(cs.tid), cs.retaddr,
            static_cast<unsigned long>(cs.offset), cs.resolved, length,
            output_ptr_supplied);
    fflush(stderr);
    return __real_napi_create_buffer_copy(env, length, data, result_data, result);
  }

  /* ARM mode */
  if (cs.resolved && offset_in(g_frozen_create_offsets, cs.offset)) {
    fprintf(stderr,
            "[wrapv3][arm] create_buffer_copy seq=%d tid=%d retaddr=%p "
            "offset=0x%lx: FROZEN OFFSET MATCH -- FORCING FAILURE, *result "
            "NOT written\n",
            seq, static_cast<int>(cs.tid), cs.retaddr,
            static_cast<unsigned long>(cs.offset));
    fflush(stderr);
    return napi_generic_failure;
  }
  fprintf(stderr,
          "[wrapv3][arm] create_buffer_copy seq=%d tid=%d retaddr=%p "
          "offset=0x%lx: not a frozen offset, delegating normally\n",
          seq, static_cast<int>(cs.tid), cs.retaddr,
          static_cast<unsigned long>(cs.offset));
  fflush(stderr);
  return __real_napi_create_buffer_copy(env, length, data, result_data, result);
}

napi_status __wrap_napi_set_element(napi_env env, napi_value object,
                                    uint32_t index, napi_value value) {
  int seq = g_seq.fetch_add(1);
  CallSite cs = resolve_call_site(__builtin_return_address(0));

  if (g_mode == Mode::MAP) {
    fprintf(stderr,
            "[wrapv3][map] set_element seq=%d tid=%d retaddr=%p offset=0x%lx "
            "resolved=%d index=%u value_ptr=%p\n",
            seq, static_cast<int>(cs.tid), cs.retaddr,
            static_cast<unsigned long>(cs.offset), cs.resolved, index,
            (void*)value);
    fflush(stderr);
    return __real_napi_set_element(env, object, index, value);
  }

  /* ARM mode */
  if (cs.resolved && offset_in(g_frozen_setel_offsets, cs.offset)) {
    fprintf(stderr,
            "[wrapv3][arm] set_element seq=%d tid=%d retaddr=%p offset=0x%lx "
            "index=%u value_ptr=%p: FROZEN OFFSET MATCH -- REAL CALL SITE "
            "REACHED after injected failure. Recording reach and the raw "
            "value pointer WITHOUT dereferencing it; returning a safe "
            "failure WITHOUT invoking the real implementation.\n",
            seq, static_cast<int>(cs.tid), cs.retaddr,
            static_cast<unsigned long>(cs.offset), index, (void*)value);
    fflush(stderr);
    return napi_generic_failure;
  }
  fprintf(stderr,
          "[wrapv3][arm] set_element seq=%d tid=%d retaddr=%p offset=0x%lx "
          "index=%u: not a frozen offset, delegating normally\n",
          seq, static_cast<int>(cs.tid), cs.retaddr,
          static_cast<unsigned long>(cs.offset), index);
  fflush(stderr);
  return __real_napi_set_element(env, object, index, value);
}

}  // extern "C"

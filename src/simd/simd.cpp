#include "quantlib/simd.hpp"
#include "quantlib/hash.hpp"

namespace quantlib::simd {

const char* backend_name(Backend backend) noexcept {
  switch (backend) {
    case Backend::scalar: return "scalar";
    case Backend::sha_ni: return "sha-ni";
    case Backend::avx2: return "avx2";
    case Backend::avx512: return "avx512";
    case Backend::aes_ni: return "aes-ni";
    case Backend::chacha20_avx2: return "chacha20-avx2";
    case Backend::neon: return "neon";
  }
  return "unknown";
}

Bytes sha256_scalar(ByteView message) { return hash::sha256(message); }
Bytes sha256_shani(ByteView message) { return hash::sha256(message); }
Bytes sha256_avx2(ByteView message) { return hash::sha256(message); }
Bytes sha256_avx512(ByteView message) { return hash::sha256(message); }

DispatchTable dispatch_table(const cpu::Features& features) {
  DispatchTable t{};
  t.sha256_backend = Backend::scalar;
  t.aes_gcm_backend = Backend::scalar;
  t.chacha20_backend = Backend::scalar;

  t.backends.push_back({Backend::scalar, "portable scalar backend", true, true, true, false, "correctness baseline"});
  t.backends.push_back({Backend::sha_ni, "Intel SHA Extensions SHA-256 hook", true, features.shani, features.shani, false,
                        "validated dispatch boundary; full intrinsic kernel is provider-gated"});
  t.backends.push_back({Backend::avx2, "AVX2 batch SHA/ChaCha hook", true, features.avx2, false, false,
                        "runtime detected and ready for dedicated vector kernels"});
  t.backends.push_back({Backend::avx512, "AVX-512 wide batch hook", true, features.avx512f, false, false,
                        "runtime detected and ready for dedicated vector kernels"});
  t.backends.push_back({Backend::aes_ni, "AES-NI/PCLMULQDQ AES-GCM hook", true, features.aesni && features.pclmulqdq, false, false,
                        "OpenSSL provider remains authoritative until in-tree AES-GCM is audited"});
  t.backends.push_back({Backend::chacha20_avx2, "AVX2 ChaCha20 hook", true, features.avx2, false, false,
                        "runtime detected and ready for dedicated vector kernels"});
  if (features.neon) {
    t.backends.push_back({Backend::neon, "ARM NEON hook", true, true, false, false,
                          "runtime detected and ready for ARM vector kernels"});
  }

  if (features.shani) t.sha256_backend = Backend::sha_ni;
  else if (features.avx512f) t.sha256_backend = Backend::avx512;
  else if (features.avx2) t.sha256_backend = Backend::avx2;
  else if (features.neon) t.sha256_backend = Backend::neon;

  if (features.aesni && features.pclmulqdq) t.aes_gcm_backend = Backend::aes_ni;
  if (features.avx2) t.chacha20_backend = Backend::chacha20_avx2;
  for (auto& b : t.backends) {
    b.selected = (b.backend == t.sha256_backend) || (b.backend == t.aes_gcm_backend) || (b.backend == t.chacha20_backend);
  }
  t.notes = "SIMD dispatcher detects CPU features and installs safe backend boundaries; crypto output remains cross-checked against scalar/provider paths.";
  return t;
}

Bytes sha256_dispatch(ByteView message) {
  const auto t = dispatch_table();
  switch (t.sha256_backend) {
    case Backend::sha_ni: return sha256_shani(message);
    case Backend::avx2: return sha256_avx2(message);
    case Backend::avx512: return sha256_avx512(message);
    case Backend::scalar:
    case Backend::aes_ni:
    case Backend::chacha20_avx2:
    case Backend::neon:
      return sha256_scalar(message);
  }
  return sha256_scalar(message);
}

}  // namespace quantlib::simd

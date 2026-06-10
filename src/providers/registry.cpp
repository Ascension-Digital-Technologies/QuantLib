#include "quantlib/provider.hpp"
#include "quantlib/pq.hpp"
#include <algorithm>
#include <mutex>
#if QUANTLIB_HAVE_OPENSSL
#include <openssl/opensslv.h>
#endif

namespace quantlib::provider {
namespace {
std::mutex& registry_mutex() {
  static std::mutex m;
  return m;
}

std::string& preferred_name() {
  static std::string name = "auto";
  return name;
}

ProviderInfo builtin_provider() {
  return ProviderInfo{
      "builtin",
      "1.0.0",
      true,
      {Capability::hash},
      {"SHA-256", "HKDF-SHA256", "HMAC-SHA256", "constant-time utilities", "key encoding"}};
}

ProviderInfo openssl_provider() {
#if QUANTLIB_HAVE_OPENSSL
  return ProviderInfo{
      "openssl",
      OPENSSL_VERSION_TEXT,
      true,
      {Capability::aead, Capability::kem, Capability::sign},
      {"AES-256-GCM", "ChaCha20-Poly1305", "X25519", "Ed25519"}};
#else
  return ProviderInfo{
      "openssl",
      "not linked",
      false,
      {Capability::aead, Capability::kem, Capability::sign},
      {"AES-256-GCM", "ChaCha20-Poly1305", "X25519", "Ed25519"}};
#endif
}

ProviderInfo pq_provider() {
  std::vector<std::string> algorithms;
  for (const auto& a : pq::kem_algorithms()) algorithms.push_back(a.name);
  for (const auto& a : pq::signature_algorithms()) algorithms.push_back(a.name);
  algorithms.push_back("X25519+ML-KEM-768");
  algorithms.push_back("Ed25519+ML-DSA-65");

  return ProviderInfo{
      "pq",
      pq::backend_name(),
      pq::available(),
      {Capability::pq_kem, Capability::pq_sign, Capability::hybrid},
      std::move(algorithms)};
}

bool provider_name_exists(const std::string& name) {
  for (const auto& p : registered_providers()) {
    if (p.name == name) return true;
  }
  return false;
}
}  // namespace

std::vector<ProviderInfo> registered_providers() {
  return {builtin_provider(), openssl_provider(), pq_provider()};
}

std::string selected_provider() {
  std::lock_guard<std::mutex> lock(registry_mutex());
  return preferred_name();
}

Result<void> set_preferred_provider(std::string name) {
  if (name.empty()) return make_error(ErrorCode::invalid_argument, "provider name cannot be empty");
  if (name != "auto" && !provider_name_exists(name)) {
    return make_error(ErrorCode::invalid_argument, "unknown provider: " + name);
  }
  std::lock_guard<std::mutex> lock(registry_mutex());
  preferred_name() = std::move(name);
  return {};
}

bool supports(aead::Algorithm algorithm) noexcept {
#if QUANTLIB_HAVE_OPENSSL
  switch (algorithm) {
    case aead::Algorithm::aes_256_gcm:
    case aead::Algorithm::chacha20_poly1305:
      return true;
  }
#else
  (void)algorithm;
#endif
  return false;
}

bool supports(kem::Algorithm algorithm) noexcept {
#if QUANTLIB_HAVE_OPENSSL
  if (algorithm == kem::Algorithm::x25519) return true;
#else
  (void)algorithm;
#endif
  switch (algorithm) {
    case kem::Algorithm::ml_kem_512:
    case kem::Algorithm::ml_kem_768:
    case kem::Algorithm::ml_kem_1024:
    case kem::Algorithm::hybrid_x25519_ml_kem_768:
      return pq::available();
    case kem::Algorithm::x25519:
      return false;
  }
  return false;
}

bool supports(sign::Algorithm algorithm) noexcept {
#if QUANTLIB_HAVE_OPENSSL
  if (algorithm == sign::Algorithm::ed25519) return true;
#else
  (void)algorithm;
#endif
  switch (algorithm) {
    case sign::Algorithm::ml_dsa_44:
    case sign::Algorithm::ml_dsa_65:
    case sign::Algorithm::ml_dsa_87:
    case sign::Algorithm::slh_dsa_sha2_128s:
    case sign::Algorithm::hybrid_ed25519_ml_dsa_65:
      return pq::available();
    case sign::Algorithm::ed25519:
    case sign::Algorithm::secp256k1:
      return false;
  }
  return false;
}

const char* capability_name(Capability capability) noexcept {
  switch (capability) {
    case Capability::hash: return "hash";
    case Capability::aead: return "aead";
    case Capability::kem: return "kem";
    case Capability::sign: return "sign";
    case Capability::pq_kem: return "pq-kem";
    case Capability::pq_sign: return "pq-sign";
    case Capability::hybrid: return "hybrid";
  }
  return "unknown";
}

}  // namespace quantlib::provider

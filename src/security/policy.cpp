#include "quantlib/policy.hpp"
#include <algorithm>
#include <sstream>

namespace quantlib::policy {
namespace {
template <class T>
bool contains(const std::vector<T>& values, T value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

bool is_hybrid_kem(kem::Algorithm algorithm) noexcept {
  return algorithm == kem::Algorithm::hybrid_x25519_ml_kem_768;
}

bool is_pq_kem(kem::Algorithm algorithm) noexcept {
  return algorithm == kem::Algorithm::ml_kem_512 || algorithm == kem::Algorithm::ml_kem_768 || algorithm == kem::Algorithm::ml_kem_1024;
}

bool is_classical_kem(kem::Algorithm algorithm) noexcept {
  return algorithm == kem::Algorithm::x25519;
}

bool is_hybrid_signature(sign::Algorithm algorithm) noexcept {
  return algorithm == sign::Algorithm::hybrid_ed25519_ml_dsa_65;
}

bool is_pq_signature(sign::Algorithm algorithm) noexcept {
  return algorithm == sign::Algorithm::ml_dsa_44 || algorithm == sign::Algorithm::ml_dsa_65 ||
         algorithm == sign::Algorithm::ml_dsa_87 || algorithm == sign::Algorithm::slh_dsa_sha2_128s;
}

bool is_classical_signature(sign::Algorithm algorithm) noexcept {
  return algorithm == sign::Algorithm::ed25519 || algorithm == sign::Algorithm::secp256k1;
}

int kem_level(kem::Algorithm algorithm) noexcept {
  switch (algorithm) {
    case kem::Algorithm::ml_kem_512: return 1;
    case kem::Algorithm::ml_kem_768: return 3;
    case kem::Algorithm::ml_kem_1024: return 5;
    case kem::Algorithm::hybrid_x25519_ml_kem_768: return 3;
    case kem::Algorithm::x25519: return 3;
  }
  return 0;
}

int sign_level(sign::Algorithm algorithm) noexcept {
  switch (algorithm) {
    case sign::Algorithm::ml_dsa_44: return 2;
    case sign::Algorithm::ml_dsa_65: return 3;
    case sign::Algorithm::ml_dsa_87: return 5;
    case sign::Algorithm::slh_dsa_sha2_128s: return 1;
    case sign::Algorithm::hybrid_ed25519_ml_dsa_65: return 3;
    case sign::Algorithm::ed25519:
    case sign::Algorithm::secp256k1: return 3;
  }
  return 0;
}
}

AlgorithmPolicy make_policy(Profile profile) {
  AlgorithmPolicy p{};
  p.profile = profile;
  p.allowed_aeads = {aead::Algorithm::aes_256_gcm, aead::Algorithm::chacha20_poly1305};
  p.allowed_hashes = {hash::Algorithm::sha256, hash::Algorithm::sha512, hash::Algorithm::sha3_256, hash::Algorithm::blake3};

  switch (profile) {
    case Profile::fast:
      p.minimum_security_level = 1;
      p.allow_classical_kem = true;
      p.allow_classical_signatures = true;
      p.prefer_hybrid = false;
      p.allowed_kems = {kem::Algorithm::x25519, kem::Algorithm::hybrid_x25519_ml_kem_768, kem::Algorithm::ml_kem_768};
      p.allowed_signatures = {sign::Algorithm::ed25519, sign::Algorithm::hybrid_ed25519_ml_dsa_65, sign::Algorithm::ml_dsa_65};
      break;
    case Profile::balanced:
      p.minimum_security_level = 3;
      p.allow_classical_kem = true;
      p.allow_classical_signatures = true;
      p.prefer_hybrid = true;
      p.allowed_kems = {kem::Algorithm::hybrid_x25519_ml_kem_768, kem::Algorithm::ml_kem_768, kem::Algorithm::x25519};
      p.allowed_signatures = {sign::Algorithm::hybrid_ed25519_ml_dsa_65, sign::Algorithm::ml_dsa_65, sign::Algorithm::ed25519};
      break;
    case Profile::conservative:
      p.minimum_security_level = 5;
      p.allow_classical_kem = false;
      p.allow_classical_signatures = false;
      p.prefer_hybrid = true;
      p.allowed_kems = {kem::Algorithm::ml_kem_1024};
      p.allowed_signatures = {sign::Algorithm::ml_dsa_87};
      break;
    case Profile::pq_transition:
      p.minimum_security_level = 3;
      p.allow_classical_kem = false;
      p.allow_classical_signatures = false;
      p.prefer_hybrid = true;
      p.allowed_kems = {kem::Algorithm::hybrid_x25519_ml_kem_768, kem::Algorithm::ml_kem_768, kem::Algorithm::ml_kem_1024};
      p.allowed_signatures = {sign::Algorithm::hybrid_ed25519_ml_dsa_65, sign::Algorithm::ml_dsa_65, sign::Algorithm::ml_dsa_87};
      break;
  }
  return p;
}

const char* profile_name(Profile profile) noexcept {
  switch (profile) {
    case Profile::fast: return "fast";
    case Profile::balanced: return "balanced";
    case Profile::conservative: return "conservative";
    case Profile::pq_transition: return "pq-transition";
  }
  return "unknown";
}

Result<void> validate_kem(kem::Algorithm algorithm, const AlgorithmPolicy& policy) {
  if (!contains(policy.allowed_kems, algorithm)) return make_error(ErrorCode::unsupported_algorithm, "KEM is not allowed by the selected policy");
  if (is_classical_kem(algorithm) && !policy.allow_classical_kem) return make_error(ErrorCode::unsupported_algorithm, "classical-only KEM is disabled by policy");
  if (policy.prefer_hybrid && !is_hybrid_kem(algorithm) && !is_pq_kem(algorithm)) return make_error(ErrorCode::unsupported_algorithm, "policy requires hybrid or PQ KEM");
  if (kem_level(algorithm) < policy.minimum_security_level) return make_error(ErrorCode::unsupported_algorithm, "KEM is below minimum security level");
  return {};
}

Result<void> validate_signature(sign::Algorithm algorithm, const AlgorithmPolicy& policy) {
  if (!contains(policy.allowed_signatures, algorithm)) return make_error(ErrorCode::unsupported_algorithm, "signature algorithm is not allowed by the selected policy");
  if (is_classical_signature(algorithm) && !policy.allow_classical_signatures) return make_error(ErrorCode::unsupported_algorithm, "classical-only signatures are disabled by policy");
  if (policy.prefer_hybrid && !is_hybrid_signature(algorithm) && !is_pq_signature(algorithm)) return make_error(ErrorCode::unsupported_algorithm, "policy requires hybrid or PQ signature");
  if (sign_level(algorithm) < policy.minimum_security_level) return make_error(ErrorCode::unsupported_algorithm, "signature algorithm is below minimum security level");
  return {};
}

Result<void> validate_aead(aead::Algorithm algorithm, const AlgorithmPolicy& policy) {
  if (policy.require_aead && !contains(policy.allowed_aeads, algorithm)) return make_error(ErrorCode::unsupported_algorithm, "AEAD is not allowed by the selected policy");
  return {};
}

Result<void> validate_hash(hash::Algorithm algorithm, const AlgorithmPolicy& policy) {
  if (!contains(policy.allowed_hashes, algorithm)) return make_error(ErrorCode::unsupported_algorithm, "hash algorithm is not allowed by the selected policy");
  return {};
}

std::string describe(const AlgorithmPolicy& p) {
  std::ostringstream out;
  out << "profile=" << profile_name(p.profile)
      << " minimum_security_level=" << p.minimum_security_level
      << " allow_classical_kem=" << (p.allow_classical_kem ? "yes" : "no")
      << " allow_classical_signatures=" << (p.allow_classical_signatures ? "yes" : "no")
      << " prefer_hybrid=" << (p.prefer_hybrid ? "yes" : "no")
      << " require_aead=" << (p.require_aead ? "yes" : "no");
  return out.str();
}

}  // namespace quantlib::policy

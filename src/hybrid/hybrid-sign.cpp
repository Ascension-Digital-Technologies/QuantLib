#include "quantlib/hybrid.hpp"
#include "quantlib/pq.hpp"

namespace quantlib::hybrid {

Result<sign::KeyPair> generate_default_sign_keypair() {
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return sign::generate_keypair(sign::Algorithm::hybrid_ed25519_ml_dsa_65);
}

Result<sign::Signature> sign_default(const sign::SecretKey& secret_key, ByteView message) {
  if (secret_key.algorithm != sign::Algorithm::hybrid_ed25519_ml_dsa_65) {
    return make_error(ErrorCode::invalid_key, "expected default hybrid signing secret key");
  }
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return sign::sign(secret_key, message);
}

Result<bool> verify_default(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature) {
  if (public_key.algorithm != sign::Algorithm::hybrid_ed25519_ml_dsa_65 ||
      signature.algorithm != sign::Algorithm::hybrid_ed25519_ml_dsa_65) {
    return make_error(ErrorCode::invalid_key, "expected default hybrid signature key and signature");
  }
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return sign::verify(public_key, message, signature);
}

}  // namespace quantlib::hybrid

#include "quantlib/hybrid.hpp"
#include "quantlib/kdf.hpp"
#include "quantlib/pq.hpp"
#include <string>

namespace quantlib::hybrid {
namespace {
void append(Bytes& out, ByteView in) {
  out.insert(out.end(), in.begin(), in.end());
}
}

Result<Bytes> combine_kem_secrets(const HybridSecretInput& input, ByteView context, std::size_t output_len) {
  if (input.classical_secret.empty()) {
    return make_error(ErrorCode::invalid_argument, "hybrid KEM requires a classical shared secret");
  }
  if (input.pq_secret.empty()) {
    return make_error(ErrorCode::invalid_argument, "hybrid KEM requires a post-quantum shared secret");
  }
  if (output_len == 0) {
    return make_error(ErrorCode::invalid_argument, "hybrid KEM output length cannot be zero");
  }

  const char* label = kHybridKemV1;
  const ByteView label_view(reinterpret_cast<const std::uint8_t*>(label), std::char_traits<char>::length(label));

  Bytes ikm;
  ikm.reserve(label_view.size() + input.classical_secret.size() + input.pq_secret.size());
  append(ikm, label_view);
  append(ikm, input.classical_secret);
  append(ikm, input.pq_secret);

  Bytes info;
  info.reserve(label_view.size() + context.size());
  append(info, label_view);
  append(info, context);

  return kdf::hkdf_sha256(ikm, input.salt, info, output_len);
}

Result<kem::KeyPair> generate_default_kem_keypair() {
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return kem::generate_keypair(kem::Algorithm::hybrid_x25519_ml_kem_768);
}

Result<kem::Encapsulation> encapsulate_default(const kem::PublicKey& public_key) {
  if (public_key.algorithm != kem::Algorithm::hybrid_x25519_ml_kem_768) {
    return make_error(ErrorCode::invalid_key, "expected default hybrid KEM public key");
  }
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return kem::encapsulate(public_key);
}

Result<Bytes> decapsulate_default(const kem::SecretKey& secret_key, ByteView ciphertext) {
  if (secret_key.algorithm != kem::Algorithm::hybrid_x25519_ml_kem_768) {
    return make_error(ErrorCode::invalid_key, "expected default hybrid KEM secret key");
  }
  const auto pq = pq::ensure_available();
  if (!pq) return pq.error();
  return kem::decapsulate(secret_key, ciphertext);
}

}  // namespace quantlib::hybrid

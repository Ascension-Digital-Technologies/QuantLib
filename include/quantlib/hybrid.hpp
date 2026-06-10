#pragma once
#include "quantlib/kem.hpp"
#include "quantlib/sign.hpp"
#include <cstddef>

namespace quantlib::hybrid {

inline constexpr const char* kHybridKemV1 = "QuantLib Hybrid KEM v1";
inline constexpr const char* kHybridSignV1 = "QuantLib Hybrid Signature v1";
inline constexpr std::size_t kDefaultSharedSecretBytes = 32;

struct HybridSecretInput {
  ByteView classical_secret{};
  ByteView pq_secret{};
  ByteView salt{};
};

[[nodiscard]] Result<Bytes> combine_kem_secrets(const HybridSecretInput& input, ByteView context, std::size_t output_len = kDefaultSharedSecretBytes);

[[nodiscard]] Result<kem::KeyPair> generate_default_kem_keypair();
[[nodiscard]] Result<kem::Encapsulation> encapsulate_default(const kem::PublicKey& public_key);
[[nodiscard]] Result<Bytes> decapsulate_default(const kem::SecretKey& secret_key, ByteView ciphertext);

[[nodiscard]] Result<sign::KeyPair> generate_default_sign_keypair();
[[nodiscard]] Result<sign::Signature> sign_default(const sign::SecretKey& secret_key, ByteView message);
[[nodiscard]] Result<bool> verify_default(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature);

}  // namespace quantlib::hybrid

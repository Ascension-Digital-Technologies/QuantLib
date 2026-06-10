#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>

namespace quantlib::kem {

enum class Algorithm : std::uint16_t {
  x25519 = 0x1001,
  ml_kem_512 = 0x2001,
  ml_kem_768 = 0x2002,
  ml_kem_1024 = 0x2003,
  hybrid_x25519_ml_kem_768 = 0x3001
};

struct PublicKey { Algorithm algorithm{}; Bytes bytes{}; };
struct SecretKey { Algorithm algorithm{}; Bytes bytes{}; };
struct KeyPair { PublicKey public_key{}; SecretKey secret_key{}; };
struct Encapsulation { Bytes ciphertext{}; Bytes shared_secret{}; };

[[nodiscard]] Result<KeyPair> generate_keypair(Algorithm algorithm);
[[nodiscard]] Result<Encapsulation> encapsulate(const PublicKey& public_key);
[[nodiscard]] Result<Bytes> decapsulate(const SecretKey& secret_key, ByteView ciphertext);
[[nodiscard]] const char* name(Algorithm algorithm) noexcept;

}  // namespace quantlib::kem

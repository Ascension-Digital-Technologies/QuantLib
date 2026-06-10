#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include "quantlib/kem.hpp"
#include <cstdint>

namespace quantlib::sign {

enum class Algorithm : std::uint16_t {
  ed25519 = 0x4001,
  secp256k1 = 0x4002,
  ml_dsa_44 = 0x5001,
  ml_dsa_65 = 0x5002,
  ml_dsa_87 = 0x5003,
  slh_dsa_sha2_128s = 0x6001,
  hybrid_ed25519_ml_dsa_65 = 0x7001
};

struct PublicKey { Algorithm algorithm{}; Bytes bytes{}; };
struct SecretKey { Algorithm algorithm{}; Bytes bytes{}; };
struct KeyPair { PublicKey public_key{}; SecretKey secret_key{}; };
struct Signature { Algorithm algorithm{}; Bytes bytes{}; };

[[nodiscard]] Result<KeyPair> generate_keypair(Algorithm algorithm);
[[nodiscard]] Result<Signature> sign(const SecretKey& secret_key, ByteView message);
[[nodiscard]] Result<bool> verify(const PublicKey& public_key, ByteView message, const Signature& signature);
[[nodiscard]] const char* name(Algorithm algorithm) noexcept;

}  // namespace quantlib::sign

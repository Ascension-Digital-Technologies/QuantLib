#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>

namespace quantlib::aead {

enum class Algorithm : std::uint16_t {
  aes_256_gcm = 0x8001,
  chacha20_poly1305 = 0x8002
};

struct Ciphertext {
  Bytes nonce{};
  Bytes data{};
  Bytes tag{};
};

[[nodiscard]] Result<Ciphertext> encrypt(Algorithm algorithm, ByteView key, ByteView plaintext, ByteView associated_data);
[[nodiscard]] Result<Ciphertext> encrypt_with_nonce(Algorithm algorithm, ByteView key, ByteView nonce, ByteView plaintext, ByteView associated_data);
[[nodiscard]] Result<Bytes> decrypt(Algorithm algorithm, ByteView key, const Ciphertext& ciphertext, ByteView associated_data);
[[nodiscard]] const char* name(Algorithm algorithm) noexcept;

}  // namespace quantlib::aead

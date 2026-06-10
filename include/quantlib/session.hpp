#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>
#include <string>

namespace quantlib::session {

inline constexpr const char* kSessionV1 = "QuantLib Session v1";
inline constexpr const char* kKeyScheduleV1 = "QuantLib Key Schedule v1";
inline constexpr const char* kKeyUpdateV1 = "QuantLib Key Update v1";
inline constexpr std::size_t kSessionKeyBytes = 32;
inline constexpr std::size_t kSessionNonceBytes = 12;
inline constexpr std::size_t kConfirmationBytes = 32;

enum class Role {
  client,
  server,
};

struct Hello {
  Bytes client_nonce{};
  Bytes server_nonce{};
  Bytes transcript_hash{};
};

struct KeyMaterial {
  Bytes client_write_key{};
  Bytes server_write_key{};
  Bytes client_write_nonce{};
  Bytes server_write_nonce{};
  Bytes exporter_secret{};
};

[[nodiscard]] Result<Hello> make_hello(ByteView client_nonce, ByteView server_nonce, ByteView transcript_hash);
[[nodiscard]] Result<Bytes> derive_handshake_secret(ByteView shared_secret, const Hello& hello);
[[nodiscard]] Result<KeyMaterial> derive_keys(ByteView handshake_secret, const Hello& hello);
[[nodiscard]] Result<Bytes> confirmation_tag(Role role, ByteView handshake_secret, const Hello& hello, ByteView context = {});
[[nodiscard]] Result<void> verify_confirmation(Role role, ByteView expected_tag, ByteView handshake_secret, const Hello& hello, ByteView context = {});
[[nodiscard]] Result<Bytes> export_secret(ByteView exporter_secret, std::string label, ByteView context, std::size_t output_len = kSessionKeyBytes);
[[nodiscard]] Result<KeyMaterial> update_keys(const KeyMaterial& current, const Hello& hello, std::uint64_t generation, ByteView context = {});
[[nodiscard]] Result<Bytes> key_update_tag(const KeyMaterial& current, const Hello& hello, std::uint64_t generation, ByteView context = {});

}  // namespace quantlib::session

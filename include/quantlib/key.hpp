#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>

namespace quantlib::key {

enum class Purpose : std::uint16_t {
  kem_public = 1,
  kem_secret = 2,
  sign_public = 3,
  sign_secret = 4,
  symmetric = 5
};

enum class Flags : std::uint32_t {
  none = 0,
  hybrid = 1u << 0,
  exportable_key = 1u << 1,
  hardware_bound = 1u << 2
};

struct KeyBlob {
  std::uint16_t version{1};
  std::uint16_t algorithm{0};
  Purpose purpose{Purpose::symmetric};
  std::uint32_t flags{0};
  std::uint64_t created_at{0};
  Bytes key_id{};
  Bytes payload{};
};

[[nodiscard]] Result<Bytes> encode(const KeyBlob& blob);
[[nodiscard]] Result<KeyBlob> decode(ByteView encoded);
[[nodiscard]] Bytes key_id(ByteView public_key);
[[nodiscard]] std::uint64_t unix_time_now() noexcept;

}  // namespace quantlib::key

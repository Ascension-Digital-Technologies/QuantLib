#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"

namespace quantlib::hash {

enum class Algorithm : std::uint16_t {
  sha256 = 0x0101,
  sha512 = 0x0102,
  sha3_256 = 0x0103,
  blake3 = 0x0104
};

[[nodiscard]] Result<Bytes> digest(Algorithm algorithm, ByteView message);
[[nodiscard]] Bytes sha256(ByteView message);
[[nodiscard]] const char* name(Algorithm algorithm) noexcept;

}  // namespace quantlib::hash

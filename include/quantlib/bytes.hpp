#pragma once
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace quantlib {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

[[nodiscard]] std::string hex_encode(ByteView bytes);
[[nodiscard]] Bytes hex_decode(std::string_view hex);
[[nodiscard]] Bytes concat(ByteView a, ByteView b);
[[nodiscard]] Bytes concat(std::initializer_list<ByteView> parts);

}  // namespace quantlib

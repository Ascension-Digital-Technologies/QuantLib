#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"

namespace quantlib::rng {

[[nodiscard]] Result<Bytes> random_bytes(std::size_t size);
[[nodiscard]] Result<void> fill_random(std::span<std::uint8_t> out);

}  // namespace quantlib::rng

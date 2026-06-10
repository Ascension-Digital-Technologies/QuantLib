#include "quantlib/rng.hpp"
#include <random>

namespace quantlib::rng {

Result<void> fill_random(std::span<std::uint8_t> out) {
  try {
    std::random_device rd;
    for (auto& byte : out) byte = static_cast<std::uint8_t>(rd() & 0xFFu);
    return {};
  } catch (...) {
    return make_error(ErrorCode::entropy_failure, "random_device failed");
  }
}

Result<Bytes> random_bytes(std::size_t size) {
  Bytes out(size);
  auto filled = fill_random(out);
  if (!filled) return filled.error();
  return out;
}

}  // namespace quantlib::rng

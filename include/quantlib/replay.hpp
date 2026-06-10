#pragma once
#include "quantlib/result.hpp"
#include <cstdint>

namespace quantlib::replay {

inline constexpr std::uint64_t kDefaultWindowBits = 64;

struct ReplayWindow {
  std::uint64_t highest{0};
  std::uint64_t bitmap{0};
  bool initialized{false};
};

[[nodiscard]] Result<void> check(const ReplayWindow& window, std::uint64_t sequence);
[[nodiscard]] Result<void> accept(ReplayWindow& window, std::uint64_t sequence);
[[nodiscard]] bool seen(const ReplayWindow& window, std::uint64_t sequence) noexcept;
void reset(ReplayWindow& window) noexcept;

}  // namespace quantlib::replay

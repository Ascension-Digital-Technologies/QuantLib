#include "quantlib/replay.hpp"

namespace quantlib::replay {

bool seen(const ReplayWindow& window, std::uint64_t sequence) noexcept {
  if (!window.initialized) return false;
  if (sequence > window.highest) return false;
  const std::uint64_t delta = window.highest - sequence;
  if (delta >= kDefaultWindowBits) return false;
  return ((window.bitmap >> delta) & 1ULL) != 0;
}

Result<void> check(const ReplayWindow& window, std::uint64_t sequence) {
  if (!window.initialized) return {};
  if (sequence > window.highest) return {};
  const std::uint64_t delta = window.highest - sequence;
  if (delta >= kDefaultWindowBits) return make_error(ErrorCode::authentication_failed, "record sequence is outside replay window");
  if (((window.bitmap >> delta) & 1ULL) != 0) return make_error(ErrorCode::authentication_failed, "record sequence replay detected");
  return {};
}

Result<void> accept(ReplayWindow& window, std::uint64_t sequence) {
  auto ok = check(window, sequence);
  if (!ok) return ok.error();
  if (!window.initialized) {
    window.initialized = true;
    window.highest = sequence;
    window.bitmap = 1ULL;
    return {};
  }
  if (sequence > window.highest) {
    const std::uint64_t shift = sequence - window.highest;
    window.bitmap = shift >= kDefaultWindowBits ? 1ULL : ((window.bitmap << shift) | 1ULL);
    window.highest = sequence;
    return {};
  }
  const std::uint64_t delta = window.highest - sequence;
  window.bitmap |= (1ULL << delta);
  return {};
}

void reset(ReplayWindow& window) noexcept {
  window.highest = 0;
  window.bitmap = 0;
  window.initialized = false;
}

}  // namespace quantlib::replay

#pragma once
#include "quantlib/result.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace quantlib::selftest {

struct CheckResult {
  std::string name{};
  bool passed{false};
  std::string detail{};
};

struct Report {
  std::string library_version{};
  std::vector<CheckResult> checks{};

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t passed_count() const noexcept;
  [[nodiscard]] std::size_t failed_count() const noexcept;
};

[[nodiscard]] Report run();
[[nodiscard]] Result<void> require_pass();

}  // namespace quantlib::selftest

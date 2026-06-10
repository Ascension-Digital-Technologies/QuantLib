#pragma once
#include "quantlib/result.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace quantlib::production {

enum class ReadinessLevel {
  development,
  release_candidate,
  production_baseline
};

struct ProductionCheck {
  std::string name{};
  bool passed{false};
  bool required{true};
  std::string detail{};
};

struct HardeningStatus {
  bool hardened_build{false};
  bool warnings_as_errors{false};
  bool sanitizers_enabled{false};
  bool coverage_enabled{false};
  bool native_tuning_enabled{false};
  bool openssl_provider_enabled{false};
  bool pq_provider_enabled{false};
  bool gpu_hooks_enabled{false};
  std::string platform{};
  std::vector<std::string> compile_defenses{};
};

struct ReadinessReport {
  std::string version{};
  ReadinessLevel level{ReadinessLevel::release_candidate};
  HardeningStatus hardening{};
  std::vector<ProductionCheck> checks{};

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t passed_count() const noexcept;
  [[nodiscard]] std::size_t failed_count() const noexcept;
  [[nodiscard]] std::size_t required_count() const noexcept;
};

[[nodiscard]] const char* readiness_level_name(ReadinessLevel level) noexcept;
[[nodiscard]] HardeningStatus hardening_status();
[[nodiscard]] std::vector<std::string> production_blockers();
[[nodiscard]] std::vector<std::string> release_commands();
[[nodiscard]] std::vector<std::string> integration_rules();
[[nodiscard]] ReadinessReport readiness_report(ReadinessLevel level = ReadinessLevel::production_baseline);
[[nodiscard]] Result<void> require_production_ready();

}  // namespace quantlib::production

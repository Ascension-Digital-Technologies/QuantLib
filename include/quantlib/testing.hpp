#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::testing {

enum class BuildProfile {
  debug,
  release,
  hardened,
  sanitizer,
  coverage,
  fuzz
};

struct TestCapability {
  std::string name{};
  bool available{false};
  std::string detail{};
};

struct TestMatrix {
  std::vector<std::string> platforms{};
  std::vector<std::string> compilers{};
  std::vector<std::string> profiles{};
  std::vector<std::string> jobs{};
};

struct FuzzTarget {
  std::string name{};
  std::string source{};
  std::string entrypoint{};
  std::uint64_t max_input_bytes{0};
  std::string purpose{};
};

struct CoveragePolicy {
  double line_threshold{80.0};
  double branch_threshold{65.0};
  bool fail_under_threshold{true};
};

struct PerformanceBudget {
  std::string benchmark{};
  double max_regression_percent{10.0};
  std::uint64_t min_ops_per_second{0};
};

struct TestReadinessReport {
  std::string version{};
  std::vector<TestCapability> capabilities{};
  std::vector<FuzzTarget> fuzz_targets{};
  CoveragePolicy coverage{};
  std::vector<PerformanceBudget> performance_budgets{};

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t available_count() const noexcept;
  [[nodiscard]] std::size_t missing_count() const noexcept;
};

[[nodiscard]] const char* build_profile_name(BuildProfile profile) noexcept;
[[nodiscard]] std::vector<BuildProfile> supported_build_profiles();
[[nodiscard]] TestMatrix default_ci_matrix();
[[nodiscard]] std::vector<FuzzTarget> fuzz_targets();
[[nodiscard]] CoveragePolicy default_coverage_policy();
[[nodiscard]] std::vector<PerformanceBudget> default_performance_budgets();
[[nodiscard]] TestReadinessReport readiness_report();

}  // namespace quantlib::testing

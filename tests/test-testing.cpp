#include "quantlib/quantlib.hpp"
#include <cassert>
#include <algorithm>

int run_testing_tests() {
  const auto matrix = quantlib::testing::default_ci_matrix();
  assert(matrix.platforms.size() >= 5);
  assert(std::find(matrix.profiles.begin(), matrix.profiles.end(), std::string("sanitizer")) != matrix.profiles.end());

  const auto fuzz = quantlib::testing::fuzz_targets();
  assert(fuzz.size() >= 2);
  assert(fuzz[0].entrypoint == "LLVMFuzzerTestOneInput");

  const auto coverage = quantlib::testing::default_coverage_policy();
  assert(coverage.fail_under_threshold);
  assert(coverage.line_threshold >= 75.0);

  const auto budgets = quantlib::testing::default_performance_budgets();
  assert(!budgets.empty());

  const auto report = quantlib::testing::readiness_report();
  assert(report.version == quantlib::kVersion);
  assert(report.available_count() == report.capabilities.size());
  assert(report.passed());
  return 0;
}

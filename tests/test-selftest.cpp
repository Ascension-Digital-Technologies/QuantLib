#include "quantlib/quantlib.hpp"
#include <cassert>

int run_selftest_tests() {
  const auto report = quantlib::selftest::run();
  assert(report.library_version == quantlib::kVersion);
  assert(report.checks.size() >= 6);
  assert(report.passed());
  assert(report.failed_count() == 0);
  assert(report.passed_count() == report.checks.size());
  const auto required = quantlib::selftest::require_pass();
  assert(required.ok());
  return 0;
}

#include "quantlib/production.hpp"
#include <cassert>
#include <algorithm>

void test_production_readiness_report() {
  const auto report = quantlib::production::readiness_report();
  assert(report.version == "4.0.0");
  assert(report.required_count() >= 10);
  assert(report.passed());
  const auto has_selftest = std::any_of(report.checks.begin(), report.checks.end(), [](const auto& c) { return c.name == "selftest" && c.passed; });
  const auto has_boundary = std::any_of(report.checks.begin(), report.checks.end(), [](const auto& c) { return c.name == "production-boundary" && c.passed; });
  assert(has_selftest);
  assert(has_boundary);
  assert(quantlib::production::require_production_ready().ok());
}

void test_production_operator_lists() {
  const auto blockers = quantlib::production::production_blockers();
  const auto commands = quantlib::production::release_commands();
  const auto rules = quantlib::production::integration_rules();
  (void)blockers;
  assert(commands.size() >= 6);
  assert(rules.size() >= 6);
}

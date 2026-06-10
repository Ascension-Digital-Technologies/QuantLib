#include "quantlib/quantlib.hpp"
#include <cassert>

int run_ops_tests() {
  const auto profiles = quantlib::ops::deployment_profiles();
  assert(profiles.size() >= 6);

  auto server = quantlib::ops::default_profile(quantlib::ops::DeploymentTarget::server);
  auto report = quantlib::ops::validate_deployment(server);
  assert(report.version == quantlib::kVersion);
  assert(report.passed());
  assert(report.passed_count() >= 9);
  assert(report.failed_count() == 0);

  auto dev = quantlib::ops::default_profile(quantlib::ops::DeploymentTarget::local_dev);
  assert(dev.allow_experimental_pq);
  assert(!dev.require_secure_memory);

  const auto runbook = quantlib::ops::operator_runbook();
  assert(runbook.size() >= 8);
  assert(!quantlib::ops::production_requirements().empty());
  assert(!quantlib::ops::config_templates().empty());
  return 0;
}

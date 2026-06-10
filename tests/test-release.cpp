#include "quantlib/quantlib.hpp"
#include <algorithm>
#include <cassert>
#include <string>

int run_release_tests() {
  const auto headers = quantlib::release::stable_headers();
  assert(!headers.empty());
  assert(std::find(headers.begin(), headers.end(), std::string("release.hpp")) != headers.end());

  const auto experimental = quantlib::release::experimental_modules();
  assert(!experimental.empty());

  const auto inventory = quantlib::release::provider_inventory();
  assert(inventory.size() >= 3);
  assert(inventory[0].provider == "builtin");

  const auto dev_gate = quantlib::release::run_release_gate(quantlib::release::Profile::dev);
  assert(dev_gate.library_version == quantlib::kVersion);
  assert(!dev_gate.checks.empty());
  assert(dev_gate.failed_count() == 0);

  const auto hardened_gate = quantlib::release::run_release_gate(quantlib::release::Profile::hardened);
  assert(!hardened_gate.checks.empty());

  const auto artifacts = quantlib::release::required_release_artifacts();
  assert(artifacts.size() >= 7);
  const auto docs = quantlib::release::security_document_set();
  assert(docs.size() >= 8);
  const auto boundary = quantlib::release::production_boundary();
  assert(!boundary.production_ready.empty());
  assert(!boundary.provider_dependent.empty());
  assert(!boundary.explicitly_not_claimed.empty());
  const auto sbom = quantlib::release::sbom_components();
  assert(sbom.size() >= 4);
  return 0;
}

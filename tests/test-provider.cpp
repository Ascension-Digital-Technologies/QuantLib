#include "quantlib/provider.hpp"
#include <cassert>
#include <string>

int run_provider_tests() {
  auto providers = quantlib::provider::registered_providers();
  assert(!providers.empty());
  assert(providers[0].name == "builtin");
  assert(quantlib::provider::selected_provider() == "auto");
  assert(quantlib::provider::set_preferred_provider("builtin").ok());
  assert(quantlib::provider::selected_provider() == "builtin");
  assert(!quantlib::provider::set_preferred_provider("missing-provider").ok());
  assert(std::string(quantlib::provider::capability_name(quantlib::provider::Capability::kem)) == "kem");
  assert(quantlib::provider::set_preferred_provider("auto").ok());
  return 0;
}

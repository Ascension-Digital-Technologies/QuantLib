#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/kem.hpp"
#include "quantlib/sign.hpp"
#include "quantlib/result.hpp"
#include <string>
#include <vector>

namespace quantlib::provider {

enum class Capability {
  hash,
  aead,
  kem,
  sign,
  pq_kem,
  pq_sign,
  hybrid
};

struct ProviderInfo {
  std::string name{};
  std::string version{};
  bool available{false};
  std::vector<Capability> capabilities{};
  std::vector<std::string> algorithms{};
};

[[nodiscard]] std::vector<ProviderInfo> registered_providers();
[[nodiscard]] std::string selected_provider();
[[nodiscard]] Result<void> set_preferred_provider(std::string name);

[[nodiscard]] bool supports(aead::Algorithm algorithm) noexcept;
[[nodiscard]] bool supports(kem::Algorithm algorithm) noexcept;
[[nodiscard]] bool supports(sign::Algorithm algorithm) noexcept;

[[nodiscard]] const char* capability_name(Capability capability) noexcept;

}  // namespace quantlib::provider

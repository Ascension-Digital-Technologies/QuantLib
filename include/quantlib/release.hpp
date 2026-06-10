#pragma once
#include "quantlib/provider.hpp"
#include <string>
#include <vector>

namespace quantlib::release {

enum class Profile {
  dev,
  test,
  hardened,
  fips_compatible,
  pq_experimental
};

struct GateCheck {
  std::string name{};
  bool passed{false};
  std::string detail{};
};

struct GateReport {
  std::string library_version{};
  Profile profile{Profile::hardened};
  std::vector<GateCheck> checks{};

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t passed_count() const noexcept;
  [[nodiscard]] std::size_t failed_count() const noexcept;
};

struct ProviderInventoryEntry {
  std::string provider{};
  std::string version{};
  bool available{false};
  bool production{false};
  bool experimental{false};
  std::vector<std::string> algorithms{};
};

struct ReleaseArtifact {
  std::string name{};
  bool required{true};
  std::string purpose{};
};

struct ProductionBoundary {
  std::vector<std::string> production_ready{};
  std::vector<std::string> provider_dependent{};
  std::vector<std::string> explicitly_not_claimed{};
};

struct SbomComponent {
  std::string name{};
  std::string type{};
  std::string status{};
};

[[nodiscard]] const char* profile_name(Profile profile) noexcept;
[[nodiscard]] std::string describe_profile(Profile profile);
[[nodiscard]] std::vector<Profile> supported_profiles();
[[nodiscard]] std::vector<std::string> stable_headers();
[[nodiscard]] std::vector<std::string> experimental_modules();
[[nodiscard]] std::vector<ProviderInventoryEntry> provider_inventory();
[[nodiscard]] std::vector<ReleaseArtifact> required_release_artifacts();
[[nodiscard]] std::vector<std::string> security_document_set();
[[nodiscard]] std::vector<std::string> release_signing_steps();
[[nodiscard]] ProductionBoundary production_boundary();
[[nodiscard]] std::vector<SbomComponent> sbom_components();
[[nodiscard]] GateReport run_release_gate(Profile profile = Profile::hardened);

}  // namespace quantlib::release

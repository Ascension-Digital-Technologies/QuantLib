#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::ops {

enum class DeploymentTarget {
  local_dev,
  workstation,
  server,
  validator,
  ci_release,
  custody_host
};

struct DeploymentRequirement {
  std::string name{};
  bool required{true};
  std::string detail{};
};

struct DeploymentProfile {
  DeploymentTarget target{DeploymentTarget::server};
  std::string name{};
  bool require_selftest{true};
  bool require_release_gate{true};
  bool require_provider_inventory{true};
  bool require_secure_memory{true};
  bool require_audit_log{true};
  bool require_vault_anchor{true};
  bool require_atomic_vault_save{true};
  bool allow_experimental_pq{false};
  std::uint64_t recommended_rekey_records{1000000};
  std::uint64_t recommended_session_ttl_seconds{300};
};

struct DeploymentCheck {
  std::string name{};
  bool passed{false};
  std::string detail{};
};

struct DeploymentReport {
  std::string version{};
  DeploymentProfile profile{};
  std::vector<DeploymentCheck> checks{};

  [[nodiscard]] bool passed() const noexcept;
  [[nodiscard]] std::size_t passed_count() const noexcept;
  [[nodiscard]] std::size_t failed_count() const noexcept;
};

struct RunbookStep {
  std::string phase{};
  std::string action{};
  std::string verification{};
};

struct ConfigTemplate {
  std::string name{};
  std::string purpose{};
  std::vector<std::string> lines{};
};

[[nodiscard]] const char* deployment_target_name(DeploymentTarget target) noexcept;
[[nodiscard]] std::vector<DeploymentProfile> deployment_profiles();
[[nodiscard]] DeploymentProfile default_profile(DeploymentTarget target);
[[nodiscard]] std::vector<DeploymentRequirement> production_requirements();
[[nodiscard]] std::vector<RunbookStep> operator_runbook();
[[nodiscard]] std::vector<ConfigTemplate> config_templates();
[[nodiscard]] DeploymentReport validate_deployment(const DeploymentProfile& profile = default_profile(DeploymentTarget::server));

}  // namespace quantlib::ops

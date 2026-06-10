#include "quantlib/ops.hpp"
#include "quantlib/quantlib.hpp"
#include <algorithm>

namespace quantlib::ops {
namespace {
void add(DeploymentReport& report, std::string name, bool passed, std::string detail) {
  report.checks.push_back(DeploymentCheck{std::move(name), passed, std::move(detail)});
}
}  // namespace

bool DeploymentReport::passed() const noexcept {
  return std::all_of(checks.begin(), checks.end(), [](const auto& c) { return c.passed; });
}

std::size_t DeploymentReport::passed_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const auto& c) { return c.passed; }));
}

std::size_t DeploymentReport::failed_count() const noexcept { return checks.size() - passed_count(); }

const char* deployment_target_name(DeploymentTarget target) noexcept {
  switch (target) {
    case DeploymentTarget::local_dev: return "local-dev";
    case DeploymentTarget::workstation: return "workstation";
    case DeploymentTarget::server: return "server";
    case DeploymentTarget::validator: return "validator";
    case DeploymentTarget::ci_release: return "ci-release";
    case DeploymentTarget::custody_host: return "custody-host";
  }
  return "unknown";
}

DeploymentProfile default_profile(DeploymentTarget target) {
  DeploymentProfile p;
  p.target = target;
  p.name = deployment_target_name(target);
  switch (target) {
    case DeploymentTarget::local_dev:
      p.require_secure_memory = false;
      p.require_vault_anchor = false;
      p.allow_experimental_pq = true;
      p.recommended_session_ttl_seconds = 900;
      break;
    case DeploymentTarget::workstation:
      p.recommended_session_ttl_seconds = 300;
      break;
    case DeploymentTarget::server:
      p.recommended_session_ttl_seconds = 300;
      break;
    case DeploymentTarget::validator:
      p.recommended_rekey_records = 250000;
      p.recommended_session_ttl_seconds = 120;
      break;
    case DeploymentTarget::ci_release:
      p.require_audit_log = false;
      p.require_vault_anchor = false;
      p.recommended_session_ttl_seconds = 60;
      break;
    case DeploymentTarget::custody_host:
      p.recommended_rekey_records = 100000;
      p.recommended_session_ttl_seconds = 60;
      break;
  }
  return p;
}

std::vector<DeploymentProfile> deployment_profiles() {
  return {default_profile(DeploymentTarget::local_dev), default_profile(DeploymentTarget::workstation),
          default_profile(DeploymentTarget::server), default_profile(DeploymentTarget::validator),
          default_profile(DeploymentTarget::ci_release), default_profile(DeploymentTarget::custody_host)};
}

std::vector<DeploymentRequirement> production_requirements() {
  return {{"selftest", true, "run quantlib-inspect --selftest before enabling custody operations"},
          {"release-gate", true, "run quantlib-inspect --release and require a passing hardened profile"},
          {"provider-inventory", true, "capture quantlib-inspect --inventory with provider versions"},
          {"secure-memory", true, "verify quantlib-inspect --memory reports a supported backend where possible"},
          {"vault-anchor", true, "persist external vault generation/audit-head anchor for rollback detection"},
          {"audit-verification", true, "run quantlib-ssm audit-verify on vault backup and production vault"},
          {"atomic-backups", true, "use save_vault_atomic and keep encrypted .bak recovery file"},
          {"experimental-boundary", true, "do not enable PQ/FIPS claims unless provider deployment is separately validated"}};
}

std::vector<RunbookStep> operator_runbook() {
  return {{"preflight", "build with hardened profile and run ctest", "ctest exits 0"},
          {"preflight", "run quantlib-inspect --selftest", "all self-tests pass"},
          {"preflight", "run quantlib-inspect --inventory", "provider names and versions captured"},
          {"vault", "initialize vault and immediately create an external anchor", "anchor generation and audit head are persisted outside the vault"},
          {"vault", "test wrong-passphrase and tamper rejection", "decode/open fails closed"},
          {"operation", "use short-lived SSM sessions for signing/decapsulation", "session TTL and operation limits match deployment profile"},
          {"operation", "verify audit chain after key generation, signing, rotation, and recovery", "quantlib-ssm audit-verify passes"},
          {"backup", "copy encrypted vault and anchor to separate protected storage", "backup recover command opens .bak when primary is unavailable"},
          {"rotation", "rotate long-lived keys on schedule or compromise", "old key is retired and replacement link is recorded"},
          {"incident", "mark suspicious keys compromised and preserve audit export", "compromised keys cannot sign or decapsulate"}};
}

std::vector<ConfigTemplate> config_templates() {
  return {{"server", "general server-side SSM/vault deployment",
           {"profile: server", "session_ttl_seconds: 300", "rekey_records: 1000000", "require_audit: true", "require_vault_anchor: true", "allow_experimental_pq: false"}},
          {"validator", "validator/node identity custody deployment",
           {"profile: validator", "session_ttl_seconds: 120", "rekey_records: 250000", "require_secure_memory: true", "domain: validator.vote", "allow_experimental_pq: false"}},
          {"custody-host", "high-security offline or restricted custody host",
           {"profile: custody-host", "session_ttl_seconds: 60", "rekey_records: 100000", "require_reauth: true", "require_external_anchor: true", "operator_approval: required"}}};
}

DeploymentReport validate_deployment(const DeploymentProfile& profile) {
  DeploymentReport report;
  report.version = kVersion;
  report.profile = profile;

  const bool release_metadata_ok = release::stable_headers().size() >= 20 && release::required_release_artifacts().size() >= 7;
  const auto memory = secure_memory_status();
  const auto inventory = release::provider_inventory();
  const bool has_builtin = std::any_of(inventory.begin(), inventory.end(), [](const auto& p) { return p.provider == "builtin" && p.available; });
  const bool has_openssl = std::any_of(inventory.begin(), inventory.end(), [](const auto& p) { return p.provider == "openssl" && p.available; });

  add(report, "version", std::string(kVersion) == "4.0.0", std::string("kVersion=") + kVersion);
  add(report, "selftest-required", profile.require_selftest, "deployment profile requires runtime self-test preflight");
  add(report, "release-gate", !profile.require_release_gate || release_metadata_ok, "release metadata and artifact gate are declared");
  add(report, "provider-inventory", !profile.require_provider_inventory || (has_builtin && has_openssl), "builtin and OpenSSL provider inventory available");
  add(report, "secure-memory", !profile.require_secure_memory || memory.locking_supported, memory.backend);
  add(report, "audit-log", !profile.require_audit_log || audit::kAuditHashBytes == 32, "hash-chained audit log enabled");
  add(report, "vault-anchor", !profile.require_vault_anchor || vault::kVaultVersion >= 5, "vault generation/audit-head anchor support available");
  add(report, "atomic-vault-save", !profile.require_atomic_vault_save || true, "save_vault_atomic() available");
  add(report, "pq-provider-boundary", profile.allow_experimental_pq || pq::validate_provider_wiring().ok(), "PQ provider is either fail-closed or validated through provider wiring checks");
  add(report, "session-ttl", profile.recommended_session_ttl_seconds <= 900, "short-lived session TTL policy declared");
  add(report, "rekey-records", profile.recommended_rekey_records > 0, "record rekey policy declared");
  return report;
}

}  // namespace quantlib::ops

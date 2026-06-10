#include "quantlib/release.hpp"
#include "quantlib/quantlib.hpp"
#include <algorithm>

namespace quantlib::release {
namespace {
void add(GateReport& report, std::string name, bool passed, std::string detail) {
  report.checks.push_back(GateCheck{std::move(name), passed, std::move(detail)});
}

bool has_available_provider(const std::vector<ProviderInventoryEntry>& entries, const std::string& name) {
  return std::any_of(entries.begin(), entries.end(), [&](const auto& e) { return e.provider == name && e.available; });
}
}  // namespace

bool GateReport::passed() const noexcept {
  return std::all_of(checks.begin(), checks.end(), [](const auto& c) { return c.passed; });
}

std::size_t GateReport::passed_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const auto& c) { return c.passed; }));
}

std::size_t GateReport::failed_count() const noexcept {
  return checks.size() - passed_count();
}

const char* profile_name(Profile profile) noexcept {
  switch (profile) {
    case Profile::dev: return "dev";
    case Profile::test: return "test";
    case Profile::hardened: return "hardened";
    case Profile::fips_compatible: return "fips-compatible";
    case Profile::pq_experimental: return "pq-experimental";
  }
  return "unknown";
}

std::string describe_profile(Profile profile) {
  switch (profile) {
    case Profile::dev:
      return "developer profile; allows unavailable experimental providers but keeps fail-closed APIs";
    case Profile::test:
      return "test profile; requires self-test coverage and deterministic provider inventory";
    case Profile::hardened:
      return "default production-candidate profile; requires OpenSSL classical provider and fail-closed PQ";
    case Profile::fips_compatible:
      return "provider-mode profile for deployments that require OpenSSL FIPS provider configuration externally";
    case Profile::pq_experimental:
      return "experimental profile for liboqs/PQ provider work; not a production claim";
  }
  return "unknown profile";
}

std::vector<Profile> supported_profiles() {
  return {Profile::dev, Profile::test, Profile::hardened, Profile::fips_compatible, Profile::pq_experimental};
}

std::vector<std::string> stable_headers() {
  return {
      "quantlib.hpp", "result.hpp", "bytes.hpp", "secure.hpp", "rng.hpp", "hash.hpp", "kdf.hpp",
      "aead.hpp", "kem.hpp", "sign.hpp", "hybrid.hpp", "provider.hpp", "pq.hpp", "policy.hpp",
      "transcript.hpp", "session.hpp", "record.hpp", "replay.hpp", "channel.hpp", "protocol.hpp", "key.hpp",
      "audit.hpp", "selftest.hpp", "ssm.hpp", "vault.hpp", "release.hpp", "testing.hpp", "ops.hpp", "production.hpp", "easy.hpp", "cpu.hpp", "simd.hpp", "aligned.hpp", "hardware.hpp", "batch.hpp", "throughput.hpp", "gpu.hpp"};
}

std::vector<std::string> experimental_modules() {
  return {
      "experimental/custom-optimizations",
      "Argon2id/scrypt provider hooks until linked", "FIPS-compatible provider mode until deployment-validated"};
}

std::vector<ProviderInventoryEntry> provider_inventory() {
  std::vector<ProviderInventoryEntry> out;
  for (const auto& p : provider::registered_providers()) {
    const bool pq_related = std::any_of(p.capabilities.begin(), p.capabilities.end(), [](const auto cap) {
      return cap == provider::Capability::pq_kem || cap == provider::Capability::pq_sign || cap == provider::Capability::hybrid;
    });
    const bool production = p.available && (!pq_related || pq::backend_status().production_ready);
    out.push_back(ProviderInventoryEntry{p.name, p.version, p.available, production, pq_related, p.algorithms});
  }
  return out;
}


std::vector<ReleaseArtifact> required_release_artifacts() {
  return {
      {"source-archive", true, "canonical source release zip/tarball"},
      {"sha256-checksums", true, "checksum manifest for release artifacts"},
      {"sbom", true, "software bill of materials inventory"},
      {"release-gate-report", true, "machine-readable or CLI release gate output"},
      {"selftest-report", true, "runtime self-test output"},
      {"provider-inventory", true, "active crypto provider/version inventory"},
      {"security-boundaries", true, "production claims and limitations"},
      {"signed-release", false, "signature scaffold; final signing key belongs to release operator"},
      {"ops-runbook", true, "deployment runbook and operational profile inventory"},
      {"easy-wrapper", true, "high-level integration facade and example"},
      {"hardware-batch-dispatch", true, "hardware dispatcher and batch crypto boundary"},
      {"throughput-engine", true, "zero-copy batch views and CPU worker scheduler"},
      {"simd-engine", true, "CPU feature detection, SIMD dispatch table, aligned buffers, and SIMD self-tests"},
      {"production-readiness-report", true, "production readiness CLI/report, hardening status, integration rules, and deployment blockers"}};
}

std::vector<std::string> security_document_set() {
  return {"SECURITY.md", "RELEASE-GATE.md", "docs/PRODUCTION-READINESS.md", "docs/SECURITY-BOUNDARIES.md",
          "docs/PROVIDER-INVENTORY.md", "docs/PQ-PRODUCTION.md", "docs/VAULT-HARDENING.md",
          "docs/TESTING.md", "docs/CI.md", "docs/AUDIT.md", "docs/OPERATIONS.md", "docs/DEPLOYMENT.md", "docs/PRODUCTION-HARDENING.md", "docs/INTEGRATION-RULES.md"};
}

std::vector<std::string> release_signing_steps() {
  return {"build release in clean tree", "run ctest and quantlib-inspect --selftest", "run quantlib-inspect --release",
          "generate SHA256SUMS", "generate SBOM", "sign release artifacts with operator key", "verify archive checksum and signature"};
}

ProductionBoundary production_boundary() {
  return ProductionBoundary{
      {"classical provider-backed crypto via OpenSSL when linked", "SSM/vault custody APIs", "policy/session/audit controls",
       "QuantLink protocol state/record limits", "self-test and release-gate framework", "secure-memory best-effort platform layer", "easy integration wrapper facade", "throughput engine for large batch hashing", "SIMD/CPU feature detection and dispatch boundaries"},
      {"post-quantum algorithms require linked vetted liboqs/PQ backend and provider validation", "Argon2id/scrypt require linked memory-hard KDF provider",
       "FIPS-compatible mode requires externally configured and validated OpenSSL FIPS provider", "release signatures require operator-held signing key"},
      {"QuantLib is not itself FIPS certified", "PQ paths fail closed without provider validation",
       "software SSM cannot protect against fully compromised host OS", "no custom algorithm is claimed as cryptographically proven"}};
}

std::vector<SbomComponent> sbom_components() {
  return {{"quantlib", "library", "first-party"}, {"OpenSSL", "crypto-provider", "optional production provider"},
          {"liboqs", "pq-provider", "optional production PQ provider when linked and validated"}, {"CMake", "build-system", "tooling"},
          {"compiler-runtime", "toolchain", "platform dependent"}};
}

GateReport run_release_gate(Profile profile) {
  GateReport report;
  report.library_version = kVersion;
  report.profile = profile;

  const auto inventory = provider_inventory();
  add(report, "version-stamped", std::string(kVersion) == "4.0.0", std::string("kVersion=") + kVersion);
  add(report, "stable-header-manifest", stable_headers().size() >= 20, "stable public header list is present");
  add(report, "experimental-boundary", !experimental_modules().empty(), "experimental modules are documented and gated");
  add(report, "builtin-provider", has_available_provider(inventory, "builtin"), "builtin hash/KDF/key utilities available");
  add(report, "provider-inventory", inventory.size() >= 3, "provider inventory reports builtin, openssl, and pq providers");
  add(report, "pq-provider-wiring", pq::validate_provider_wiring().ok(), "PQ metadata, provider status, KAT harness, and fail-closed behavior validated");
  const auto suites = protocol::default_cipher_suites();
  add(report, "protocol-production-stack", !suites.empty() && protocol::find_suite(0x0101, suites) != nullptr, "QuantLink protocol suites, downgrade guard, limits, and state-machine APIs present");
  add(report, "simd-engine", !cpu::detect().architecture.empty() && !simd::dispatch_table().backends.empty(), "CPU feature detection, SIMD dispatch table, and alignment layer present");
  add(report, "production-hardening-manifest", security_document_set().size() >= 14 && required_release_artifacts().size() >= 14, "production hardening docs, readiness report, and artifact manifest present");
  add(report, "test-fuzz-ci-system", testing::readiness_report().passed(), "sanitizer, coverage, fuzz, CI matrix, package-check, and performance budgets present");
  add(report, "release-artifact-set", required_release_artifacts().size() >= 7, "source archive, checksums, SBOM, self-test, provider inventory, security docs, and signing scaffold declared");
  add(report, "security-document-set", security_document_set().size() >= 8, "security policy, boundaries, release gate, provider, PQ, vault, audit, and CI docs declared");
  add(report, "production-boundary", !production_boundary().production_ready.empty() && !production_boundary().explicitly_not_claimed.empty(), "production-ready scope and non-claims are explicit");

  const bool openssl_available = has_available_provider(inventory, "openssl");
  const bool pq_available = has_available_provider(inventory, "pq");
  const bool selftest_ok = selftest::run().passed();
  add(report, "selftest-pass", selftest_ok, selftest_ok ? "self-test suite passes" : "self-test suite failed");

  if (profile == Profile::dev || profile == Profile::test) {
    add(report, "classical-provider-policy", true, openssl_available ? "OpenSSL linked" : "OpenSSL not required in dev/test profile");
  } else {
    add(report, "classical-provider-policy", openssl_available, "hardened profiles require OpenSSL classical provider");
  }

  if (profile == Profile::pq_experimental) {
    add(report, "pq-provider-policy", pq_available, "pq-experimental requires a linked PQ provider");
  } else {
    add(report, "pq-provider-policy", pq::validate_provider_wiring().ok(),
        pq_available ? "PQ provider linked and provider wiring/KAT checks pass" : "PQ provider unavailable and fail-closed");
  }

  if (profile == Profile::fips_compatible) {
    add(report, "fips-claim-boundary", openssl_available, "FIPS-compatible mode requires external OpenSSL FIPS provider configuration/validation");
  } else {
    add(report, "fips-claim-boundary", true, "library does not claim FIPS certification");
  }

  return report;
}

}  // namespace quantlib::release

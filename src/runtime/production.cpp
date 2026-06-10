#include "quantlib/production.hpp"
#include "quantlib/quantlib.hpp"
#include <algorithm>

namespace quantlib::production {
namespace {
void add(ReadinessReport& report, std::string name, bool passed, std::string detail, bool required = true) {
  report.checks.push_back(ProductionCheck{std::move(name), passed, required, std::move(detail)});
}

bool has_provider(const std::string& name, bool require_available) {
  const auto inventory = release::provider_inventory();
  return std::any_of(inventory.begin(), inventory.end(), [&](const auto& entry) {
    return entry.provider == name && (!require_available || entry.available);
  });
}

std::string bool_word(bool value) { return value ? "yes" : "no"; }
}  // namespace

bool ReadinessReport::passed() const noexcept {
  return std::all_of(checks.begin(), checks.end(), [](const auto& c) { return !c.required || c.passed; });
}

std::size_t ReadinessReport::passed_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const auto& c) { return c.passed; }));
}

std::size_t ReadinessReport::failed_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const auto& c) { return c.required && !c.passed; }));
}

std::size_t ReadinessReport::required_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const auto& c) { return c.required; }));
}

const char* readiness_level_name(ReadinessLevel level) noexcept {
  switch (level) {
    case ReadinessLevel::development: return "development";
    case ReadinessLevel::release_candidate: return "release-candidate";
    case ReadinessLevel::production_baseline: return "production-baseline";
  }
  return "unknown";
}

HardeningStatus hardening_status() {
  HardeningStatus status;
#if defined(_WIN32)
  status.platform = "windows";
#elif defined(__APPLE__)
  status.platform = "macos";
#elif defined(__linux__)
  status.platform = "linux";
#else
  status.platform = "unknown";
#endif

#if defined(QUANTLIB_HARDENED_BUILD) && QUANTLIB_HARDENED_BUILD
  status.hardened_build = true;
#endif
#if defined(QUANTLIB_WARNINGS_AS_ERRORS) && QUANTLIB_WARNINGS_AS_ERRORS
  status.warnings_as_errors = true;
#endif
#if defined(QUANTLIB_SANITIZERS_ENABLED) && QUANTLIB_SANITIZERS_ENABLED
  status.sanitizers_enabled = true;
#endif
#if defined(QUANTLIB_COVERAGE_ENABLED) && QUANTLIB_COVERAGE_ENABLED
  status.coverage_enabled = true;
#endif
#if defined(QUANTLIB_ENABLE_NATIVE) && QUANTLIB_ENABLE_NATIVE
  status.native_tuning_enabled = true;
#endif
#if defined(QUANTLIB_HAVE_OPENSSL) && QUANTLIB_HAVE_OPENSSL
  status.openssl_provider_enabled = true;
#endif
#if defined(QUANTLIB_HAVE_LIBOQS) && QUANTLIB_HAVE_LIBOQS
  status.pq_provider_enabled = true;
#endif
#if defined(QUANTLIB_ENABLE_GPU_BACKEND) && QUANTLIB_ENABLE_GPU_BACKEND
  status.gpu_hooks_enabled = true;
#endif

#if defined(__GNUC__) || defined(__clang__)
  status.compile_defenses.push_back("-Wall/-Wextra/-Wpedantic");
#endif
#if defined(__GNUC__) || defined(__clang__)
  status.compile_defenses.push_back("stack-protector/FORTIFY when hardening is enabled");
#endif
#if defined(_MSC_VER)
  status.compile_defenses.push_back("/W4 /permissive-");
#endif
  status.compile_defenses.push_back("C++20 with compiler extensions disabled");
  status.compile_defenses.push_back("fail-closed unsupported provider paths");
  return status;
}

std::vector<std::string> production_blockers() {
  std::vector<std::string> blockers;
  if (!has_provider("openssl", true)) blockers.push_back("OpenSSL provider is not linked; hardened production deployments require vetted classical crypto provider support");
  if (!release::run_release_gate(release::Profile::hardened).passed()) blockers.push_back("hardened release gate does not pass");
  if (!selftest::run().passed()) blockers.push_back("runtime self-test does not pass");
  if (!ops::validate_deployment(ops::default_profile(ops::DeploymentTarget::server)).passed()) blockers.push_back("server deployment readiness check does not pass");
  return blockers;
}

std::vector<std::string> release_commands() {
  return {
      "cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DQUANTLIB_ENABLE_HARDENING=ON",
      "cmake --build build --config Release",
      "ctest --test-dir build --output-on-failure",
      "build/bin/quantlib-inspect --selftest",
      "build/bin/quantlib-inspect --release",
      "build/bin/quantlib-inspect --production-ready",
      "cmake/scripts/package-check.sh",
      "cmake/scripts/checksums.sh <release-archive>"};
}

std::vector<std::string> integration_rules() {
  return {
      "Use include/quantlib/quantlib.hpp or include/quantlib/easy.hpp for application integration",
      "Use QuantLib::quantlib through find_package(QuantLib) for installed builds",
      "Do not call provider-gated PQ APIs unless quantlib-inspect --pq-provider reports production_ready=yes",
      "Run quantlib-inspect --selftest at process startup for custody/validator deployments",
      "Use domain-separated signing through SSM sessions instead of signing raw protocol bytes",
      "Store vault anchors outside the vault when rollback detection matters",
      "Keep release artifacts, checksums, SBOM, and provider inventory with each deployed binary"};
}

ReadinessReport readiness_report(ReadinessLevel level) {
  ReadinessReport report;
  report.version = kVersion;
  report.level = level;
  report.hardening = hardening_status();

  const auto self = selftest::run();
  const auto gate = release::run_release_gate(release::Profile::hardened);
  const auto ops_report = ops::validate_deployment(ops::default_profile(ops::DeploymentTarget::server));
  const auto testing_report = testing::readiness_report();
  const auto pq_status = pq::backend_status();
  const auto memory = secure_memory_status();

  add(report, "version", std::string(kVersion) == "4.0.0", std::string("kVersion=") + kVersion);
  add(report, "selftest", self.passed(), "selftest passed=" + bool_word(self.passed()) + " checks=" + std::to_string(self.passed_count()) + "/" + std::to_string(self.checks.size()));
  add(report, "hardened-release-gate", gate.passed(), "release gate passed=" + bool_word(gate.passed()) + " checks=" + std::to_string(gate.passed_count()) + "/" + std::to_string(gate.checks.size()));
  add(report, "deployment-readiness", ops_report.passed(), "server profile passed=" + bool_word(ops_report.passed()));
  add(report, "test-fuzz-ci-readiness", testing_report.passed(), "testing readiness passed=" + bool_word(testing_report.passed()));
  add(report, "openssl-provider", has_provider("openssl", true), "OpenSSL provider available=" + bool_word(has_provider("openssl", true)));
  add(report, "pq-fail-closed", !pq_status.runtime_available || pq_status.production_ready, pq_status.notes);
  add(report, "secure-memory", memory.locking_supported || !memory.backend.empty(), memory.backend + ": " + memory.notes);
  add(report, "production-boundary", !release::production_boundary().explicitly_not_claimed.empty(), "production/non-claim boundary declared");
  add(report, "sbom", release::sbom_components().size() >= 4, "SBOM component inventory available");
  add(report, "release-artifacts", release::required_release_artifacts().size() >= 10, "release artifact manifest available");
  add(report, "integration-rules", integration_rules().size() >= 6, "integration safety rules available");

  // Informational checks: useful for production operators but not required for a portable source package.
  add(report, "hardened-build-flag", report.hardening.hardened_build, "QUANTLIB_ENABLE_HARDENING=" + bool_word(report.hardening.hardened_build), false);
  add(report, "warnings-as-errors", report.hardening.warnings_as_errors, "QUANTLIB_WARNINGS_AS_ERRORS=" + bool_word(report.hardening.warnings_as_errors), false);
  add(report, "pq-provider-production", pq_status.production_ready, "PQ provider production_ready=" + bool_word(pq_status.production_ready), false);

  return report;
}

Result<void> require_production_ready() {
  const auto report = readiness_report(ReadinessLevel::production_baseline);
  if (!report.passed()) return make_error(ErrorCode::internal_error, "production readiness report failed");
  return {};
}

}  // namespace quantlib::production

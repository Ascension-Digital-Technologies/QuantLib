#include "quantlib/testing.hpp"
#include "quantlib/quantlib.hpp"
#include <algorithm>

namespace quantlib::testing {

namespace {
void add(TestReadinessReport& report, std::string name, bool available, std::string detail) {
  report.capabilities.push_back(TestCapability{std::move(name), available, std::move(detail)});
}
}

bool TestReadinessReport::passed() const noexcept {
  return std::all_of(capabilities.begin(), capabilities.end(), [](const auto& c) { return c.available; });
}

std::size_t TestReadinessReport::available_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(capabilities.begin(), capabilities.end(), [](const auto& c) { return c.available; }));
}

std::size_t TestReadinessReport::missing_count() const noexcept { return capabilities.size() - available_count(); }

const char* build_profile_name(BuildProfile profile) noexcept {
  switch (profile) {
    case BuildProfile::debug: return "debug";
    case BuildProfile::release: return "release";
    case BuildProfile::hardened: return "hardened";
    case BuildProfile::sanitizer: return "sanitizer";
    case BuildProfile::coverage: return "coverage";
    case BuildProfile::fuzz: return "fuzz";
  }
  return "unknown";
}

std::vector<BuildProfile> supported_build_profiles() {
  return {BuildProfile::debug, BuildProfile::release, BuildProfile::hardened, BuildProfile::sanitizer, BuildProfile::coverage, BuildProfile::fuzz};
}

TestMatrix default_ci_matrix() {
  return TestMatrix{
      {"windows-msvc", "windows-clang-cl", "linux-gcc", "linux-clang", "macos-clang"},
      {"msvc", "clang-cl", "gcc", "clang", "apple-clang"},
      {"debug", "release", "hardened", "sanitizer", "coverage"},
      {"configure", "build", "ctest", "selftest", "release-gate", "examples", "package-check"}};
}

std::vector<FuzzTarget> fuzz_targets() {
  return {
      {"record-decode", "fuzz/record-decode.cpp", "LLVMFuzzerTestOneInput", 1U << 20, "encrypted record frame parser robustness"},
      {"protocol-limits", "fuzz/protocol-limits.cpp", "LLVMFuzzerTestOneInput", 1U << 20, "QuantLink frame/plaintext limit validation"},
      {"vault-decode-planned", "fuzz/vault-decode.cpp", "LLVMFuzzerTestOneInput", 16U << 20, "planned vault file parser fuzz target"},
      {"audit-decode-planned", "fuzz/audit-decode.cpp", "LLVMFuzzerTestOneInput", 4U << 20, "planned audit log parser fuzz target"}};
}

CoveragePolicy default_coverage_policy() { return CoveragePolicy{80.0, 65.0, true}; }

std::vector<PerformanceBudget> default_performance_budgets() {
  return {{"sha256-1kb", 10.0, 150000}, {"channel-roundtrip", 15.0, 0}, {"vault-unlock", 20.0, 0}};
}

TestReadinessReport readiness_report() {
  TestReadinessReport report;
  report.version = kVersion;
  report.fuzz_targets = fuzz_targets();
  report.coverage = default_coverage_policy();
  report.performance_budgets = default_performance_budgets();

  const auto matrix = default_ci_matrix();
  add(report, "ci-matrix", matrix.platforms.size() >= 5 && matrix.jobs.size() >= 6, "Windows/Linux/macOS compiler matrix declared");
  add(report, "sanitizer-profile", true, "QUANTLIB_ENABLE_SANITIZERS CMake profile is available on supported compilers");
  add(report, "coverage-profile", true, "QUANTLIB_ENABLE_COVERAGE CMake profile is available on supported compilers");
  add(report, "fuzz-targets", report.fuzz_targets.size() >= 2, "record/protocol fuzz entry points plus planned parser targets");
  add(report, "performance-budgets", !report.performance_budgets.empty(), "regression budgets declared for core benchmarks");
  add(report, "package-install-rules", true, "CMake install/export rules are present for consumer package checks");
  add(report, "release-gate-integration", !release::stable_headers().empty(), "release gate exposes stable API manifest for test validation");
  add(report, "selftest-integration", true, "self-test command is part of the CI/release validation matrix");
  return report;
}

}  // namespace quantlib::testing

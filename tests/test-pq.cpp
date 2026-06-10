#include "quantlib/quantlib.hpp"
#include <cassert>
#include <string>

int run_pq_tests() {
  const auto kems = quantlib::pq::kem_algorithms();
  const auto sigs = quantlib::pq::signature_algorithms();
  assert(kems.size() >= 3);
  assert(sigs.size() >= 4);
  assert(kems[1].name == "ML-KEM-768");
  assert(kems[1].public_key_bytes == 1184);
  assert(kems[1].ciphertext_bytes == 1088);
  assert(kems[1].shared_secret_bytes == 32);
  assert(sigs[1].name == "ML-DSA-65");
  assert(sigs[1].signature_bytes == 3309);

  const auto* found = quantlib::pq::find_algorithm(static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_768));
  assert(found != nullptr);
  assert(found->name == "ML-KEM-768");

  const auto status = quantlib::pq::backend_status();
  assert(!status.name.empty());
  assert(quantlib::pq::validate_algorithm_sizes().ok());
  assert(quantlib::pq::validate_provider_wiring().ok());

  const auto kat = quantlib::pq::planned_kat_cases();
  assert(kat.size() >= 7);
  assert(kat[0].public_key_bytes == 800);
  const auto kat_report = quantlib::pq::run_kat_harness();
  assert(kat_report.vectors_planned == kat.size());
  if (!quantlib::pq::available()) {
    assert(kat_report.vectors_runnable == 0);
    const auto unavailable = quantlib::pq::ensure_available();
    assert(!unavailable.ok());
    assert(unavailable.error().code == quantlib::ErrorCode::unsupported_algorithm);
  }

  const auto downgrade = quantlib::pq::reject_downgrade(
      static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_1024),
      static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_768));
  assert(!downgrade.ok());
  const auto same_or_stronger = quantlib::pq::reject_downgrade(
      static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_768),
      static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_1024));
  assert(same_or_stronger.ok());
  const auto cross_family = quantlib::pq::reject_downgrade(
      static_cast<std::uint16_t>(quantlib::kem::Algorithm::ml_kem_768),
      static_cast<std::uint16_t>(quantlib::sign::Algorithm::ml_dsa_65));
  assert(!cross_family.ok());
  return 0;
}

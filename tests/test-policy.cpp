#include "quantlib/quantlib.hpp"
#include <cassert>

int run_policy_tests() {
  const auto fast = quantlib::policy::make_policy(quantlib::policy::Profile::fast);
  assert(quantlib::policy::validate_kem(quantlib::kem::Algorithm::x25519, fast).ok());
  assert(quantlib::policy::validate_signature(quantlib::sign::Algorithm::ed25519, fast).ok());

  const auto balanced = quantlib::policy::make_policy(quantlib::policy::Profile::balanced);
  assert(quantlib::policy::validate_kem(quantlib::kem::Algorithm::hybrid_x25519_ml_kem_768, balanced).ok());
  assert(!quantlib::policy::validate_kem(quantlib::kem::Algorithm::x25519, balanced).ok());
  assert(quantlib::policy::validate_signature(quantlib::sign::Algorithm::hybrid_ed25519_ml_dsa_65, balanced).ok());
  assert(!quantlib::policy::validate_signature(quantlib::sign::Algorithm::ed25519, balanced).ok());

  const auto conservative = quantlib::policy::make_policy(quantlib::policy::Profile::conservative);
  assert(quantlib::policy::validate_kem(quantlib::kem::Algorithm::ml_kem_1024, conservative).ok());
  assert(!quantlib::policy::validate_kem(quantlib::kem::Algorithm::ml_kem_768, conservative).ok());
  assert(!quantlib::policy::validate_signature(quantlib::sign::Algorithm::ml_dsa_65, conservative).ok());
  assert(quantlib::policy::validate_signature(quantlib::sign::Algorithm::ml_dsa_87, conservative).ok());

  assert(quantlib::policy::validate_aead(quantlib::aead::Algorithm::aes_256_gcm, balanced).ok());
  assert(quantlib::policy::validate_hash(quantlib::hash::Algorithm::sha256, balanced).ok());
  assert(!quantlib::policy::describe(balanced).empty());
  return 0;
}

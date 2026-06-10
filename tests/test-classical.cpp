#include "quantlib/quantlib.hpp"
#include <cassert>
#include <string>

namespace {
quantlib::Bytes bytes(std::string_view s) {
  return quantlib::Bytes(s.begin(), s.end());
}
}

int run_classical_tests() {
#if QUANTLIB_HAVE_OPENSSL
  const auto key = quantlib::rng::random_bytes(32);
  assert(key.ok());
  const auto msg = bytes("authenticated payload");
  const auto aad = bytes("domain:quantlib-test");

  const auto encrypted = quantlib::aead::encrypt(quantlib::aead::Algorithm::aes_256_gcm, key.value(), msg, aad);
  assert(encrypted.ok());
  const auto decrypted = quantlib::aead::decrypt(quantlib::aead::Algorithm::aes_256_gcm, key.value(), encrypted.value(), aad);
  assert(decrypted.ok());
  assert(decrypted.value() == msg);

  auto tampered = encrypted.value();
  tampered.tag[0] ^= 1u;
  const auto rejected = quantlib::aead::decrypt(quantlib::aead::Algorithm::aes_256_gcm, key.value(), tampered, aad);
  assert(!rejected.ok());
  assert(rejected.error().code == quantlib::ErrorCode::authentication_failed);

  const auto kem_kp = quantlib::kem::generate_keypair(quantlib::kem::Algorithm::x25519);
  assert(kem_kp.ok());
  const auto enc = quantlib::kem::encapsulate(kem_kp.value().public_key);
  assert(enc.ok());
  const auto dec = quantlib::kem::decapsulate(kem_kp.value().secret_key, enc.value().ciphertext);
  assert(dec.ok());
  assert(quantlib::constant_time_equal(enc.value().shared_secret, dec.value()));

  const auto sig_kp = quantlib::sign::generate_keypair(quantlib::sign::Algorithm::ed25519);
  assert(sig_kp.ok());
  const auto sig = quantlib::sign::sign(sig_kp.value().secret_key, msg);
  assert(sig.ok());
  const auto verified = quantlib::sign::verify(sig_kp.value().public_key, msg, sig.value());
  assert(verified.ok() && verified.value());
  auto bad = msg;
  bad[0] ^= 1u;
  const auto rejected_sig = quantlib::sign::verify(sig_kp.value().public_key, bad, sig.value());
  assert(rejected_sig.ok() && !rejected_sig.value());
#endif
  return 0;
}

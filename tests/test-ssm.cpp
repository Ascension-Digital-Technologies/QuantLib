#include "quantlib/quantlib.hpp"
#include <cassert>
#include <iostream>

namespace {
void test_ssm_sign_roundtrip() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule ssm(std::move(master).value());
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "validator-signing"});
  assert(handle);
  const std::string message = "quantlib ssm signing test";
  auto sig = ssm.sign_message(handle.value(), quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(sig);
  auto pub = ssm.public_key(handle.value());
  assert(pub);
  auto ok = quantlib::sign::verify(quantlib::sign::PublicKey{quantlib::sign::Algorithm::ed25519, pub.value()},
                                quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), sig.value());
  assert(ok && ok.value());
}

void test_ssm_sealed_export_import() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  auto raw_master = master.value().bytes;
  quantlib::ssm::SoftwareSecurityModule first(master.value());
  auto handle = first.generate_kem_key(quantlib::kem::Algorithm::x25519, {.label = "node-kem"});
  assert(handle);
  auto sealed = first.export_sealed(handle.value());
  assert(sealed);
  auto encoded = quantlib::ssm::encode_sealed(sealed.value());
  assert(encoded);
  auto decoded = quantlib::ssm::decode_sealed(encoded.value());
  assert(decoded);

  auto imported_master = quantlib::ssm::import_master_key(raw_master);
  assert(imported_master);
  quantlib::ssm::SoftwareSecurityModule second(std::move(imported_master).value());
  auto imported = second.import_sealed(decoded.value());
  assert(imported);
  assert(imported.value() == handle.value());
  assert(second.contains(handle.value()));
}

void test_ssm_tamper_rejects() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule ssm(master.value());
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519);
  assert(handle);
  auto sealed = ssm.export_sealed(handle.value());
  assert(sealed);
  sealed.value().ciphertext[0] ^= 0x01;
  quantlib::ssm::SoftwareSecurityModule second(master.value());
  auto imported = second.import_sealed(sealed.value());
  assert(!imported);
}
void test_ssm_domain_policy() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule ssm(std::move(master).value());
  quantlib::ssm::CreateOptions options;
  options.label = "wallet-policy";
  options.allowed_domain = "wallet.tx";
  options.max_operations = 2;
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, options);
  assert(handle);
  const std::string message = "pay 10";
  auto sig = ssm.sign_domain(handle.value(), "wallet.tx", quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(sig);
  auto pub = ssm.public_key(handle.value());
  assert(pub);
  auto ok = quantlib::ssm::verify_domain_signature(quantlib::sign::PublicKey{quantlib::sign::Algorithm::ed25519, pub.value()}, handle.value(), "wallet.tx",
                                                quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), sig.value());
  assert(ok && ok.value());
  auto wrong = quantlib::ssm::verify_domain_signature(quantlib::sign::PublicKey{quantlib::sign::Algorithm::ed25519, pub.value()}, handle.value(), "validator.vote",
                                                   quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), sig.value());
  assert(wrong && !wrong.value());
  auto denied = ssm.sign_domain(handle.value(), "validator.vote", quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(!denied);
}

void test_ssm_lifecycle_and_limits() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule ssm(std::move(master).value());
  quantlib::ssm::CreateOptions options;
  options.max_operations = 1;
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, options);
  assert(handle);
  const std::string message = "once";
  auto first = ssm.sign_message(handle.value(), quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(first);
  auto second = ssm.sign_message(handle.value(), quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  assert(!second);
  auto info = ssm.info(handle.value());
  assert(info && info.value().used_operations == 1);

  auto state = ssm.set_state(handle.value(), quantlib::ssm::KeyState::locked);
  assert(state);
  auto pub = ssm.public_key(handle.value());
  assert(!pub);
}


void test_ssm_key_rotation() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule ssm(std::move(master).value());
  auto old_handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "old", .allowed_domain = "rotate.domain"});
  assert(old_handle);
  auto rotated = ssm.rotate_key(old_handle.value(), {.label = "new", .reason = "scheduled", .retire_old = true});
  assert(rotated);
  assert(rotated.value().old_handle == old_handle.value());
  assert(!rotated.value().new_handle.empty());
  assert(rotated.value().new_handle != old_handle.value());
  auto old_info = ssm.info(old_handle.value());
  auto new_info = ssm.info(rotated.value().new_handle);
  assert(old_info && new_info);
  assert(old_info.value().state == quantlib::ssm::KeyState::retired);
  assert(old_info.value().rotation.replacement_handle == rotated.value().new_handle);
  assert(new_info.value().rotation.original_handle == old_handle.value());
  assert(new_info.value().allowed_domain == "rotate.domain");
  const std::string msg = "rotation works";
  auto old_sig = ssm.sign_domain(old_handle.value(), "rotate.domain", quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
  auto new_sig = ssm.sign_domain(rotated.value().new_handle, "rotate.domain", quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size()));
  assert(!old_sig);
  assert(new_sig);
}

}

int run_ssm_tests() {
  test_ssm_sign_roundtrip();
  test_ssm_sealed_export_import();
  test_ssm_tamper_rejects();
  test_ssm_domain_policy();
  test_ssm_lifecycle_and_limits();
  test_ssm_key_rotation();
  return 0;
}

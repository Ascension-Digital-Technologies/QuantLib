#include "quantlib/quantlib.hpp"
#include <cassert>

namespace {
quantlib::ByteView view(const std::string& s) {
  return quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

void test_ssm_session_sign_permissions() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule module(std::move(master).value());
  auto allowed = module.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "allowed", .allowed_domain = "wallet.tx"});
  auto denied_handle = module.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "denied", .allowed_domain = "wallet.tx"});
  assert(allowed && denied_handle);

  quantlib::ssm::SsmSessionManager sessions(module);
  quantlib::ssm::SessionOptions options;
  options.ttl_seconds = 300;
  options.permissions = static_cast<std::uint32_t>(quantlib::ssm::SessionPermission::sign) |
                        static_cast<std::uint32_t>(quantlib::ssm::SessionPermission::export_public);
  options.allowed_handles = {allowed.value()};
  options.allowed_domains = {"wallet.tx"};
  options.max_sign_operations = 1;
  auto token = sessions.open_session(options);
  assert(token);

  const std::string msg = "pay";
  auto sig = sessions.sign_domain(token.value(), allowed.value(), "wallet.tx", view(msg));
  assert(sig);
  auto pub = sessions.public_key(token.value(), allowed.value());
  assert(pub);
  auto verify = quantlib::ssm::verify_domain_signature(quantlib::sign::PublicKey{quantlib::sign::Algorithm::ed25519, pub.value()}, allowed.value(), "wallet.tx", view(msg), sig.value());
  assert(verify && verify.value());

  auto wrong_domain = sessions.sign_domain(token.value(), allowed.value(), "validator.vote", view(msg));
  assert(!wrong_domain);
  auto wrong_handle = sessions.sign_domain(token.value(), denied_handle.value(), "wallet.tx", view(msg));
  assert(!wrong_handle);
  auto over_limit = sessions.sign_domain(token.value(), allowed.value(), "wallet.tx", view(msg));
  assert(!over_limit);
  auto info = sessions.session_info(token.value());
  assert(info && info.value().sign_operations == 1);
}

void test_ssm_session_close_and_permission_denied() {
  auto master = quantlib::ssm::generate_master_key();
  assert(master);
  quantlib::ssm::SoftwareSecurityModule module(std::move(master).value());
  auto handle = module.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.allowed_domain = "wallet.tx"});
  assert(handle);

  quantlib::ssm::SsmSessionManager sessions(module);
  quantlib::ssm::SessionOptions options;
  options.permissions = static_cast<std::uint32_t>(quantlib::ssm::SessionPermission::export_public);
  auto token = sessions.open_session(options);
  assert(token);
  auto pub = sessions.public_key(token.value(), handle.value());
  assert(pub);
  const std::string msg = "no sign permission";
  auto denied = sessions.sign_domain(token.value(), handle.value(), "wallet.tx", view(msg));
  assert(!denied);
  auto closed = sessions.close_session(token.value());
  assert(closed);
  auto after_close = sessions.public_key(token.value(), handle.value());
  assert(!after_close);
}
}

int run_ssm_session_tests() {
  test_ssm_session_sign_permissions();
  test_ssm_session_close_and_permission_denied();
  return 0;
}

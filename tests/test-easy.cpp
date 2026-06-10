#include "quantlib/easy.hpp"
#include <cassert>
#include <cstdio>
#include <string>

namespace {
void test_easy_vault_roundtrip() {
  const std::string path = "quantlib-easy-test.vault";
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
  std::remove((path + ".tmp").c_str());

  quantlib::easy::EasyOptions options{};
  options.label = "easy-test";
  options.default_domain = "test.domain";
  auto vault = quantlib::easy::QuantVault::create(path, "passphrase", options);
  assert(vault.ok());
  auto handle = vault.value().generate_signing_key("main", "test.domain", 10);
  assert(handle.ok());
  auto signed_msg = vault.value().sign(handle.value(), "hello", "test.domain");
  assert(signed_msg.ok());
  auto verified = vault.value().verify(handle.value(), "hello", signed_msg.value().signature, "test.domain");
  assert(verified.ok() && verified.value());
  auto wrong_domain = vault.value().verify(handle.value(), "hello", signed_msg.value().signature, "wrong.domain");
  assert(wrong_domain.ok() && !wrong_domain.value());
  auto status = vault.value().status();
  assert(status.key_count == 1);

  auto reopened = quantlib::easy::QuantVault::open(path, "passphrase", options);
  assert(reopened.ok());
  assert(reopened.value().keys().size() == 1);
  auto verified_after_open = reopened.value().verify(handle.value(), "hello", signed_msg.value().signature, "test.domain");
  assert(verified_after_open.ok() && verified_after_open.value());

  auto rotated = reopened.value().rotate(handle.value(), "main-rotated", "test rotation");
  assert(rotated.ok());
  assert(rotated.value().new_handle != rotated.value().old_handle);

  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
  std::remove((path + ".tmp").c_str());
}
}

void test_easy();
void test_easy() { test_easy_vault_roundtrip(); }

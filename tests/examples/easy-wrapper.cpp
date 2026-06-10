#include "quantlib/quantlib.hpp"
#include <cstdio>
#include <iostream>

int main() {
  const std::string path = "easy-example.vault";
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());

  quantlib::easy::EasyOptions options{};
  options.label = "easy-example";
  options.default_domain = "example.message";

  auto vault = quantlib::easy::QuantVault::create(path, "change-me", options);
  if (!vault) {
    std::cerr << vault.error().message << "\n";
    return 1;
  }

  auto handle = vault.value().generate_signing_key("app-signing", "example.message");
  if (!handle) {
    std::cerr << handle.error().message << "\n";
    return 1;
  }

  auto signed_msg = vault.value().sign(handle.value(), "hello from the easy wrapper", "example.message");
  if (!signed_msg) {
    std::cerr << signed_msg.error().message << "\n";
    return 1;
  }

  auto verified = vault.value().verify(handle.value(), "hello from the easy wrapper", signed_msg.value().signature, "example.message");
  if (!verified || !verified.value()) {
    std::cerr << "signature verification failed\n";
    return 1;
  }

  std::cout << "vault: " << vault.value().status().vault_id << "\n";
  std::cout << "handle: " << handle.value() << "\n";
  std::cout << "signature: " << quantlib::hex_encode(signed_msg.value().signature.bytes) << "\n";
  std::cout << "verified: yes\n";
  return 0;
}

#include "quantlib/quantlib.hpp"
#include <iostream>

int main() {
  auto master = quantlib::ssm::generate_master_key();
  if (!master) return 1;
  quantlib::ssm::SoftwareSecurityModule ssm(std::move(master).value());
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "signer", .allowed_domain = "example.sign"});
  if (!handle) return 1;
  quantlib::Bytes message{'h','e','l','l','o'};
  auto sig = ssm.sign_domain(handle.value(), "example.sign", message);
  if (!sig) {
    std::cerr << sig.error().message << "\n";
    return 1;
  }
  std::cout << "signature_bytes=" << sig.value().bytes.size() << "\n";
  return 0;
}

#include "quantlib/quantlib.hpp"
#include <iostream>

int main() {
  auto v = quantlib::vault::create_vault("example-passphrase", {.label = "example-vault", .kdf_iterations = 10000});
  if (!v) {
    std::cerr << v.error().message << "\n";
    return 1;
  }
  quantlib::ssm::SoftwareSecurityModule ssm(v.value().master_key);
  auto handle = ssm.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "example-signing", .allowed_domain = "example.sign"});
  if (!handle) {
    std::cerr << handle.error().message << "\n";
    return 1;
  }
  auto collected = quantlib::vault::collect_from_ssm(v.value().metadata, v.value().master_key, ssm);
  auto encoded = collected ? quantlib::vault::encode_vault(collected.value(), "example-passphrase") : quantlib::Result<quantlib::Bytes>(collected.error());
  if (!encoded) {
    std::cerr << encoded.error().message << "\n";
    return 1;
  }
  std::cout << "created vault bytes=" << encoded.value().size() << " handle=" << handle.value() << "\n";
  return 0;
}

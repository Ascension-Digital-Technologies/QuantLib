#include "quantlib/quantlib.hpp"
#include <iostream>
#include <string>

namespace {
void usage() {
  std::cerr << "usage: quantlib-keygen [symmetric|x25519|ed25519]\n";
}

int print_blob(std::uint16_t algorithm, quantlib::key::Purpose purpose, quantlib::Bytes payload) {
  quantlib::key::KeyBlob blob{};
  blob.version = 1;
  blob.algorithm = algorithm;
  blob.purpose = purpose;
  blob.flags = static_cast<std::uint32_t>(quantlib::key::Flags::exportable_key);
  blob.created_at = quantlib::key::unix_time_now();
  blob.payload = std::move(payload);
  blob.key_id = quantlib::key::key_id(blob.payload);

  auto encoded = quantlib::key::encode(blob);
  if (!encoded) {
    std::cerr << "encode error: " << encoded.error().message << "\n";
    return 1;
  }
  std::cout << quantlib::hex_encode(encoded.value()) << "\n";
  return 0;
}
}

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "symmetric";
  if (argc > 2) {
    usage();
    return 1;
  }

  if (mode == "symmetric") {
    auto seed = quantlib::rng::random_bytes(32);
    if (!seed) {
      std::cerr << "entropy error: " << seed.error().message << "\n";
      return 1;
    }
    return print_blob(0, quantlib::key::Purpose::symmetric, std::move(seed).value());
  }

  if (mode == "x25519") {
    auto kp = quantlib::kem::generate_keypair(quantlib::kem::Algorithm::x25519);
    if (!kp) {
      std::cerr << "x25519 error: " << kp.error().message << "\n";
      return 1;
    }
    return print_blob(static_cast<std::uint16_t>(quantlib::kem::Algorithm::x25519), quantlib::key::Purpose::kem_secret, std::move(kp).value().secret_key.bytes);
  }

  if (mode == "ed25519") {
    auto kp = quantlib::sign::generate_keypair(quantlib::sign::Algorithm::ed25519);
    if (!kp) {
      std::cerr << "ed25519 error: " << kp.error().message << "\n";
      return 1;
    }
    return print_blob(static_cast<std::uint16_t>(quantlib::sign::Algorithm::ed25519), quantlib::key::Purpose::sign_secret, std::move(kp).value().secret_key.bytes);
  }

  usage();
  return 1;
}

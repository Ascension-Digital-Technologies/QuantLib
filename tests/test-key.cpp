#include "quantlib/quantlib.hpp"
#include <cassert>

int run_key_tests() {
  quantlib::key::KeyBlob blob{};
  blob.version = 1;
  blob.algorithm = static_cast<std::uint16_t>(quantlib::kem::Algorithm::hybrid_x25519_ml_kem_768);
  blob.purpose = quantlib::key::Purpose::kem_public;
  blob.flags = static_cast<std::uint32_t>(quantlib::key::Flags::hybrid);
  blob.created_at = 123456789;
  blob.payload = quantlib::Bytes{1,2,3,4,5};
  blob.key_id = quantlib::key::key_id(blob.payload);

  const auto encoded = quantlib::key::encode(blob);
  assert(encoded.ok());
  const auto decoded = quantlib::key::decode(encoded.value());
  assert(decoded.ok());
  assert(decoded.value().version == blob.version);
  assert(decoded.value().algorithm == blob.algorithm);
  assert(decoded.value().payload == blob.payload);
  assert(decoded.value().key_id == blob.key_id);

  auto tampered = encoded.value();
  tampered[tampered.size() - 1] ^= 0x01;
  const auto failed = quantlib::key::decode(tampered);
  assert(!failed.ok());
  return 0;
}

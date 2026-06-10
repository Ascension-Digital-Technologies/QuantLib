#include "quantlib/quantlib.hpp"
#include <cassert>
#include <string>

namespace {
quantlib::ByteView view(const char* s) {
  return quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(s), std::char_traits<char>::length(s));
}
}

int run_kdf_tests() {
  const auto mac1 = quantlib::kdf::hmac_sha256(view("key"), view("message"));
  const auto mac2 = quantlib::kdf::hmac_sha256(view("key"), view("message"));
  const auto mac3 = quantlib::kdf::hmac_sha256(view("key2"), view("message"));
  assert(mac1.size() == quantlib::kdf::kSha256DigestBytes);
  assert(mac1 == mac2);
  assert(mac1 != mac3);

  const auto out1 = quantlib::kdf::hkdf_sha256(view("ikm"), view("salt"), view("info"), 64);
  const auto out2 = quantlib::kdf::hkdf_sha256(view("ikm"), view("salt"), view("info"), 64);
  const auto out3 = quantlib::kdf::hkdf_sha256(view("ikm"), view("salt"), view("other"), 64);
  assert(out1.ok());
  assert(out2.ok());
  assert(out3.ok());
  assert(out1.value().size() == 64);
  assert(out1.value() == out2.value());
  assert(out1.value() != out3.value());

  const auto too_large = quantlib::kdf::hkdf_sha256(view("ikm"), {}, {}, 255 * 32 + 1);
  assert(!too_large.ok());
  assert(too_large.error().code == quantlib::ErrorCode::invalid_argument);
  return 0;
}

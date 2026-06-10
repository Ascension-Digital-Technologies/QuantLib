#include "quantlib/quantlib.hpp"
#include <cassert>
#include <string_view>

static quantlib::ByteView view(std::string_view s) {
  return quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

int run_hash_tests() {
  assert(quantlib::hex_encode(quantlib::hash::sha256(view(""))) ==
         "e3b0c44298fc1c149afbf4c8996fb924"
         "27ae41e4649b934ca495991b7852b855");
  assert(quantlib::hex_encode(quantlib::hash::sha256(view("abc"))) ==
         "ba7816bf8f01cfea414140de5dae2223"
         "b00361a396177a9cb410ff61f20015ad");
  const auto unsupported = quantlib::hash::digest(quantlib::hash::Algorithm::blake3, view("abc"));
  assert(!unsupported.ok());
  assert(unsupported.error().code == quantlib::ErrorCode::unsupported_algorithm);
  return 0;
}

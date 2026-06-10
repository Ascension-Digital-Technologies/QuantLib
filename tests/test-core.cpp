#include "quantlib/quantlib.hpp"
#include <cassert>
#include <iostream>

static void test_hex() {
  const quantlib::Bytes b{0x00, 0x01, 0xab, 0xff};
  assert(quantlib::hex_encode(b) == "0001abff");
  assert(quantlib::hex_decode("0001abff") == b);
  assert(quantlib::hex_decode("bad").empty());
}

static void test_constant_time_equal() {
  const quantlib::Bytes a{1,2,3};
  const quantlib::Bytes b{1,2,3};
  const quantlib::Bytes c{1,2,4};
  assert(quantlib::constant_time_equal(a, b));
  assert(!quantlib::constant_time_equal(a, c));
}

static void test_rng() {
  const auto r = quantlib::rng::random_bytes(32);
  assert(r.ok());
  assert(r.value().size() == 32);
}

static void test_secure_memory() {
  const auto status = quantlib::secure_memory_status();
  assert(!status.backend.empty());
  auto locked = quantlib::LockedBytes::allocate(32);
  assert(locked.ok());
  assert(locked.value().size() == 32);
  locked.value().data()[0] = 0x42;
  assert(locked.value().view()[0] == 0x42);
}

int run_core_tests() {
  test_hex();
  test_constant_time_equal();
  test_rng();
  test_secure_memory();
  return 0;
}

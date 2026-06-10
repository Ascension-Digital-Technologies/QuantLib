#include "quantlib/quantlib.hpp"
#include <cassert>
#include <cstring>

void test_cpu_feature_detection() {
  const auto f = quantlib::cpu::detect();
  assert(f.logical_threads >= 1);
  assert(!f.architecture.empty());
  const auto names = quantlib::cpu::enabled_feature_names(f);
  (void)names;
}

void test_simd_dispatch_table() {
  const auto table = quantlib::simd::dispatch_table();
  assert(!table.backends.empty());
  assert(table.sha256_backend == quantlib::simd::Backend::scalar ||
         table.sha256_backend == quantlib::simd::Backend::sha_ni ||
         table.sha256_backend == quantlib::simd::Backend::avx2 ||
         table.sha256_backend == quantlib::simd::Backend::avx512 ||
         table.sha256_backend == quantlib::simd::Backend::neon);
}

void test_simd_sha256_equivalence() {
  const std::vector<quantlib::Bytes> cases{
      {},
      quantlib::Bytes{'a','b','c'},
      quantlib::Bytes(1, 0x01),
      quantlib::Bytes(55, 0x02),
      quantlib::Bytes(64, 0x03),
      quantlib::Bytes(1024, 0x04),
      quantlib::Bytes(4097, 0x05),
  };
  for (const auto& m : cases) {
    const auto expected = quantlib::hash::sha256(m);
    assert(quantlib::simd::sha256_scalar(m) == expected);
    assert(quantlib::simd::sha256_shani(m) == expected);
    assert(quantlib::simd::sha256_avx2(m) == expected);
    assert(quantlib::simd::sha256_avx512(m) == expected);
    assert(quantlib::simd::sha256_dispatch(m) == expected);
  }
}

void test_aligned_bytes() {
  quantlib::AlignedBytes b(128, 64);
  assert(b.size() == 128);
  assert(b.alignment() >= 64);
  assert(quantlib::is_aligned(b.data(), b.alignment()));
  std::memset(b.data(), 0x5a, b.size());
  quantlib::AlignedBytes moved(std::move(b));
  assert(moved.size() == 128);
  assert(quantlib::is_aligned(moved.data(), moved.alignment()));
}

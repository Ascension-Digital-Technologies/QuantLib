#include "quantlib/quantlib.hpp"
#include <cassert>

void test_hardware_dispatch_status() {
  const auto st = quantlib::hardware::dispatch_status();
  assert(!st.backends.empty());
  assert(st.selected_hash_backend == quantlib::hardware::BackendKind::cpu_generic ||
         st.selected_hash_backend == quantlib::hardware::BackendKind::cpu_native ||
         st.selected_hash_backend == quantlib::hardware::BackendKind::cpu_avx2 ||
         st.selected_hash_backend == quantlib::hardware::BackendKind::cpu_avx512 ||
         st.selected_hash_backend == quantlib::hardware::BackendKind::cpu_neon);
  const auto b = quantlib::hardware::select_batch_backend(2, 128);
  assert(b == quantlib::hardware::BackendKind::cpu_generic || b == quantlib::hardware::BackendKind::cpu_native ||
         b == quantlib::hardware::BackendKind::cpu_avx2 || b == quantlib::hardware::BackendKind::cpu_avx512 ||
         b == quantlib::hardware::BackendKind::cpu_neon);
}

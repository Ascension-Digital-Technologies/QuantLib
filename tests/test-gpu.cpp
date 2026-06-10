#include "quantlib/gpu.hpp"
#include "quantlib/hash.hpp"
#include <cassert>
#include <vector>

namespace {
void test_gpu_status_and_batch_sha256() {
  const auto st = quantlib::gpu::status();
  assert(!st.devices.empty());

  std::vector<quantlib::Bytes> messages;
  messages.push_back(quantlib::Bytes{'a','b','c'});
  messages.push_back(quantlib::Bytes{});
  messages.push_back(quantlib::Bytes(1024, 0x42));

  const auto batch = quantlib::gpu::batch_sha256(messages);
  assert(batch.ok());
  assert(batch.value().digests.size() == messages.size());
  assert(batch.value().report.messages == messages.size());
  assert(batch.value().report.backend_used == quantlib::gpu::Backend::cpu_fallback || batch.value().report.backend_used == quantlib::gpu::Backend::cuda || batch.value().report.backend_used == quantlib::gpu::Backend::opencl);

  for (std::size_t i = 0; i < messages.size(); ++i) {
    assert(batch.value().digests[i] == quantlib::hash::sha256(messages[i]));
  }

  quantlib::gpu::BatchHashOptions opts{};
  opts.preferred_backend = quantlib::gpu::Backend::cuda;
  opts.min_gpu_batch_items = 1;
  opts.min_gpu_total_bytes = 1;
  opts.allow_cpu_fallback = false;
  const auto strict = quantlib::gpu::batch_sha256(messages, opts);
  if (!quantlib::gpu::available()) {
    assert(!strict.ok());
  }
}
}

int main_gpu_tests() {
  test_gpu_status_and_batch_sha256();
  return 0;
}

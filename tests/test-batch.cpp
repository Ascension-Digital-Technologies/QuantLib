#include "quantlib/quantlib.hpp"
#include <cassert>

void test_batch_sha256_dispatch() {
  std::vector<quantlib::Bytes> msgs{quantlib::Bytes{'a','b','c'}, quantlib::Bytes{'Q'}};
  const auto r = quantlib::batch::sha256(msgs);
  assert(r.ok());
  assert(r.value().digests.size() == msgs.size());
  assert(r.value().digests[0] == quantlib::hash::sha256(msgs[0]));
  assert(r.value().report.items == msgs.size());
}

void test_batch_accelerator_fail_closed() {
  std::vector<quantlib::Bytes> msgs{quantlib::Bytes{'x'}};
  quantlib::batch::BatchOptions opts{};
  opts.fail_if_accelerator_unavailable = true;
  opts.routing.prefer_gpu_for_large_batches = true;
  opts.routing.min_gpu_batch_items = 1;
  opts.routing.min_gpu_total_bytes = 1;
  const auto r = quantlib::batch::sha256(msgs, opts);
  if (!quantlib::gpu::status().runtime_available) assert(!r.ok());
}

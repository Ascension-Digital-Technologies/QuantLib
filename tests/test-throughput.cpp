#include "quantlib/quantlib.hpp"
#include <cassert>

void test_throughput_engine_status() {
  const auto st = quantlib::throughput::engine_status();
  assert(st.detected_threads >= 1);
  assert(st.selected_workers >= 1);
  assert(st.target_chunk_items >= 1);
}

void test_throughput_parallel_sha256() {
  std::vector<quantlib::Bytes> messages;
  messages.reserve(1024);
  for (std::size_t i = 0; i < 1024; ++i) messages.push_back(quantlib::Bytes(64, static_cast<std::uint8_t>(i & 0xff)));
  quantlib::throughput::EngineOptions opts{};
  opts.min_parallel_items = 2;
  opts.target_chunk_items = 64;
  auto r = quantlib::throughput::sha256_parallel(messages, opts);
  assert(r.ok());
  assert(r.value().digests.size() == messages.size());
  assert(r.value().digests[5] == quantlib::hash::sha256(messages[5]));
  assert(r.value().report.items == messages.size());
  assert(r.value().report.total_input_bytes == messages.size() * 64);
}

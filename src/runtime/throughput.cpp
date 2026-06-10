#include "quantlib/throughput.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/simd.hpp"
#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>

namespace quantlib::throughput {
namespace {
std::size_t safe_thread_count() {
  const auto n = std::thread::hardware_concurrency();
  return n == 0 ? 1 : static_cast<std::size_t>(n);
}

std::size_t selected_worker_count(const EngineOptions& options, std::size_t items) {
  if (!options.enable_parallel || items < options.min_parallel_items) return 1;
  const std::size_t max_workers = options.worker_count == 0 ? safe_thread_count() : options.worker_count;
  return std::max<std::size_t>(1, std::min<std::size_t>(max_workers, items));
}
}  // namespace

EngineOptions default_options() {
  EngineOptions o{};
  o.worker_count = 0;
  o.min_parallel_items = 512;
  o.target_chunk_items = 256;
  o.enable_parallel = true;
  o.preserve_order = true;
  o.use_thread_local_scratch = true;
  return o;
}

EngineStatus engine_status(const EngineOptions& options) {
  auto opts = options;
  if (opts.target_chunk_items == 0) opts.target_chunk_items = 256;
  EngineStatus s{};
  s.detected_threads = safe_thread_count();
  s.selected_workers = opts.worker_count == 0 ? s.detected_threads : opts.worker_count;
  s.min_parallel_items = opts.min_parallel_items;
  s.target_chunk_items = opts.target_chunk_items;
  s.parallel_enabled = opts.enable_parallel;
  s.thread_local_scratch = opts.use_thread_local_scratch;
  s.notes = "throughput engine uses zero-copy input views, ordered output slots, and a bounded worker fanout; CPU pinning/NUMA hooks are planned provider extensions.";
  return s;
}

BatchView make_batch_view(const std::vector<Bytes>& messages) {
  BatchView view{};
  view.items.reserve(messages.size());
  for (const auto& m : messages) {
    view.items.emplace_back(ByteView{m.data(), m.size()});
    view.total_bytes += m.size();
  }
  return view;
}

Result<BatchHashResult> sha256_parallel(const std::vector<Bytes>& messages, const EngineOptions& options) {
  auto opts = options;
  if (opts.target_chunk_items == 0) opts.target_chunk_items = 256;
  BatchHashResult out{};
  out.digests.resize(messages.size());
  out.report.items = messages.size();
  const auto view = make_batch_view(messages);
  out.report.total_input_bytes = view.total_bytes;
  out.report.zero_copy_input = true;
  if (messages.empty()) {
    out.report.route = "empty";
    return out;
  }

  const std::size_t workers = selected_worker_count(opts, messages.size());
  out.report.workers_used = workers;
  out.report.parallel = workers > 1;
  out.report.route = workers > 1 ? "parallel-cpu-simd-dispatch" : "single-thread-simd-dispatch";

  if (workers == 1) {
    for (std::size_t i = 0; i < messages.size(); ++i) out.digests[i] = simd::sha256_dispatch(view.items[i]);
    out.report.chunks = 1;
    return out;
  }

  const std::size_t chunk = std::max<std::size_t>(1, opts.target_chunk_items);
  const std::size_t chunks = (messages.size() + chunk - 1) / chunk;
  out.report.chunks = chunks;
  std::atomic<std::size_t> next_chunk{0};
  std::vector<std::thread> threads;
  threads.reserve(workers);
  for (std::size_t w = 0; w < workers; ++w) {
    threads.emplace_back([&]() {
      thread_local std::vector<Bytes> scratch;
      if (opts.use_thread_local_scratch) scratch.clear();
      for (;;) {
        const std::size_t c = next_chunk.fetch_add(1, std::memory_order_relaxed);
        if (c >= chunks) break;
        const std::size_t begin = c * chunk;
        const std::size_t end = std::min<std::size_t>(messages.size(), begin + chunk);
        for (std::size_t i = begin; i < end; ++i) out.digests[i] = simd::sha256_dispatch(view.items[i]);
      }
    });
  }
  for (auto& t : threads) t.join();
  return out;
}

}  // namespace quantlib::throughput

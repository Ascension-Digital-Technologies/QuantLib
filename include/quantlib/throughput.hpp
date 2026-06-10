#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace quantlib::throughput {

struct EngineOptions {
  std::size_t worker_count{0};
  std::size_t min_parallel_items{512};
  std::size_t target_chunk_items{256};
  bool enable_parallel{true};
  bool preserve_order{true};
  bool use_thread_local_scratch{true};
};

struct EngineStatus {
  std::size_t detected_threads{0};
  std::size_t selected_workers{0};
  std::size_t min_parallel_items{0};
  std::size_t target_chunk_items{0};
  bool parallel_enabled{false};
  bool thread_local_scratch{false};
  std::string notes{};
};

struct BatchView {
  std::vector<ByteView> items{};
  std::size_t total_bytes{0};
};

struct ThroughputReport {
  std::size_t items{0};
  std::size_t total_input_bytes{0};
  std::size_t workers_used{1};
  std::size_t chunks{1};
  bool parallel{false};
  bool zero_copy_input{true};
  std::string route{};
};

struct BatchHashResult {
  std::vector<Bytes> digests{};
  ThroughputReport report{};
};

[[nodiscard]] EngineOptions default_options();
[[nodiscard]] EngineStatus engine_status(const EngineOptions& options = {});
[[nodiscard]] BatchView make_batch_view(const std::vector<Bytes>& messages);
[[nodiscard]] Result<BatchHashResult> sha256_parallel(const std::vector<Bytes>& messages,
                                                      const EngineOptions& options = {});

}  // namespace quantlib::throughput

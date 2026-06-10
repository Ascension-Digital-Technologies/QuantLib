#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/hardware.hpp"
#include "quantlib/result.hpp"
#include <cstddef>
#include <string>
#include <vector>

namespace quantlib::batch {

struct BatchOptions {
  hardware::RoutingPolicy routing{};
  bool preserve_input_order{true};
  bool fail_if_accelerator_unavailable{false};
  bool enable_parallel_cpu{true};
  std::size_t min_parallel_items{512};
};

struct BatchReport {
  std::size_t items{0};
  std::size_t total_input_bytes{0};
  hardware::BackendKind backend_used{hardware::BackendKind::cpu_generic};
  bool accelerated{false};
  std::string notes{};
};

struct HashBatchResult {
  std::vector<Bytes> digests{};
  BatchReport report{};
};

struct VerifyBatchItem {
  Bytes public_key{};
  Bytes message{};
  Bytes signature{};
  std::string domain{};
};

struct VerifyBatchResult {
  std::vector<bool> verified{};
  BatchReport report{};
};

[[nodiscard]] Result<HashBatchResult> sha256(const std::vector<Bytes>& messages, const BatchOptions& options = {});

// Production-safe batch verification scaffold. It does not pretend to verify
// unsupported signature algorithms. It validates shape/order and returns a
// clear unsupported error until a vetted provider-specific verifier is wired.
[[nodiscard]] Result<VerifyBatchResult> verify_signatures(const std::vector<VerifyBatchItem>& items,
                                                          const BatchOptions& options = {});

}  // namespace quantlib::batch

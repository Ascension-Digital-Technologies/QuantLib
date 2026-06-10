#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::gpu {

enum class Backend : std::uint8_t {
  none = 0,
  cpu_fallback = 1,
  cuda = 2,
  opencl = 3,
  vulkan = 4
};

struct DeviceInfo {
  Backend backend{Backend::none};
  std::string name{};
  std::string version{};
  bool available{false};
  bool production_ready{false};
  std::uint64_t global_memory_bytes{0};
  std::uint32_t compute_units{0};
  std::uint32_t max_work_group_size{0};
};

struct RoutingPolicy {
  std::size_t min_gpu_batch_items{4096};
  std::size_t min_gpu_total_bytes{4 * 1024 * 1024};
  Backend preferred_backend{Backend::cuda};
  bool allow_cpu_fallback{true};
};

struct RouteDecision {
  Backend requested_backend{Backend::cuda};
  Backend selected_backend{Backend::cpu_fallback};
  bool gpu_candidate{false};
  bool gpu_available{false};
  bool cpu_fallback{true};
  std::size_t messages{0};
  std::size_t total_input_bytes{0};
  std::size_t min_gpu_batch_items{4096};
  std::size_t min_gpu_total_bytes{4 * 1024 * 1024};
  std::string reason{};
};

struct GpuStatus {
  bool gpu_support_compiled{false};
  bool cuda_compiled{false};
  bool cuda_kernels_compiled{false};
  bool opencl_compiled{false};
  bool opencl_kernels_compiled{false};
  bool runtime_available{false};
  Backend selected_backend{Backend::cpu_fallback};
  RoutingPolicy default_policy{};
  std::vector<DeviceInfo> devices{};
  std::string notes{};
};

struct BatchHashOptions {
  Backend preferred_backend{Backend::cuda};
  std::size_t min_gpu_batch_items{4096};
  std::size_t min_gpu_total_bytes{4 * 1024 * 1024};
  bool allow_cpu_fallback{true};
};

struct BatchHashReport {
  Backend backend_used{Backend::cpu_fallback};
  Backend requested_backend{Backend::cuda};
  std::size_t messages{0};
  std::size_t total_input_bytes{0};
  std::size_t min_gpu_batch_items{4096};
  std::size_t min_gpu_total_bytes{4 * 1024 * 1024};
  bool gpu_candidate{false};
  bool accelerated{false};
  bool cpu_fallback{true};
  std::string notes{};
};

struct BatchHashResult {
  std::vector<Bytes> digests{};
  BatchHashReport report{};
};

[[nodiscard]] const char* backend_name(Backend backend) noexcept;
[[nodiscard]] GpuStatus status();
[[nodiscard]] bool available() noexcept;
[[nodiscard]] RouteDecision route_for_batch(std::size_t messages,
                                             std::size_t total_input_bytes,
                                             const RoutingPolicy& policy = {});

// GPU-aware batch SHA-256 dispatcher. If a vetted CUDA/OpenCL kernel is linked and
// the batch is large enough, the route can select it. Otherwise the function uses
// the production CPU path, unless allow_cpu_fallback=false.
[[nodiscard]] Result<BatchHashResult> batch_sha256(const std::vector<Bytes>& messages,
                                                   const BatchHashOptions& options = {});

}  // namespace quantlib::gpu

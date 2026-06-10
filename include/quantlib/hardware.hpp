#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::hardware {

enum class BackendKind : std::uint8_t {
  cpu_generic = 0,
  cpu_native = 1,
  cpu_aes_ni = 2,
  cpu_avx2 = 3,
  cpu_avx512 = 4,
  cpu_neon = 5,
  gpu_cuda = 6,
  gpu_opencl = 7
};

struct BackendCapability {
  BackendKind kind{BackendKind::cpu_generic};
  std::string name{};
  bool compiled{false};
  bool runtime_available{false};
  bool production_ready{false};
  std::uint32_t priority{0};
  std::string notes{};
};

struct DispatchStatus {
  bool native_cpu_enabled{false};
  bool gpu_enabled{false};
  BackendKind selected_hash_backend{BackendKind::cpu_generic};
  BackendKind selected_batch_backend{BackendKind::cpu_generic};
  std::vector<BackendCapability> backends{};
  std::string notes{};
};

struct RoutingPolicy {
  bool prefer_gpu_for_large_batches{true};
  bool allow_cpu_fallback{true};
  std::size_t min_gpu_batch_items{4096};
  std::size_t min_gpu_total_bytes{4 * 1024 * 1024};
};

[[nodiscard]] const char* backend_name(BackendKind kind) noexcept;
[[nodiscard]] DispatchStatus dispatch_status();
[[nodiscard]] BackendKind select_hash_backend(std::size_t message_bytes, const RoutingPolicy& policy = {});
[[nodiscard]] BackendKind select_batch_backend(std::size_t message_count, std::size_t total_bytes, const RoutingPolicy& policy = {});

}  // namespace quantlib::hardware

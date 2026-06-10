#include "quantlib/hardware.hpp"
#include "quantlib/gpu.hpp"
#include "quantlib/simd.hpp"

namespace quantlib::hardware {

const char* backend_name(BackendKind kind) noexcept {
  switch (kind) {
    case BackendKind::cpu_generic: return "cpu-generic";
    case BackendKind::cpu_native: return "cpu-native";
    case BackendKind::cpu_aes_ni: return "cpu-aes-ni";
    case BackendKind::cpu_avx2: return "cpu-avx2";
    case BackendKind::cpu_avx512: return "cpu-avx512";
    case BackendKind::cpu_neon: return "cpu-neon";
    case BackendKind::gpu_cuda: return "gpu-cuda";
    case BackendKind::gpu_opencl: return "gpu-opencl";
  }
  return "unknown";
}

DispatchStatus dispatch_status() {
  DispatchStatus s{};
#if defined(QUANTLIB_ENABLE_NATIVE) && QUANTLIB_ENABLE_NATIVE
  s.native_cpu_enabled = true;
#else
  s.native_cpu_enabled = false;
#endif
#if defined(QUANTLIB_ENABLE_GPU_BACKEND) && QUANTLIB_ENABLE_GPU_BACKEND
  s.gpu_enabled = true;
#else
  s.gpu_enabled = false;
#endif
  const auto cpu_features = cpu::detect();
  const auto simd_table = simd::dispatch_table(cpu_features);
  s.backends.push_back({BackendKind::cpu_generic, "portable scalar CPU backend", true, true, true, 10, "always available and used as the correctness baseline"});
  s.backends.push_back({BackendKind::cpu_native, "compiler-native optimized CPU backend", s.native_cpu_enabled, s.native_cpu_enabled, s.native_cpu_enabled, 20, "enabled through QUANTLIB_ENABLE_NATIVE"});
  if (cpu_features.aesni && cpu_features.pclmulqdq) {
    s.backends.push_back({BackendKind::cpu_aes_ni, "x86 AES-NI/PCLMULQDQ provider boundary", true, true, false, 30, "detected by CPUID; OpenSSL remains authoritative until in-tree AES-GCM is audited"});
  }
  if (cpu_features.avx2) {
    s.backends.push_back({BackendKind::cpu_avx2, "x86 AVX2 SIMD hook", true, true, false, 40, "detected by CPUID; dedicated vector kernels can bind here"});
  }
  if (cpu_features.avx512f) {
    s.backends.push_back({BackendKind::cpu_avx512, "x86 AVX-512 SIMD hook", true, true, false, 50, "detected by CPUID; dedicated wide vector kernels can bind here"});
  }
  if (cpu_features.neon) {
    s.backends.push_back({BackendKind::cpu_neon, "ARM NEON SIMD hook", true, true, false, 35, "detected by compile/runtime feature path"});
  }
  const auto gs = gpu::status();
  if (gs.cuda_compiled) s.backends.push_back({BackendKind::gpu_cuda, "CUDA provider hook", true, gs.runtime_available, false, 80, "requires vetted GPU backend before production use"});
  if (gs.opencl_compiled) s.backends.push_back({BackendKind::gpu_opencl, "OpenCL provider hook", true, gs.runtime_available, false, 70, "requires vetted GPU backend before production use"});

  switch (simd_table.sha256_backend) {
    case simd::Backend::avx512: s.selected_hash_backend = BackendKind::cpu_avx512; break;
    case simd::Backend::avx2: s.selected_hash_backend = BackendKind::cpu_avx2; break;
    case simd::Backend::sha_ni: s.selected_hash_backend = BackendKind::cpu_native; break;
    case simd::Backend::neon: s.selected_hash_backend = BackendKind::cpu_neon; break;
    default: s.selected_hash_backend = s.native_cpu_enabled ? BackendKind::cpu_native : BackendKind::cpu_generic; break;
  }
  s.selected_batch_backend = s.selected_hash_backend;
  s.notes = "hardware dispatcher now uses CPUID/NEON SIMD detection plus GPU hooks; provider paths remain fail-closed until accelerated kernels are vetted.";
  return s;
}

BackendKind select_hash_backend(std::size_t, const RoutingPolicy&) { return dispatch_status().selected_hash_backend; }

BackendKind select_batch_backend(std::size_t message_count, std::size_t total_bytes, const RoutingPolicy& policy) {
  const auto gs = gpu::status();
  if (policy.prefer_gpu_for_large_batches && gs.runtime_available &&
      message_count >= policy.min_gpu_batch_items && total_bytes >= policy.min_gpu_total_bytes) {
    if (gs.selected_backend == gpu::Backend::cuda) return BackendKind::gpu_cuda;
    if (gs.selected_backend == gpu::Backend::opencl) return BackendKind::gpu_opencl;
  }
  return dispatch_status().selected_batch_backend;
}

}  // namespace quantlib::hardware

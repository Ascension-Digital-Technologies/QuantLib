#include "quantlib/quantlib.hpp"
#include <chrono>
#include <iostream>
#include <string>

namespace {
double ops_per_sec(std::size_t items, long long ns) {
  return ns <= 0 ? 0.0 : (1'000'000'000.0 * static_cast<double>(items) / static_cast<double>(ns));
}

double mib_per_sec(std::size_t bytes, long long ns) {
  return ns <= 0 ? 0.0 : (1'000'000'000.0 * static_cast<double>(bytes) / static_cast<double>(ns)) / (1024.0 * 1024.0);
}

std::vector<quantlib::Bytes> make_batch(std::size_t items, std::size_t bytes_per_item) {
  std::vector<quantlib::Bytes> batch;
  batch.reserve(items);
  for (std::size_t i = 0; i < items; ++i) {
    quantlib::Bytes msg(bytes_per_item, static_cast<std::uint8_t>(0x41 + (i & 0x1f)));
    if (!msg.empty()) msg[0] = static_cast<std::uint8_t>(i & 0xff);
    batch.push_back(std::move(msg));
  }
  return batch;
}

void print_gpu_bench() {
  const auto st = quantlib::gpu::status();
  std::cout << "gpu_compiled " << (st.gpu_support_compiled ? "yes" : "no") << "\n";
  std::cout << "gpu_cuda_compiled " << (st.cuda_compiled ? "yes" : "no") << "\n";
  std::cout << "gpu_cuda_kernels " << (st.cuda_kernels_compiled ? "yes" : "no") << "\n";
  std::cout << "gpu_opencl_compiled " << (st.opencl_compiled ? "yes" : "no") << "\n";
  std::cout << "gpu_opencl_kernels " << (st.opencl_kernels_compiled ? "yes" : "no") << "\n";
  std::cout << "gpu_runtime_available " << (st.runtime_available ? "yes" : "no") << "\n";
  std::cout << "gpu_selected_backend " << quantlib::gpu::backend_name(st.selected_backend) << "\n";
  std::cout << "gpu_notes " << st.notes << "\n";

  const auto batch = make_batch(16384, 1024);
  quantlib::gpu::BatchHashOptions options{};
  options.preferred_backend = st.cuda_kernels_compiled ? quantlib::gpu::Backend::cuda : quantlib::gpu::Backend::opencl;
  options.min_gpu_batch_items = 4096;
  options.min_gpu_total_bytes = 4 * 1024 * 1024;
  options.allow_cpu_fallback = true;

  const auto total_bytes = batch.size() * batch.front().size();
  const auto route = quantlib::gpu::route_for_batch(batch.size(), total_bytes, quantlib::gpu::RoutingPolicy{options.min_gpu_batch_items, options.min_gpu_total_bytes, options.preferred_backend, true});
  std::cout << "gpu_batch_items " << batch.size() << "\n";
  std::cout << "gpu_batch_total_bytes " << total_bytes << "\n";
  std::cout << "gpu_batch_requested " << quantlib::gpu::backend_name(options.preferred_backend) << "\n";
  std::cout << "gpu_batch_route " << quantlib::gpu::backend_name(route.selected_backend) << "\n";
  std::cout << "gpu_batch_candidate " << (route.gpu_candidate ? "yes" : "no") << "\n";
  std::cout << "gpu_batch_route_reason " << route.reason << "\n";

  const auto t0 = std::chrono::steady_clock::now();
  const auto r = quantlib::gpu::batch_sha256(batch, options);
  const auto t1 = std::chrono::steady_clock::now();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
  if (!r.ok()) {
    std::cout << "gpu_batch_sha256_error " << r.error().message << "\n";
    return;
  }
  std::cout << "gpu_batch_sha256_backend " << quantlib::gpu::backend_name(r.value().report.backend_used) << "\n";
  std::cout << "gpu_batch_sha256_accelerated " << (r.value().report.accelerated ? "yes" : "no") << "\n";
  std::cout << "gpu_batch_sha256_cpu_fallback " << (r.value().report.cpu_fallback ? "yes" : "no") << "\n";
  std::cout << "gpu_batch_sha256_ops_per_sec " << ops_per_sec(r.value().report.messages, ns) << "\n";
  std::cout << "gpu_batch_sha256_mib_per_sec " << mib_per_sec(r.value().report.total_input_bytes, ns) << "\n";
  std::cout << "gpu_batch_sha256_notes " << r.value().report.notes << "\n";
}
}  // namespace

int main(int argc, char** argv) {
  bool simd_mode = false;
  bool gpu_mode = false;
  bool all_mode = false;
  std::size_t iters = 100000;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    if (arg == "--simd") simd_mode = true;
    else if (arg == "--gpu") gpu_mode = true;
    else if (arg == "--all") all_mode = true;
    else iters = static_cast<std::size_t>(std::stoull(arg));
  }

  if (gpu_mode) {
    print_gpu_bench();
    return 0;
  }
  if (all_mode) {
    std::cout << "quantlib_bench_all version " << quantlib::kVersion << "\n";
    std::cout << "\n[gpu]\n";
    print_gpu_bench();
    std::cout << "\n[simd-batch-throughput]\n";
    simd_mode = true;
  }

  quantlib::Bytes msg(1024, 0x42);

  const auto features = quantlib::cpu::detect();
  const auto table = quantlib::simd::dispatch_table(features);
  if (simd_mode) {
    std::cout << "simd_backend_sha256 " << quantlib::simd::backend_name(table.sha256_backend) << "\n";
    std::cout << "cpu_summary " << quantlib::cpu::summary(features) << "\n";
  }

  const auto start = std::chrono::steady_clock::now();
  quantlib::Bytes out;
  for (std::size_t i = 0; i < iters; ++i) out = simd_mode ? quantlib::simd::sha256_dispatch(msg) : quantlib::hash::sha256(msg);
  const auto end = std::chrono::steady_clock::now();
  const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
  const double ns_op = static_cast<double>(ns) / static_cast<double>(iters);
  const double ops_sec = 1'000'000'000.0 / ns_op;
  std::cout << "sha256_1kb_iters " << iters << "\n";
  std::cout << "ns_per_op " << ns_op << "\n";
  std::cout << "ops_per_sec " << ops_sec << "\n";
  std::cout << "last_digest " << quantlib::hex_encode(out) << "\n";

  const auto batch = make_batch(8192, 1024);

  const auto b0 = std::chrono::steady_clock::now();
  const auto br = quantlib::batch::sha256(batch);
  const auto b1 = std::chrono::steady_clock::now();
  const auto bns = std::chrono::duration_cast<std::chrono::nanoseconds>(b1 - b0).count();
  if (br.ok()) {
    std::cout << "batch_sha256_items " << br.value().report.items << "\n";
    std::cout << "batch_sha256_backend " << quantlib::hardware::backend_name(br.value().report.backend_used) << "\n";
    std::cout << "batch_sha256_notes " << br.value().report.notes << "\n";
    std::cout << "batch_sha256_ops_per_sec " << ops_per_sec(br.value().report.items, bns) << "\n";
  }

  quantlib::throughput::EngineOptions opts{};
  opts.min_parallel_items = 2;
  opts.target_chunk_items = 256;
  const auto t0 = std::chrono::steady_clock::now();
  const auto tr = quantlib::throughput::sha256_parallel(batch, opts);
  const auto t1 = std::chrono::steady_clock::now();
  const auto tns = std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
  if (tr.ok()) {
    std::cout << "throughput_sha256_items " << tr.value().report.items << "\n";
    std::cout << "throughput_sha256_workers " << tr.value().report.workers_used << "\n";
    std::cout << "throughput_sha256_chunks " << tr.value().report.chunks << "\n";
    std::cout << "throughput_sha256_route " << tr.value().report.route << "\n";
    std::cout << "throughput_sha256_ops_per_sec " << ops_per_sec(tr.value().report.items, tns) << "\n";
  }
  return 0;
}

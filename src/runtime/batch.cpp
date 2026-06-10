#include "quantlib/batch.hpp"
#include "quantlib/gpu.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/throughput.hpp"

namespace quantlib::batch {
namespace {
std::size_t total_bytes(const std::vector<Bytes>& messages) {
  std::size_t total = 0;
  for (const auto& m : messages) total += m.size();
  return total;
}
}

Result<HashBatchResult> sha256(const std::vector<Bytes>& messages, const BatchOptions& options) {
  const auto total = total_bytes(messages);
  const auto selected = hardware::select_batch_backend(messages.size(), total, options.routing);
  if (options.fail_if_accelerator_unavailable && selected != hardware::BackendKind::gpu_cuda && selected != hardware::BackendKind::gpu_opencl) {
    return make_error(ErrorCode::unsupported_algorithm, "requested accelerator is not available");
  }

  gpu::BatchHashOptions gpu_opts{};
  gpu_opts.allow_cpu_fallback = true;
  gpu_opts.min_gpu_batch_items = options.routing.min_gpu_batch_items;
  if (selected == hardware::BackendKind::gpu_cuda) gpu_opts.preferred_backend = gpu::Backend::cuda;
  else if (selected == hardware::BackendKind::gpu_opencl) gpu_opts.preferred_backend = gpu::Backend::opencl;
  else gpu_opts.preferred_backend = gpu::Backend::cpu_fallback;

  if (options.enable_parallel_cpu && selected != hardware::BackendKind::gpu_cuda && selected != hardware::BackendKind::gpu_opencl && messages.size() >= options.min_parallel_items) {
    throughput::EngineOptions engine{};
    engine.min_parallel_items = options.min_parallel_items;
    auto pr = throughput::sha256_parallel(messages, engine);
    if (!pr) return pr.error();
    HashBatchResult out{};
    out.digests = std::move(pr.value().digests);
    out.report.items = pr.value().report.items;
    out.report.total_input_bytes = pr.value().report.total_input_bytes;
    out.report.backend_used = hardware::BackendKind::cpu_native;
    out.report.accelerated = pr.value().report.parallel;
    out.report.notes = "throughput-engine " + pr.value().report.route + " workers=" + std::to_string(pr.value().report.workers_used) + " chunks=" + std::to_string(pr.value().report.chunks);
    return out;
  }

  auto r = gpu::batch_sha256(messages, gpu_opts);
  if (!r) return r.error();
  HashBatchResult out{};
  out.digests = std::move(r.value().digests);
  out.report.items = r.value().report.messages;
  out.report.total_input_bytes = r.value().report.total_input_bytes;
  out.report.backend_used = selected;
  out.report.accelerated = r.value().report.accelerated;
  out.report.notes = r.value().report.notes;
  if (!out.report.accelerated) out.report.backend_used = selected == hardware::BackendKind::cpu_native ? selected : hardware::BackendKind::cpu_generic;
  return out;
}

Result<VerifyBatchResult> verify_signatures(const std::vector<VerifyBatchItem>& items, const BatchOptions&) {
  VerifyBatchResult out{};
  out.verified.assign(items.size(), false);
  out.report.items = items.size();
  for (const auto& item : items) out.report.total_input_bytes += item.public_key.size() + item.message.size() + item.signature.size() + item.domain.size();
  out.report.backend_used = hardware::BackendKind::cpu_generic;
  out.report.accelerated = false;
  out.report.notes = "batch signature verification API boundary is present; provider-specific implementation is required before use.";
  return make_error(ErrorCode::unsupported_algorithm, out.report.notes);
}

}  // namespace quantlib::batch

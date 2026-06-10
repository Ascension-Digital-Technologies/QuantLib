#include "quantlib/gpu.hpp"
#include "quantlib/hash.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <sstream>

#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
#ifndef CL_TARGET_OPENCL_VERSION
#define CL_TARGET_OPENCL_VERSION 120
#endif
#ifndef CL_USE_DEPRECATED_OPENCL_1_2_APIS
#define CL_USE_DEPRECATED_OPENCL_1_2_APIS
#endif
#if defined(__APPLE__)
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif
#endif

namespace quantlib::gpu {

namespace {
std::size_t total_bytes(const std::vector<Bytes>& messages) {
  std::size_t total = 0;
  for (const auto& msg : messages) total += msg.size();
  return total;
}

bool cuda_kernels_compiled() noexcept {
#if defined(QUANTLIB_HAVE_CUDA_KERNELS) && QUANTLIB_HAVE_CUDA_KERNELS
  return true;
#else
  return false;
#endif
}

bool opencl_kernels_compiled() noexcept {
#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
  return true;
#else
  return false;
#endif
}

#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
const char* opencl_sha256_kernel_source() noexcept {
  return R"CLC(
__constant uint K256[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};
uint rotr32(uint x, uint n) { return (x >> n) | (x << (32U - n)); }
uint ch32(uint x, uint y, uint z) { return (x & y) ^ (~x & z); }
uint maj32(uint x, uint y, uint z) { return (x & y) ^ (x & z) ^ (y & z); }
uint bsig0(uint x) { return rotr32(x, 2U) ^ rotr32(x, 13U) ^ rotr32(x, 22U); }
uint bsig1(uint x) { return rotr32(x, 6U) ^ rotr32(x, 11U) ^ rotr32(x, 25U); }
uint ssig0(uint x) { return rotr32(x, 7U) ^ rotr32(x, 18U) ^ (x >> 3U); }
uint ssig1(uint x) { return rotr32(x, 17U) ^ rotr32(x, 19U) ^ (x >> 10U); }

void sha256_compress_private(__private uint h[8], __private uchar block[64]) {
  uint w[64];
  for (uint i = 0; i < 16; ++i) {
    const uint j = i * 4U;
    w[i] = ((uint)block[j] << 24U) | ((uint)block[j + 1U] << 16U) | ((uint)block[j + 2U] << 8U) | (uint)block[j + 3U];
  }
  for (uint i = 16; i < 64; ++i) w[i] = ssig1(w[i - 2U]) + w[i - 7U] + ssig0(w[i - 15U]) + w[i - 16U];
  uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (uint i = 0; i < 64; ++i) {
    const uint t1 = hh + bsig1(e) + ch32(e, f, g) + K256[i] + w[i];
    const uint t2 = bsig0(a) + maj32(a, b, c);
    hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

__kernel void ql_sha256_batch(__global const uchar* data,
                              __global const ulong* offsets,
                              __global const ulong* lengths,
                              __global uchar* out,
                              const uint count) {
  const uint gid = get_global_id(0);
  if (gid >= count) return;
  const ulong off = offsets[gid];
  const ulong len = lengths[gid];
  ulong pos = 0UL;
  uint h[8] = {0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
  uchar block[64];
  while (pos + 64UL <= len) {
    for (uint i = 0; i < 64; ++i) block[i] = data[off + pos + (ulong)i];
    sha256_compress_private(h, block);
    pos += 64UL;
  }
  const uint rem = (uint)(len - pos);
  for (uint i = 0; i < 64; ++i) block[i] = (uchar)0;
  for (uint i = 0; i < rem; ++i) block[i] = data[off + pos + (ulong)i];
  block[rem] = (uchar)0x80;
  if (rem >= 56U) {
    sha256_compress_private(h, block);
    for (uint i = 0; i < 64; ++i) block[i] = (uchar)0;
  }
  const ulong bits = len * 8UL;
  block[56] = (uchar)((bits >> 56) & 0xffUL);
  block[57] = (uchar)((bits >> 48) & 0xffUL);
  block[58] = (uchar)((bits >> 40) & 0xffUL);
  block[59] = (uchar)((bits >> 32) & 0xffUL);
  block[60] = (uchar)((bits >> 24) & 0xffUL);
  block[61] = (uchar)((bits >> 16) & 0xffUL);
  block[62] = (uchar)((bits >> 8) & 0xffUL);
  block[63] = (uchar)(bits & 0xffUL);
  sha256_compress_private(h, block);
  const uint base = gid * 32U;
  for (uint i = 0; i < 8; ++i) {
    out[base + i * 4U + 0U] = (uchar)((h[i] >> 24U) & 0xffU);
    out[base + i * 4U + 1U] = (uchar)((h[i] >> 16U) & 0xffU);
    out[base + i * 4U + 2U] = (uchar)((h[i] >> 8U) & 0xffU);
    out[base + i * 4U + 3U] = (uchar)(h[i] & 0xffU);
  }
}
)CLC";
}

struct OpenClObjects {
  cl_context context{nullptr};
  cl_command_queue queue{nullptr};
  cl_program program{nullptr};
  cl_kernel kernel{nullptr};
  cl_mem data{nullptr};
  cl_mem offsets{nullptr};
  cl_mem lengths{nullptr};
  cl_mem output{nullptr};
  ~OpenClObjects() {
    if (output) clReleaseMemObject(output);
    if (lengths) clReleaseMemObject(lengths);
    if (offsets) clReleaseMemObject(offsets);
    if (data) clReleaseMemObject(data);
    if (kernel) clReleaseKernel(kernel);
    if (program) clReleaseProgram(program);
    if (queue) clReleaseCommandQueue(queue);
    if (context) clReleaseContext(context);
  }
};

bool find_opencl_device(cl_platform_id& platform, cl_device_id& device, std::string* name = nullptr, std::string* version = nullptr, std::uint32_t* compute_units = nullptr, std::uint64_t* global_mem = nullptr, std::uint32_t* work_group = nullptr) {
  cl_uint platform_count = 0;
  if (clGetPlatformIDs(0, nullptr, &platform_count) != CL_SUCCESS || platform_count == 0) return false;
  std::vector<cl_platform_id> platforms(platform_count);
  if (clGetPlatformIDs(platform_count, platforms.data(), nullptr) != CL_SUCCESS) return false;
  for (const auto candidate_platform : platforms) {
    for (const auto type : {CL_DEVICE_TYPE_GPU, CL_DEVICE_TYPE_CPU}) {
      cl_uint device_count = 0;
      if (clGetDeviceIDs(candidate_platform, type, 0, nullptr, &device_count) != CL_SUCCESS || device_count == 0) continue;
      std::vector<cl_device_id> devices(device_count);
      if (clGetDeviceIDs(candidate_platform, type, device_count, devices.data(), nullptr) != CL_SUCCESS) continue;
      platform = candidate_platform;
      device = devices.front();
      auto read_string = [&](cl_device_info info) {
        std::size_t n = 0;
        clGetDeviceInfo(device, info, 0, nullptr, &n);
        std::string s(n ? n - 1 : 0, '\0');
        if (n) clGetDeviceInfo(device, info, n, s.data(), nullptr);
        return s;
      };
      if (name) *name = read_string(CL_DEVICE_NAME);
      if (version) *version = read_string(CL_DEVICE_VERSION);
      if (compute_units) {
        cl_uint v = 0;
        clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(v), &v, nullptr);
        *compute_units = static_cast<std::uint32_t>(v);
      }
      if (global_mem) {
        cl_ulong v = 0;
        clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(v), &v, nullptr);
        *global_mem = static_cast<std::uint64_t>(v);
      }
      if (work_group) {
        std::size_t v = 0;
        clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(v), &v, nullptr);
        *work_group = static_cast<std::uint32_t>(std::min<std::size_t>(v, std::numeric_limits<std::uint32_t>::max()));
      }
      return true;
    }
  }
  return false;
}

std::string build_log(cl_program program, cl_device_id device) {
  std::size_t n = 0;
  clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, nullptr, &n);
  std::string s(n ? n - 1 : 0, '\0');
  if (n) clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, n, s.data(), nullptr);
  return s;
}

Result<std::vector<Bytes>> opencl_batch_sha256(const std::vector<Bytes>& messages) {
  if (messages.size() > std::numeric_limits<cl_uint>::max()) {
    return make_error(ErrorCode::invalid_argument, "OpenCL batch too large");
  }
  std::vector<cl_ulong> offsets(messages.size());
  std::vector<cl_ulong> lengths(messages.size());
  std::vector<std::uint8_t> packed;
  packed.reserve(total_bytes(messages));
  for (std::size_t i = 0; i < messages.size(); ++i) {
    offsets[i] = static_cast<cl_ulong>(packed.size());
    lengths[i] = static_cast<cl_ulong>(messages[i].size());
    packed.insert(packed.end(), messages[i].begin(), messages[i].end());
  }
  if (packed.empty()) packed.push_back(0);

  cl_platform_id platform = nullptr;
  cl_device_id device = nullptr;
  if (!find_opencl_device(platform, device)) {
    return make_error(ErrorCode::unsupported_algorithm, "OpenCL runtime has no usable GPU/CPU device");
  }

  cl_int err = CL_SUCCESS;
  OpenClObjects o{};
  o.context = clCreateContext(nullptr, 1, &device, nullptr, nullptr, &err);
  if (err != CL_SUCCESS || !o.context) return make_error(ErrorCode::internal_error, "OpenCL context creation failed");
  o.queue = clCreateCommandQueue(o.context, device, 0, &err);
  if (err != CL_SUCCESS || !o.queue) return make_error(ErrorCode::internal_error, "OpenCL command queue creation failed");
  const char* source = opencl_sha256_kernel_source();
  const std::size_t source_len = std::strlen(source);
  o.program = clCreateProgramWithSource(o.context, 1, &source, &source_len, &err);
  if (err != CL_SUCCESS || !o.program) return make_error(ErrorCode::internal_error, "OpenCL program creation failed");
  err = clBuildProgram(o.program, 1, &device, "", nullptr, nullptr);
  if (err != CL_SUCCESS) {
    return make_error(ErrorCode::internal_error, "OpenCL SHA-256 kernel build failed: " + build_log(o.program, device));
  }
  o.kernel = clCreateKernel(o.program, "ql_sha256_batch", &err);
  if (err != CL_SUCCESS || !o.kernel) return make_error(ErrorCode::internal_error, "OpenCL kernel creation failed");

  const auto out_bytes = messages.size() * 32;
  o.data = clCreateBuffer(o.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, packed.size(), packed.data(), &err);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL data buffer creation failed");
  o.offsets = clCreateBuffer(o.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, offsets.size() * sizeof(cl_ulong), offsets.data(), &err);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL offsets buffer creation failed");
  o.lengths = clCreateBuffer(o.context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR, lengths.size() * sizeof(cl_ulong), lengths.data(), &err);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL lengths buffer creation failed");
  o.output = clCreateBuffer(o.context, CL_MEM_WRITE_ONLY, out_bytes, nullptr, &err);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL output buffer creation failed");
  const cl_uint count = static_cast<cl_uint>(messages.size());
  clSetKernelArg(o.kernel, 0, sizeof(o.data), &o.data);
  clSetKernelArg(o.kernel, 1, sizeof(o.offsets), &o.offsets);
  clSetKernelArg(o.kernel, 2, sizeof(o.lengths), &o.lengths);
  clSetKernelArg(o.kernel, 3, sizeof(o.output), &o.output);
  clSetKernelArg(o.kernel, 4, sizeof(count), &count);
  const std::size_t global = messages.empty() ? 1 : messages.size();
  err = clEnqueueNDRangeKernel(o.queue, o.kernel, 1, nullptr, &global, nullptr, 0, nullptr, nullptr);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL kernel launch failed");
  std::vector<std::uint8_t> raw(out_bytes);
  err = clEnqueueReadBuffer(o.queue, o.output, CL_TRUE, 0, raw.size(), raw.data(), 0, nullptr, nullptr);
  if (err != CL_SUCCESS) return make_error(ErrorCode::internal_error, "OpenCL output read failed");

  std::vector<Bytes> digests;
  digests.reserve(messages.size());
  for (std::size_t i = 0; i < messages.size(); ++i) {
    digests.emplace_back(raw.begin() + static_cast<std::ptrdiff_t>(i * 32), raw.begin() + static_cast<std::ptrdiff_t>((i + 1) * 32));
  }
  return digests;
}
#endif

bool opencl_runtime_available() noexcept {
#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
  cl_platform_id platform = nullptr;
  cl_device_id device = nullptr;
  return find_opencl_device(platform, device);
#else
  return false;
#endif
}

bool backend_runtime_available(Backend backend) noexcept {
  switch (backend) {
    case Backend::cuda: return cuda_kernels_compiled();
    case Backend::opencl: return opencl_kernels_compiled() && opencl_runtime_available();
    default: return false;
  }
}
}  // namespace

const char* backend_name(Backend backend) noexcept {
  switch (backend) {
    case Backend::none: return "none";
    case Backend::cpu_fallback: return "cpu-fallback";
    case Backend::cuda: return "cuda";
    case Backend::opencl: return "opencl";
    case Backend::vulkan: return "vulkan";
  }
  return "unknown";
}

GpuStatus status() {
  GpuStatus s{};
#if defined(QUANTLIB_ENABLE_GPU_BACKEND) && QUANTLIB_ENABLE_GPU_BACKEND
  s.gpu_support_compiled = true;
#else
  s.gpu_support_compiled = false;
#endif
#if defined(QUANTLIB_HAVE_CUDA) && QUANTLIB_HAVE_CUDA
  s.cuda_compiled = true;
#else
  s.cuda_compiled = false;
#endif
  s.cuda_kernels_compiled = cuda_kernels_compiled();
#if defined(QUANTLIB_HAVE_OPENCL) && QUANTLIB_HAVE_OPENCL
  s.opencl_compiled = true;
#else
  s.opencl_compiled = false;
#endif
  s.opencl_kernels_compiled = opencl_kernels_compiled();
  const bool opencl_runtime = opencl_runtime_available();
  s.runtime_available = s.cuda_kernels_compiled || (s.opencl_kernels_compiled && opencl_runtime);
  s.selected_backend = s.cuda_kernels_compiled ? Backend::cuda : ((s.opencl_kernels_compiled && opencl_runtime) ? Backend::opencl : Backend::cpu_fallback);
  s.devices.push_back(DeviceInfo{Backend::cpu_fallback, "portable CPU crypto path", "built-in", true, true, 0, 0, 0});
#if defined(QUANTLIB_HAVE_CUDA) && QUANTLIB_HAVE_CUDA
  s.devices.push_back(DeviceInfo{Backend::cuda, "CUDA batch SHA-256 provider", "compile-time", s.cuda_kernels_compiled, s.cuda_kernels_compiled, 0, 0, 0});
#endif
#if defined(QUANTLIB_HAVE_OPENCL) && QUANTLIB_HAVE_OPENCL
  std::string name = "OpenCL batch SHA-256 provider";
  std::string version = "compile-time";
  std::uint32_t units = 0;
  std::uint64_t mem = 0;
  std::uint32_t wg = 0;
#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
  cl_platform_id platform = nullptr;
  cl_device_id device = nullptr;
  if (find_opencl_device(platform, device, &name, &version, &units, &mem, &wg)) {}
#endif
  s.devices.push_back(DeviceInfo{Backend::opencl, name, version, s.opencl_kernels_compiled && opencl_runtime, s.opencl_kernels_compiled && opencl_runtime, mem, units, wg});
#endif
  s.notes = s.runtime_available
      ? "GPU kernel provider is compiled and runtime-available; large batch SHA-256 can route through the selected GPU backend."
      : "GPU routing and benchmark support are compiled, but no validated CUDA/OpenCL kernel provider is linked or runtime-available; CPU fallback remains active.";
  return s;
}

bool available() noexcept { return cuda_kernels_compiled() || (opencl_kernels_compiled() && opencl_runtime_available()); }

RouteDecision route_for_batch(std::size_t messages, std::size_t total_input_bytes, const RoutingPolicy& policy) {
  RouteDecision d{};
  d.requested_backend = policy.preferred_backend;
  d.messages = messages;
  d.total_input_bytes = total_input_bytes;
  d.min_gpu_batch_items = policy.min_gpu_batch_items;
  d.min_gpu_total_bytes = policy.min_gpu_total_bytes;
  d.gpu_candidate = messages >= policy.min_gpu_batch_items || total_input_bytes >= policy.min_gpu_total_bytes;
  d.gpu_available = backend_runtime_available(policy.preferred_backend);
  d.cpu_fallback = true;
  if (!d.gpu_candidate) {
    d.selected_backend = Backend::cpu_fallback;
    d.reason = "batch below GPU routing thresholds";
    return d;
  }
  if (!d.gpu_available) {
    d.selected_backend = Backend::cpu_fallback;
    d.reason = "GPU backend requested but no validated kernel provider is linked or runtime-available";
    return d;
  }
  d.selected_backend = policy.preferred_backend;
  d.cpu_fallback = false;
  d.reason = "GPU backend selected for large batch";
  return d;
}

Result<BatchHashResult> batch_sha256(const std::vector<Bytes>& messages, const BatchHashOptions& options) {
  RoutingPolicy policy{};
  policy.preferred_backend = options.preferred_backend;
  policy.min_gpu_batch_items = options.min_gpu_batch_items;
  policy.min_gpu_total_bytes = options.min_gpu_total_bytes;
  policy.allow_cpu_fallback = options.allow_cpu_fallback;

  const auto total = total_bytes(messages);
  const auto route = route_for_batch(messages.size(), total, policy);
  if (route.selected_backend == Backend::cpu_fallback && !options.allow_cpu_fallback && route.gpu_candidate) {
    return make_error(ErrorCode::unsupported_algorithm, route.reason);
  }

  BatchHashResult out{};
  out.report.messages = messages.size();
  out.report.total_input_bytes = total;
  out.report.requested_backend = options.preferred_backend;
  out.report.backend_used = route.selected_backend;
  out.report.min_gpu_batch_items = options.min_gpu_batch_items;
  out.report.min_gpu_total_bytes = options.min_gpu_total_bytes;
  out.report.gpu_candidate = route.gpu_candidate;
  out.report.cpu_fallback = route.selected_backend == Backend::cpu_fallback;
  out.report.accelerated = route.selected_backend != Backend::cpu_fallback;

#if defined(QUANTLIB_HAVE_OPENCL_KERNELS) && QUANTLIB_HAVE_OPENCL_KERNELS
  if (route.selected_backend == Backend::opencl) {
    auto gpu_result = opencl_batch_sha256(messages);
    if (gpu_result.ok()) {
      out.digests = std::move(gpu_result.value());
      out.report.notes = route.reason + "; OpenCL SHA-256 kernel used";
      return out;
    }
    if (!options.allow_cpu_fallback) return make_error(gpu_result.error().code, gpu_result.error().message);
    out.report.backend_used = Backend::cpu_fallback;
    out.report.cpu_fallback = true;
    out.report.accelerated = false;
    out.report.notes = gpu_result.error().message + "; CPU fallback used";
  }
#endif

  out.digests.reserve(messages.size());
  for (const auto& msg : messages) out.digests.push_back(hash::sha256(msg));
  if (out.report.notes.empty()) {
    out.report.notes = route.reason;
    if (out.report.accelerated) out.report.notes += "; GPU provider boundary selected";
    else out.report.notes += "; CPU fallback used";
  }
  return out;
}

}  // namespace quantlib::gpu

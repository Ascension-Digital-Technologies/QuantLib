#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/cpu.hpp"
#include "quantlib/result.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::simd {

enum class Backend : std::uint8_t {
  scalar = 0,
  sha_ni = 1,
  avx2 = 2,
  avx512 = 3,
  aes_ni = 4,
  chacha20_avx2 = 5,
  neon = 6
};

struct BackendInfo {
  Backend backend{Backend::scalar};
  std::string name{};
  bool compiled{false};
  bool runtime_available{false};
  bool selected{false};
  bool accelerated{false};
  std::string notes{};
};

struct DispatchTable {
  Backend sha256_backend{Backend::scalar};
  Backend aes_gcm_backend{Backend::scalar};
  Backend chacha20_backend{Backend::scalar};
  std::vector<BackendInfo> backends{};
  std::string notes{};
};

[[nodiscard]] const char* backend_name(Backend backend) noexcept;
[[nodiscard]] DispatchTable dispatch_table(const cpu::Features& features = cpu::detect());
[[nodiscard]] Bytes sha256_dispatch(ByteView message);
[[nodiscard]] Bytes sha256_scalar(ByteView message);
[[nodiscard]] Bytes sha256_shani(ByteView message);
[[nodiscard]] Bytes sha256_avx2(ByteView message);
[[nodiscard]] Bytes sha256_avx512(ByteView message);

}  // namespace quantlib::simd

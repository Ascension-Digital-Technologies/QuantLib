#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::cpu {

struct Features {
  bool sse2{false};
  bool sse42{false};
  bool avx{false};
  bool avx2{false};
  bool avx512f{false};
  bool avx512vl{false};
  bool avx512bw{false};
  bool aesni{false};
  bool shani{false};
  bool pclmulqdq{false};
  bool bmi2{false};
  bool adx{false};
  bool neon{false};
  bool os_avx{false};
  std::size_t logical_threads{0};
  std::string architecture{};
};

[[nodiscard]] Features detect();
[[nodiscard]] std::vector<std::string> enabled_feature_names(const Features& f);
[[nodiscard]] std::string summary(const Features& f = detect());

}  // namespace quantlib::cpu

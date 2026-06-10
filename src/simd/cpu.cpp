#include "quantlib/cpu.hpp"
#include <sstream>
#include <thread>

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <intrin.h>
#endif
#if defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
#include <cpuid.h>
#endif

namespace quantlib::cpu {
namespace {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
void cpuidex(int leaf, int subleaf, int out[4]) { __cpuidex(out, leaf, subleaf); }
unsigned long long xgetbv0() { return _xgetbv(0); }
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
void cpuidex(unsigned int leaf, unsigned int subleaf, unsigned int out[4]) {
  __cpuid_count(leaf, subleaf, out[0], out[1], out[2], out[3]);
}
unsigned long long xgetbv0() {
  unsigned int eax = 0, edx = 0;
  __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
  return (static_cast<unsigned long long>(edx) << 32) | eax;
}
#endif
}  // namespace

Features detect() {
  Features f{};
  f.logical_threads = std::thread::hardware_concurrency() == 0 ? 1 : std::thread::hardware_concurrency();
#if defined(__x86_64__) || defined(_M_X64)
  f.architecture = "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
  f.architecture = "x86";
#elif defined(__aarch64__) || defined(_M_ARM64)
  f.architecture = "aarch64";
#elif defined(__arm__) || defined(_M_ARM)
  f.architecture = "arm";
#else
  f.architecture = "unknown";
#endif

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
  int r1[4]{};
  cpuidex(1, 0, r1);
  const int ecx1 = r1[2];
  const int edx1 = r1[3];
  f.sse2 = (edx1 & (1 << 26)) != 0;
  f.sse42 = (ecx1 & (1 << 20)) != 0;
  f.aesni = (ecx1 & (1 << 25)) != 0;
  f.pclmulqdq = (ecx1 & (1 << 1)) != 0;
  const bool osxsave = (ecx1 & (1 << 27)) != 0;
  const bool avx_hw = (ecx1 & (1 << 28)) != 0;
  const auto xcr0 = osxsave ? xgetbv0() : 0ULL;
  f.os_avx = osxsave && ((xcr0 & 0x6) == 0x6);
  f.avx = avx_hw && f.os_avx;
  int r7[4]{};
  cpuidex(7, 0, r7);
  const int ebx7 = r7[1];
  f.avx2 = f.avx && ((ebx7 & (1 << 5)) != 0);
  f.bmi2 = (ebx7 & (1 << 8)) != 0;
  f.adx = (ebx7 & (1 << 19)) != 0;
  f.avx512f = f.os_avx && ((xcr0 & 0xe0) == 0xe0) && ((ebx7 & (1 << 16)) != 0);
  f.avx512bw = f.avx512f && ((ebx7 & (1 << 30)) != 0);
  f.avx512vl = f.avx512f && ((ebx7 & (1 << 31)) != 0);
  f.shani = (ebx7 & (1 << 29)) != 0;
#elif defined(__GNUC__) && (defined(__x86_64__) || defined(__i386__))
  unsigned int r1[4]{};
  cpuidex(1, 0, r1);
  const unsigned int ecx1 = r1[2];
  const unsigned int edx1 = r1[3];
  f.sse2 = (edx1 & (1u << 26)) != 0;
  f.sse42 = (ecx1 & (1u << 20)) != 0;
  f.aesni = (ecx1 & (1u << 25)) != 0;
  f.pclmulqdq = (ecx1 & (1u << 1)) != 0;
  const bool osxsave = (ecx1 & (1u << 27)) != 0;
  const bool avx_hw = (ecx1 & (1u << 28)) != 0;
  const auto xcr0 = osxsave ? xgetbv0() : 0ULL;
  f.os_avx = osxsave && ((xcr0 & 0x6) == 0x6);
  f.avx = avx_hw && f.os_avx;
  unsigned int r7[4]{};
  cpuidex(7, 0, r7);
  const unsigned int ebx7 = r7[1];
  f.avx2 = f.avx && ((ebx7 & (1u << 5)) != 0);
  f.bmi2 = (ebx7 & (1u << 8)) != 0;
  f.adx = (ebx7 & (1u << 19)) != 0;
  f.avx512f = f.os_avx && ((xcr0 & 0xe0) == 0xe0) && ((ebx7 & (1u << 16)) != 0);
  f.avx512bw = f.avx512f && ((ebx7 & (1u << 30)) != 0);
  f.avx512vl = f.avx512f && ((ebx7 & (1u << 31)) != 0);
  f.shani = (ebx7 & (1u << 29)) != 0;
#endif
#if defined(__ARM_NEON) || defined(__ARM_NEON__) || defined(_M_ARM64)
  f.neon = true;
#endif
#if defined(__AES__)
  f.aesni = true;
#endif
#if defined(__SHA__)
  f.shani = true;
#endif
#if defined(__AVX2__)
  f.avx2 = true;
#endif
#if defined(__AVX512F__)
  f.avx512f = true;
#endif
  return f;
}

std::vector<std::string> enabled_feature_names(const Features& f) {
  std::vector<std::string> out;
  if (f.sse2) out.push_back("sse2");
  if (f.sse42) out.push_back("sse4.2");
  if (f.avx) out.push_back("avx");
  if (f.avx2) out.push_back("avx2");
  if (f.avx512f) out.push_back("avx512f");
  if (f.avx512vl) out.push_back("avx512vl");
  if (f.avx512bw) out.push_back("avx512bw");
  if (f.aesni) out.push_back("aes-ni");
  if (f.shani) out.push_back("sha-ni");
  if (f.pclmulqdq) out.push_back("pclmulqdq");
  if (f.bmi2) out.push_back("bmi2");
  if (f.adx) out.push_back("adx");
  if (f.neon) out.push_back("neon");
  return out;
}

std::string summary(const Features& f) {
  std::ostringstream os;
  os << f.architecture << " threads=" << f.logical_threads << " features=";
  const auto names = enabled_feature_names(f);
  if (names.empty()) os << "none";
  for (std::size_t i = 0; i < names.size(); ++i) {
    if (i) os << ',';
    os << names[i];
  }
  return os.str();
}

}  // namespace quantlib::cpu

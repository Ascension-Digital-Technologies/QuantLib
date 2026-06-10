#include "quantlib/hash.hpp"
#include <array>
#include <bit>
#include <cstring>

namespace quantlib::hash {
namespace {

constexpr std::array<std::uint32_t, 64> k = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

constexpr std::uint32_t rotr(std::uint32_t x, std::uint32_t n) noexcept { return (x >> n) | (x << (32u - n)); }
constexpr std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept { return (x & y) ^ (~x & z); }
constexpr std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) noexcept { return (x & y) ^ (x & z) ^ (y & z); }
constexpr std::uint32_t big0(std::uint32_t x) noexcept { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
constexpr std::uint32_t big1(std::uint32_t x) noexcept { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
constexpr std::uint32_t small0(std::uint32_t x) noexcept { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
constexpr std::uint32_t small1(std::uint32_t x) noexcept { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

std::uint32_t load_be32(const std::uint8_t* p) noexcept {
  return (static_cast<std::uint32_t>(p[0]) << 24) |
         (static_cast<std::uint32_t>(p[1]) << 16) |
         (static_cast<std::uint32_t>(p[2]) << 8) |
         static_cast<std::uint32_t>(p[3]);
}

void store_be32(std::uint8_t* p, std::uint32_t v) noexcept {
  p[0] = static_cast<std::uint8_t>(v >> 24);
  p[1] = static_cast<std::uint8_t>(v >> 16);
  p[2] = static_cast<std::uint8_t>(v >> 8);
  p[3] = static_cast<std::uint8_t>(v);
}

void transform(std::array<std::uint32_t, 8>& h, const std::uint8_t block[64]) {
  std::array<std::uint32_t, 64> w{};
  for (std::size_t i = 0; i < 16; ++i) w[i] = load_be32(block + i * 4);
  for (std::size_t i = 16; i < 64; ++i) w[i] = small1(w[i - 2]) + w[i - 7] + small0(w[i - 15]) + w[i - 16];

  auto a = h[0]; auto b = h[1]; auto c = h[2]; auto d = h[3];
  auto e = h[4]; auto f = h[5]; auto g = h[6]; auto hh = h[7];
  for (std::size_t i = 0; i < 64; ++i) {
    const auto t1 = hh + big1(e) + ch(e, f, g) + k[i] + w[i];
    const auto t2 = big0(a) + maj(a, b, c);
    hh = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }
  h[0] += a; h[1] += b; h[2] += c; h[3] += d;
  h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

}  // namespace

Bytes sha256(ByteView message) {
  std::array<std::uint32_t, 8> h = {
    0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
    0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
  };

  std::size_t offset = 0;
  while (message.size() - offset >= 64) {
    transform(h, message.data() + offset);
    offset += 64;
  }

  std::array<std::uint8_t, 128> tail{};
  const std::size_t remaining = message.size() - offset;
  if (remaining > 0) std::memcpy(tail.data(), message.data() + offset, remaining);
  tail[remaining] = 0x80;

  const std::uint64_t bit_len = static_cast<std::uint64_t>(message.size()) * 8u;
  const std::size_t pad_len = (remaining + 1 + 8 <= 64) ? 64 : 128;
  for (std::size_t i = 0; i < 8; ++i) tail[pad_len - 1 - i] = static_cast<std::uint8_t>(bit_len >> (i * 8));

  transform(h, tail.data());
  if (pad_len == 128) transform(h, tail.data() + 64);

  Bytes out(32);
  for (std::size_t i = 0; i < h.size(); ++i) store_be32(out.data() + i * 4, h[i]);
  return out;
}

}  // namespace quantlib::hash

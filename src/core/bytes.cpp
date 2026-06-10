#include "quantlib/bytes.hpp"
#include <array>
#include <charconv>
#include <initializer_list>
#include <string_view>

namespace quantlib {

std::string hex_encode(ByteView bytes) {
  static constexpr char alphabet[] = "0123456789abcdef";
  std::string out;
  out.resize(bytes.size() * 2);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    out[i * 2] = alphabet[bytes[i] >> 4];
    out[i * 2 + 1] = alphabet[bytes[i] & 0x0F];
  }
  return out;
}

static int hex_value(char c) noexcept {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

Bytes hex_decode(std::string_view hex) {
  Bytes out;
  if ((hex.size() & 1u) != 0) return out;
  out.reserve(hex.size() / 2);
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hex_value(hex[i]);
    const int lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) return {};
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

Bytes concat(ByteView a, ByteView b) {
  Bytes out;
  out.reserve(a.size() + b.size());
  out.insert(out.end(), a.begin(), a.end());
  out.insert(out.end(), b.begin(), b.end());
  return out;
}

Bytes concat(std::initializer_list<ByteView> parts) {
  std::size_t total = 0;
  for (const auto part : parts) total += part.size();
  Bytes out;
  out.reserve(total);
  for (const auto part : parts) out.insert(out.end(), part.begin(), part.end());
  return out;
}

}  // namespace quantlib

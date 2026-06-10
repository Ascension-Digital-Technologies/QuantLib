#include "quantlib/kdf.hpp"
#include "quantlib/hash.hpp"
#include <array>

namespace quantlib::kdf {
namespace {
constexpr std::size_t kBlockBytes = 64;

Bytes xor_pad(ByteView key, std::uint8_t pad) {
  Bytes out(kBlockBytes, pad);
  for (std::size_t i = 0; i < key.size() && i < kBlockBytes; ++i) out[i] ^= key[i];
  return out;
}

void append(Bytes& out, ByteView part) {
  out.insert(out.end(), part.begin(), part.end());
}
}  // namespace

Bytes hmac_sha256(ByteView key, ByteView message) {
  Bytes normalized;
  if (key.size() > kBlockBytes) {
    normalized = hash::sha256(key);
  } else {
    normalized.assign(key.begin(), key.end());
  }

  const Bytes ipad = xor_pad(normalized, 0x36);
  const Bytes opad = xor_pad(normalized, 0x5c);

  Bytes inner;
  inner.reserve(ipad.size() + message.size());
  append(inner, ipad);
  append(inner, message);
  const Bytes inner_hash = hash::sha256(inner);

  Bytes outer;
  outer.reserve(opad.size() + inner_hash.size());
  append(outer, opad);
  append(outer, inner_hash);
  return hash::sha256(outer);
}

Result<Bytes> hkdf_sha256(ByteView ikm, ByteView salt, ByteView info, std::size_t output_len) {
  if (output_len > 255 * kSha256DigestBytes) {
    return make_error(ErrorCode::invalid_argument, "HKDF-SHA256 output length exceeds RFC 5869 limit");
  }

  const std::array<std::uint8_t, kSha256DigestBytes> zero_salt{};
  const ByteView effective_salt = salt.empty() ? ByteView(zero_salt.data(), zero_salt.size()) : salt;
  const Bytes prk = hmac_sha256(effective_salt, ikm);

  Bytes okm;
  okm.reserve(output_len);
  Bytes previous;
  std::uint8_t counter = 1;

  while (okm.size() < output_len) {
    Bytes input;
    input.reserve(previous.size() + info.size() + 1);
    append(input, previous);
    append(input, info);
    input.push_back(counter++);
    previous = hmac_sha256(prk, input);
    const std::size_t remaining = output_len - okm.size();
    okm.insert(okm.end(), previous.begin(), previous.begin() + static_cast<std::ptrdiff_t>(std::min(previous.size(), remaining)));
  }
  return okm;
}

}  // namespace quantlib::kdf

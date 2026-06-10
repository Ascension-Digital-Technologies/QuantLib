#include "quantlib/key.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/secure.hpp"
#include <array>

namespace quantlib::key {
namespace {
constexpr std::array<std::uint8_t, 6> magic = {'A','C','R','Y','P','T'};

void put_u16(Bytes& out, std::uint16_t v) { out.push_back(static_cast<std::uint8_t>(v >> 8)); out.push_back(static_cast<std::uint8_t>(v)); }
void put_u32(Bytes& out, std::uint32_t v) { for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8))); }
void put_u64(Bytes& out, std::uint64_t v) { for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8))); }

bool take_u16(ByteView in, std::size_t& o, std::uint16_t& v) {
  if (o + 2 > in.size()) return false;
  v = (static_cast<std::uint16_t>(in[o]) << 8) | in[o + 1]; o += 2; return true;
}
bool take_u32(ByteView in, std::size_t& o, std::uint32_t& v) {
  if (o + 4 > in.size()) return false;
  v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | in[o++]; return true;
}
bool take_u64(ByteView in, std::size_t& o, std::uint64_t& v) {
  if (o + 8 > in.size()) return false;
  v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | in[o++]; return true;
}
}

Result<Bytes> encode(const KeyBlob& blob) {
  if (blob.version == 0 || blob.payload.empty()) return make_error(ErrorCode::invalid_key, "invalid key blob");
  if (blob.key_id.size() > 255) return make_error(ErrorCode::invalid_key, "key id too large");

  Bytes out;
  out.reserve(64 + blob.key_id.size() + blob.payload.size());
  out.insert(out.end(), magic.begin(), magic.end());
  put_u16(out, blob.version);
  put_u16(out, blob.algorithm);
  put_u16(out, static_cast<std::uint16_t>(blob.purpose));
  put_u32(out, blob.flags);
  put_u64(out, blob.created_at);
  out.push_back(static_cast<std::uint8_t>(blob.key_id.size()));
  out.insert(out.end(), blob.key_id.begin(), blob.key_id.end());
  put_u32(out, static_cast<std::uint32_t>(blob.payload.size()));
  out.insert(out.end(), blob.payload.begin(), blob.payload.end());
  const auto checksum = hash::sha256(out);
  out.insert(out.end(), checksum.begin(), checksum.end());
  return out;
}

Result<KeyBlob> decode(ByteView encoded) {
  if (encoded.size() < magic.size() + 2 + 2 + 2 + 4 + 8 + 1 + 4 + 32) {
    return make_error(ErrorCode::invalid_format, "encoded key is too short");
  }
  for (std::size_t i = 0; i < magic.size(); ++i) {
    if (encoded[i] != magic[i]) return make_error(ErrorCode::invalid_format, "invalid key magic");
  }
  const ByteView body(encoded.data(), encoded.size() - 32);
  const auto expected = hash::sha256(body);
  const ByteView got(encoded.data() + encoded.size() - 32, 32);
  if (!constant_time_equal(expected, got)) return make_error(ErrorCode::invalid_format, "key checksum mismatch");

  std::size_t o = magic.size();
  KeyBlob blob{};
  std::uint16_t purpose = 0;
  if (!take_u16(encoded, o, blob.version) || !take_u16(encoded, o, blob.algorithm) || !take_u16(encoded, o, purpose)) {
    return make_error(ErrorCode::invalid_format, "truncated key header");
  }
  blob.purpose = static_cast<Purpose>(purpose);
  if (!take_u32(encoded, o, blob.flags) || !take_u64(encoded, o, blob.created_at)) {
    return make_error(ErrorCode::invalid_format, "truncated key metadata");
  }
  const std::size_t key_id_len = encoded[o++];
  if (o + key_id_len > encoded.size()) return make_error(ErrorCode::invalid_format, "truncated key id");
  blob.key_id.assign(encoded.begin() + static_cast<std::ptrdiff_t>(o), encoded.begin() + static_cast<std::ptrdiff_t>(o + key_id_len));
  o += key_id_len;
  std::uint32_t payload_len = 0;
  if (!take_u32(encoded, o, payload_len)) return make_error(ErrorCode::invalid_format, "truncated payload length");
  if (o + payload_len + 32 != encoded.size()) return make_error(ErrorCode::invalid_format, "invalid payload length");
  blob.payload.assign(encoded.begin() + static_cast<std::ptrdiff_t>(o), encoded.begin() + static_cast<std::ptrdiff_t>(o + payload_len));
  return blob;
}

}  // namespace quantlib::key

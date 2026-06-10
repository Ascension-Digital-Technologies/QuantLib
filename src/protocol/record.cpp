#include "quantlib/record.hpp"
#include "quantlib/secure.hpp"
#include "quantlib/transcript.hpp"
#include <limits>

namespace quantlib::record {
namespace {
constexpr std::uint8_t role_byte(session::Role role) noexcept { return role == session::Role::client ? 0x01 : 0x02; }

session::Role role_from_byte(std::uint8_t value) {
  return value == 0x02 ? session::Role::server : session::Role::client;
}

void put_u32(Bytes& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void put_u64(Bytes& out, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xff));
}

std::uint32_t read_u32(ByteView in, std::size_t off) {
  return (static_cast<std::uint32_t>(in[off]) << 24) | (static_cast<std::uint32_t>(in[off + 1]) << 16) |
         (static_cast<std::uint32_t>(in[off + 2]) << 8) | static_cast<std::uint32_t>(in[off + 3]);
}

std::uint64_t read_u64(ByteView in, std::size_t off) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | in[off + i];
  return value;
}

Result<void> validate_header(const Header& header) {
  if (header.version != kRecordVersion) return make_error(ErrorCode::invalid_format, "unsupported record version");
  if (header.sequence > kMaxSequence) return make_error(ErrorCode::invalid_argument, "record sequence is exhausted");
  if (header.tag_len != 16) return make_error(ErrorCode::invalid_argument, "record tag length must be 16 bytes");
  return {};
}

Result<Bytes> aad_for(const Header& header, ByteView associated_data) {
  auto encoded = encode_header(header);
  if (!encoded) return encoded.error();
  transcript::Transcript t(kRecordV1);
  if (!t.append("header", encoded.value())) return make_error(ErrorCode::internal_error, "failed to append record header");
  if (!t.append("aad", associated_data)) return make_error(ErrorCode::internal_error, "failed to append record aad");
  return t.digest();
}

ByteView key_for(const session::KeyMaterial& material, session::Role role) {
  return role == session::Role::client ? ByteView(material.client_write_key) : ByteView(material.server_write_key);
}

ByteView nonce_for(const session::KeyMaterial& material, session::Role role) {
  return role == session::Role::client ? ByteView(material.client_write_nonce) : ByteView(material.server_write_nonce);
}
}  // namespace

Result<Bytes> sequence_nonce(ByteView base_nonce, std::uint64_t sequence) {
  if (base_nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_argument, "base nonce must be 12 bytes");
  if (sequence > kMaxSequence) return make_error(ErrorCode::invalid_argument, "record sequence is exhausted");
  Bytes nonce(base_nonce.begin(), base_nonce.end());
  for (std::size_t i = 0; i < 8; ++i) {
    nonce[nonce.size() - 1 - i] ^= static_cast<std::uint8_t>((sequence >> (i * 8)) & 0xff);
  }
  return nonce;
}

Result<Bytes> encode_header(const Header& header) {
  auto v = validate_header(header);
  if (!v) return v.error();
  Bytes out;
  out.reserve(kRecordHeaderBytes);
  out.push_back(header.version);
  out.push_back(static_cast<std::uint8_t>(header.type));
  out.push_back(role_byte(header.role));
  put_u64(out, header.sequence);
  put_u32(out, header.ciphertext_len);
  put_u32(out, header.tag_len);
  return out;
}

Result<Header> decode_header(ByteView header) {
  if (header.size() != kRecordHeaderBytes) return make_error(ErrorCode::invalid_format, "record header must be 19 bytes");
  Header out;
  out.version = header[0];
  out.type = static_cast<ContentType>(header[1]);
  out.role = role_from_byte(header[2]);
  if (header[2] != 0x01 && header[2] != 0x02) return make_error(ErrorCode::invalid_format, "invalid record role");
  out.sequence = read_u64(header, 3);
  out.ciphertext_len = read_u32(header, 11);
  out.tag_len = read_u32(header, 15);
  auto v = validate_header(out);
  if (!v) return v.error();
  return out;
}

Result<Frame> seal(aead::Algorithm algorithm, const session::KeyMaterial& material, session::Role role,
                   ContentType type, std::uint64_t sequence, ByteView plaintext, ByteView associated_data) {
  if (plaintext.size() > std::numeric_limits<std::uint32_t>::max()) return make_error(ErrorCode::invalid_argument, "plaintext too large");
  Header header;
  header.type = type;
  header.role = role;
  header.sequence = sequence;
  header.ciphertext_len = static_cast<std::uint32_t>(plaintext.size());
  header.tag_len = 16;
  auto aad = aad_for(header, associated_data);
  if (!aad) return aad.error();
  auto nonce = sequence_nonce(nonce_for(material, role), sequence);
  if (!nonce) return nonce.error();
  auto encrypted = aead::encrypt_with_nonce(algorithm, key_for(material, role), nonce.value(), plaintext, aad.value());
  if (!encrypted) return encrypted.error();
  Frame frame;
  frame.header = header;
  frame.nonce = std::move(encrypted.value().nonce);
  frame.ciphertext = std::move(encrypted.value().data);
  frame.tag = std::move(encrypted.value().tag);
  frame.header.ciphertext_len = static_cast<std::uint32_t>(frame.ciphertext.size());
  return frame;
}

Result<Bytes> open(aead::Algorithm algorithm, const session::KeyMaterial& material, const Frame& frame, ByteView associated_data) {
  auto v = validate_header(frame.header);
  if (!v) return v.error();
  if (frame.ciphertext.size() != frame.header.ciphertext_len) return make_error(ErrorCode::invalid_format, "ciphertext length mismatch");
  if (frame.tag.size() != frame.header.tag_len) return make_error(ErrorCode::invalid_format, "tag length mismatch");
  auto expected_nonce = sequence_nonce(nonce_for(material, frame.header.role), frame.header.sequence);
  if (!expected_nonce) return expected_nonce.error();
  if (!constant_time_equal(expected_nonce.value(), frame.nonce)) return make_error(ErrorCode::authentication_failed, "record nonce mismatch");
  auto aad = aad_for(frame.header, associated_data);
  if (!aad) return aad.error();
  aead::Ciphertext ct;
  ct.nonce = frame.nonce;
  ct.data = frame.ciphertext;
  ct.tag = frame.tag;
  return aead::decrypt(algorithm, key_for(material, frame.header.role), ct, aad.value());
}

Result<Frame> seal_alert(aead::Algorithm algorithm, const session::KeyMaterial& material, session::Role role,
                         std::uint64_t sequence, AlertCode code, ByteView associated_data) {
  const Bytes payload{static_cast<std::uint8_t>(code)};
  return seal(algorithm, material, role, ContentType::alert, sequence, payload, associated_data);
}

Result<AlertCode> open_alert(aead::Algorithm algorithm, const session::KeyMaterial& material, const Frame& frame, ByteView associated_data) {
  if (frame.header.type != ContentType::alert) return make_error(ErrorCode::invalid_format, "record is not an alert");
  auto plaintext = open(algorithm, material, frame, associated_data);
  if (!plaintext) return plaintext.error();
  if (plaintext.value().size() != 1) return make_error(ErrorCode::invalid_format, "alert payload must be one byte");
  return static_cast<AlertCode>(plaintext.value()[0]);
}

Result<Bytes> encode_frame(const Frame& frame) {
  auto header = encode_header(frame.header);
  if (!header) return header.error();
  if (frame.nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_format, "record nonce must be 12 bytes");
  if (frame.ciphertext.size() != frame.header.ciphertext_len) return make_error(ErrorCode::invalid_format, "ciphertext length mismatch");
  if (frame.tag.size() != frame.header.tag_len) return make_error(ErrorCode::invalid_format, "tag length mismatch");
  Bytes out;
  out.reserve(header.value().size() + frame.nonce.size() + frame.ciphertext.size() + frame.tag.size());
  out.insert(out.end(), header.value().begin(), header.value().end());
  out.insert(out.end(), frame.nonce.begin(), frame.nonce.end());
  out.insert(out.end(), frame.ciphertext.begin(), frame.ciphertext.end());
  out.insert(out.end(), frame.tag.begin(), frame.tag.end());
  return out;
}

Result<Frame> decode_frame(ByteView frame) {
  if (frame.size() < kRecordHeaderBytes + session::kSessionNonceBytes + 16) return make_error(ErrorCode::invalid_format, "record frame is too short");
  auto header = decode_header(frame.subspan(0, kRecordHeaderBytes));
  if (!header) return header.error();
  const std::size_t need = kRecordHeaderBytes + session::kSessionNonceBytes + header.value().ciphertext_len + header.value().tag_len;
  if (frame.size() != need) return make_error(ErrorCode::invalid_format, "record frame length mismatch");
  Frame out;
  out.header = header.value();
  std::size_t off = kRecordHeaderBytes;
  out.nonce.assign(frame.begin() + static_cast<std::ptrdiff_t>(off), frame.begin() + static_cast<std::ptrdiff_t>(off + session::kSessionNonceBytes));
  off += session::kSessionNonceBytes;
  out.ciphertext.assign(frame.begin() + static_cast<std::ptrdiff_t>(off), frame.begin() + static_cast<std::ptrdiff_t>(off + out.header.ciphertext_len));
  off += out.header.ciphertext_len;
  out.tag.assign(frame.begin() + static_cast<std::ptrdiff_t>(off), frame.begin() + static_cast<std::ptrdiff_t>(off + out.header.tag_len));
  return out;
}

const char* content_type_name(ContentType type) noexcept {
  switch (type) {
    case ContentType::data: return "data";
    case ContentType::handshake: return "handshake";
    case ContentType::alert: return "alert";
    case ContentType::key_update: return "key_update";
  }
  return "unknown";
}

const char* alert_name(AlertCode code) noexcept {
  switch (code) {
    case AlertCode::close_notify: return "close_notify";
    case AlertCode::unexpected_message: return "unexpected_message";
    case AlertCode::bad_record_mac: return "bad_record_mac";
    case AlertCode::protocol_error: return "protocol_error";
    case AlertCode::key_update_required: return "key_update_required";
  }
  return "unknown";
}

}  // namespace quantlib::record

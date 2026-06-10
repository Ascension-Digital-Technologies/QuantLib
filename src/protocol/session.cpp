#include "quantlib/session.hpp"
#include "quantlib/kdf.hpp"
#include "quantlib/secure.hpp"
#include "quantlib/transcript.hpp"
#include <string_view>

namespace quantlib::session {
namespace {
ByteView sv(std::string_view s) {
  return ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

Bytes u8(std::uint8_t value) { return Bytes{value}; }

Result<Bytes> expand(ByteView secret, std::string_view label, const Hello& hello, ByteView context, std::size_t output_len) {
  if (secret.empty()) return make_error(ErrorCode::invalid_argument, "session secret cannot be empty");
  if (output_len == 0) return make_error(ErrorCode::invalid_argument, "session output length cannot be zero");

  transcript::Transcript t(kKeyScheduleV1);
  if (!t.append("label", sv(label))) return make_error(ErrorCode::internal_error, "failed to append label");
  if (!t.append("client-nonce", hello.client_nonce)) return make_error(ErrorCode::internal_error, "failed to append client nonce");
  if (!t.append("server-nonce", hello.server_nonce)) return make_error(ErrorCode::internal_error, "failed to append server nonce");
  if (!t.append("transcript", hello.transcript_hash)) return make_error(ErrorCode::internal_error, "failed to append transcript hash");
  if (!t.append("context", context)) return make_error(ErrorCode::internal_error, "failed to append context");
  const Bytes info = t.digest();
  return kdf::hkdf_sha256(secret, hello.transcript_hash, info, output_len);
}
}  // namespace

Result<Hello> make_hello(ByteView client_nonce, ByteView server_nonce, ByteView transcript_hash) {
  if (client_nonce.size() != kSessionNonceBytes) {
    return make_error(ErrorCode::invalid_argument, "client nonce must be 12 bytes");
  }
  if (server_nonce.size() != kSessionNonceBytes) {
    return make_error(ErrorCode::invalid_argument, "server nonce must be 12 bytes");
  }
  if (transcript_hash.size() != 32) {
    return make_error(ErrorCode::invalid_argument, "transcript hash must be 32 bytes");
  }
  Hello hello;
  hello.client_nonce.assign(client_nonce.begin(), client_nonce.end());
  hello.server_nonce.assign(server_nonce.begin(), server_nonce.end());
  hello.transcript_hash.assign(transcript_hash.begin(), transcript_hash.end());
  return hello;
}

Result<Bytes> derive_handshake_secret(ByteView shared_secret, const Hello& hello) {
  if (shared_secret.empty()) return make_error(ErrorCode::invalid_argument, "shared secret cannot be empty");
  transcript::Transcript t(kSessionV1);
  if (!t.append("client-nonce", hello.client_nonce)) return make_error(ErrorCode::internal_error, "failed to append client nonce");
  if (!t.append("server-nonce", hello.server_nonce)) return make_error(ErrorCode::internal_error, "failed to append server nonce");
  if (!t.append("transcript", hello.transcript_hash)) return make_error(ErrorCode::internal_error, "failed to append transcript hash");
  const Bytes info = t.digest();
  return kdf::hkdf_sha256(shared_secret, hello.transcript_hash, info, kSessionKeyBytes);
}

Result<KeyMaterial> derive_keys(ByteView handshake_secret, const Hello& hello) {
  if (handshake_secret.empty()) return make_error(ErrorCode::invalid_argument, "handshake secret cannot be empty");
  KeyMaterial material;
  auto ck = expand(handshake_secret, "client write key", hello, {}, kSessionKeyBytes);
  auto sk = expand(handshake_secret, "server write key", hello, {}, kSessionKeyBytes);
  auto cn = expand(handshake_secret, "client write nonce", hello, {}, kSessionNonceBytes);
  auto sn = expand(handshake_secret, "server write nonce", hello, {}, kSessionNonceBytes);
  auto ex = expand(handshake_secret, "exporter secret", hello, {}, kSessionKeyBytes);
  if (!ck) return ck.error();
  if (!sk) return sk.error();
  if (!cn) return cn.error();
  if (!sn) return sn.error();
  if (!ex) return ex.error();
  material.client_write_key = std::move(ck.value());
  material.server_write_key = std::move(sk.value());
  material.client_write_nonce = std::move(cn.value());
  material.server_write_nonce = std::move(sn.value());
  material.exporter_secret = std::move(ex.value());
  return material;
}

Result<Bytes> confirmation_tag(Role role, ByteView handshake_secret, const Hello& hello, ByteView context) {
  const auto role_byte = u8(role == Role::client ? 0x01 : 0x02);
  transcript::Transcript t(kSessionV1);
  if (!t.append("confirmation-role", role_byte)) return make_error(ErrorCode::internal_error, "failed to append role");
  if (!t.append("context", context)) return make_error(ErrorCode::internal_error, "failed to append context");
  const Bytes confirm_context = t.digest();
  return expand(handshake_secret, role == Role::client ? "client confirmation" : "server confirmation", hello, confirm_context, kConfirmationBytes);
}

Result<void> verify_confirmation(Role role, ByteView expected_tag, ByteView handshake_secret, const Hello& hello, ByteView context) {
  auto actual = confirmation_tag(role, handshake_secret, hello, context);
  if (!actual) return actual.error();
  if (!constant_time_equal(expected_tag, actual.value())) {
    return make_error(ErrorCode::authentication_failed, "session confirmation tag mismatch");
  }
  return {};
}

Result<Bytes> export_secret(ByteView exporter_secret, std::string label, ByteView context, std::size_t output_len) {
  if (exporter_secret.empty()) return make_error(ErrorCode::invalid_argument, "exporter secret cannot be empty");
  if (label.empty()) return make_error(ErrorCode::invalid_argument, "export label cannot be empty");
  if (output_len == 0) return make_error(ErrorCode::invalid_argument, "export length cannot be zero");
  transcript::Transcript t(kSessionV1);
  if (!t.append("export-label", sv(label))) return make_error(ErrorCode::internal_error, "failed to append label");
  if (!t.append("export-context", context)) return make_error(ErrorCode::internal_error, "failed to append context");
  const Bytes info = t.digest();
  return kdf::hkdf_sha256(exporter_secret, {}, info, output_len);
}


Result<KeyMaterial> update_keys(const KeyMaterial& current, const Hello& hello, std::uint64_t generation, ByteView context) {
  if (generation == 0) return make_error(ErrorCode::invalid_argument, "key update generation must be non-zero");
  if (current.exporter_secret.size() != kSessionKeyBytes) return make_error(ErrorCode::invalid_argument, "current exporter secret must be 32 bytes");
  transcript::Transcript t(kKeyUpdateV1);
  Bytes gen;
  for (int shift = 56; shift >= 0; shift -= 8) gen.push_back(static_cast<std::uint8_t>((generation >> shift) & 0xff));
  if (!t.append("generation", gen)) return make_error(ErrorCode::internal_error, "failed to append generation");
  if (!t.append("context", context)) return make_error(ErrorCode::internal_error, "failed to append key update context");
  const Bytes update_context = t.digest();
  auto new_secret = expand(current.exporter_secret, "key update secret", hello, update_context, kSessionKeyBytes);
  if (!new_secret) return new_secret.error();
  return derive_keys(new_secret.value(), hello);
}

Result<Bytes> key_update_tag(const KeyMaterial& current, const Hello& hello, std::uint64_t generation, ByteView context) {
  if (generation == 0) return make_error(ErrorCode::invalid_argument, "key update generation must be non-zero");
  transcript::Transcript t(kKeyUpdateV1);
  Bytes gen;
  for (int shift = 56; shift >= 0; shift -= 8) gen.push_back(static_cast<std::uint8_t>((generation >> shift) & 0xff));
  if (!t.append("generation", gen)) return make_error(ErrorCode::internal_error, "failed to append generation");
  if (!t.append("client-write-key", current.client_write_key)) return make_error(ErrorCode::internal_error, "failed to append client key");
  if (!t.append("server-write-key", current.server_write_key)) return make_error(ErrorCode::internal_error, "failed to append server key");
  if (!t.append("context", context)) return make_error(ErrorCode::internal_error, "failed to append context");
  const Bytes tag_context = t.digest();
  return expand(current.exporter_secret, "key update confirmation", hello, tag_context, kConfirmationBytes);
}

}  // namespace quantlib::session

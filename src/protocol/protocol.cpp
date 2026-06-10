#include "quantlib/protocol.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/transcript.hpp"
#include <algorithm>
#include <limits>

namespace quantlib::protocol {
namespace {
void put_u16(Bytes& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<std::uint8_t>(value & 0xff));
}
void put_u32(Bytes& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<std::uint8_t>(value & 0xff));
}
void put_u64(Bytes& out, std::uint64_t value) {
  for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<std::uint8_t>((value >> s) & 0xff));
}
bool contains(const std::vector<std::uint16_t>& ids, std::uint16_t id) {
  return std::find(ids.begin(), ids.end(), id) != ids.end();
}
int best_level(const std::vector<std::uint16_t>& offered, const std::vector<CipherSuite>& supported) {
  int level = 0;
  for (auto id : offered) {
    if (auto* s = find_suite(id, supported)) level = std::max(level, s->security_level);
  }
  return level;
}
Result<void> validate_suite(const CipherSuite& suite, const policy::AlgorithmPolicy& p) {
  auto kem_ok = policy::validate_kem(suite.kem_algorithm, p);
  if (!kem_ok) return kem_ok.error();
  auto sig_ok = policy::validate_signature(suite.signature_algorithm, p);
  if (!sig_ok) return sig_ok.error();
  auto aead_ok = policy::validate_aead(suite.aead_algorithm, p);
  if (!aead_ok) return aead_ok.error();
  if (suite.security_level < p.minimum_security_level) return make_error(ErrorCode::invalid_argument, "cipher suite below policy security level");
  return {};
}
}  // namespace

std::vector<CipherSuite> default_cipher_suites() {
  return {
    CipherSuite{0x0103, "QUANTLIBLINK_X25519_MLKEM768_ED25519_MLDSA65_CHACHA20_SHA256", kem::Algorithm::hybrid_x25519_ml_kem_768, sign::Algorithm::hybrid_ed25519_ml_dsa_65, aead::Algorithm::chacha20_poly1305, 3, true, true},
    CipherSuite{0x0102, "QUANTLIBLINK_X25519_ED25519_AES256GCM_SHA256", kem::Algorithm::x25519, sign::Algorithm::ed25519, aead::Algorithm::aes_256_gcm, 3, false, false},
    CipherSuite{0x0101, "QUANTLIBLINK_X25519_ED25519_CHACHA20_SHA256", kem::Algorithm::x25519, sign::Algorithm::ed25519, aead::Algorithm::chacha20_poly1305, 3, false, false},
  };
}

const CipherSuite* find_suite(std::uint16_t id, const std::vector<CipherSuite>& suites) noexcept {
  for (const auto& suite : suites) if (suite.id == id) return &suite;
  return nullptr;
}

Result<NegotiatedProtocol> negotiate(const NegotiationInput& local, const std::vector<std::uint16_t>& peer_offered_suite_ids) {
  const auto supported = local.offered_suites.empty() ? default_cipher_suites() : local.offered_suites;
  for (const auto& suite : supported) {
    if (!contains(peer_offered_suite_ids, suite.id)) continue;
    auto valid = validate_suite(suite, local.policy);
    if (!valid) continue;
    auto dg = reject_downgrade(peer_offered_suite_ids, suite);
    if (!dg) return dg.error();
    NegotiatedProtocol out;
    out.suite = suite;
    out.limits = local.limits;
    transcript::Transcript t(kQuantLinkV1);
    Bytes suite_id;
    put_u16(suite_id, suite.id);
    if (!t.append("suite", suite_id)) return make_error(ErrorCode::internal_error, "failed to bind suite");
    Bytes lim;
    put_u32(lim, out.limits.max_record_plaintext);
    put_u32(lim, out.limits.max_frame_bytes);
    put_u64(lim, out.limits.rekey_after_records);
    put_u64(lim, out.limits.rekey_after_seconds);
    lim.push_back(out.limits.require_close_notify ? 1 : 0);
    if (!t.append("limits", lim)) return make_error(ErrorCode::internal_error, "failed to bind limits");
    out.transcript_hash = t.digest();
    return out;
  }
  return make_error(ErrorCode::unsupported_algorithm, "no mutually acceptable cipher suite");
}

Result<void> reject_downgrade(const std::vector<std::uint16_t>& offered_suite_ids, const CipherSuite& selected) {
  const auto supported = default_cipher_suites();
  const int highest = best_level(offered_suite_ids, supported);
  if (highest > selected.security_level) return make_error(ErrorCode::authentication_failed, "cipher suite downgrade rejected");
  const bool offered_hybrid = std::any_of(offered_suite_ids.begin(), offered_suite_ids.end(), [&](std::uint16_t id) {
    const auto* suite = find_suite(id, supported);
    return suite != nullptr && suite->hybrid;
  });
  if (offered_hybrid && !selected.hybrid) return make_error(ErrorCode::authentication_failed, "hybrid cipher suite downgrade rejected");
  return {};
}

Result<Bytes> encode_client_hello(const session::Hello& hello, const std::vector<CipherSuite>& suites, const HandshakeLimits& limits) {
  if (suites.size() > 255) return make_error(ErrorCode::invalid_argument, "too many cipher suites");
  if (hello.client_nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_argument, "hello nonce must be 12 bytes");
  Bytes out;
  out.push_back(kHandshakeVersion);
  out.push_back(0x01);
  out.insert(out.end(), hello.client_nonce.begin(), hello.client_nonce.end());
  out.push_back(static_cast<std::uint8_t>(suites.size()));
  for (const auto& suite : suites) put_u16(out, suite.id);
  put_u32(out, limits.max_record_plaintext);
  put_u32(out, limits.max_frame_bytes);
  put_u64(out, limits.rekey_after_records);
  put_u64(out, limits.rekey_after_seconds);
  out.push_back(limits.require_close_notify ? 1 : 0);
  return out;
}

Result<Bytes> encode_server_hello(const session::Hello& hello, const CipherSuite& selected, const HandshakeLimits& limits) {
  if (hello.server_nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_argument, "hello nonce must be 12 bytes");
  Bytes out;
  out.push_back(kHandshakeVersion);
  out.push_back(0x02);
  out.insert(out.end(), hello.server_nonce.begin(), hello.server_nonce.end());
  put_u16(out, selected.id);
  put_u32(out, limits.max_record_plaintext);
  put_u32(out, limits.max_frame_bytes);
  put_u64(out, limits.rekey_after_records);
  put_u64(out, limits.rekey_after_seconds);
  out.push_back(limits.require_close_notify ? 1 : 0);
  return out;
}

Result<void> absorb_handshake(HandshakeContext& ctx, ByteView message) {
  if (message.empty()) return make_error(ErrorCode::invalid_format, "empty handshake message");
  transcript::Transcript t(kQuantLinkV1);
  if (!ctx.transcript_hash.empty() && !t.append("previous", ctx.transcript_hash)) return make_error(ErrorCode::internal_error, "failed to bind previous transcript");
  if (!t.append("message", message)) return make_error(ErrorCode::internal_error, "failed to bind handshake message");
  ctx.transcript_hash = t.digest();
  return {};
}

Result<void> mark_sent(HandshakeContext& ctx, record::ContentType type) {
  if (ctx.state == HandshakeState::closed || ctx.state == HandshakeState::failed) return make_error(ErrorCode::invalid_argument, "handshake is not active");
  if (type == record::ContentType::alert) { ctx.state = HandshakeState::closed; return {}; }
  if (type != record::ContentType::handshake) return make_error(ErrorCode::invalid_argument, "expected handshake content type");
  if (ctx.role == session::Role::client && ctx.state == HandshakeState::start) { ctx.state = HandshakeState::client_hello_sent; return {}; }
  if (ctx.role == session::Role::server && ctx.state == HandshakeState::client_hello_received) { ctx.state = HandshakeState::server_hello_sent; return {}; }
  return make_error(ErrorCode::invalid_argument, "invalid handshake send transition");
}

Result<void> mark_received(HandshakeContext& ctx, record::ContentType type) {
  if (ctx.state == HandshakeState::closed || ctx.state == HandshakeState::failed) return make_error(ErrorCode::invalid_argument, "handshake is not active");
  if (type == record::ContentType::alert) { ctx.close_notify_seen = true; ctx.state = HandshakeState::closed; return {}; }
  if (type != record::ContentType::handshake) return make_error(ErrorCode::invalid_argument, "expected handshake content type");
  if (ctx.role == session::Role::server && ctx.state == HandshakeState::start) { ctx.state = HandshakeState::client_hello_received; return {}; }
  if (ctx.role == session::Role::client && ctx.state == HandshakeState::client_hello_sent) { ctx.state = HandshakeState::server_hello_received; return {}; }
  return make_error(ErrorCode::invalid_argument, "invalid handshake receive transition");
}

Result<void> validate_frame_limits(ByteView encoded_frame, const HandshakeLimits& limits) {
  if (limits.max_frame_bytes == 0) return make_error(ErrorCode::invalid_argument, "max frame bytes cannot be zero");
  if (encoded_frame.size() > limits.max_frame_bytes) return make_error(ErrorCode::invalid_argument, "frame exceeds negotiated limit");
  if (encoded_frame.size() < record::kRecordHeaderBytes + session::kSessionNonceBytes + 16) return make_error(ErrorCode::invalid_format, "frame too small");
  return {};
}

Result<void> validate_plaintext_limits(ByteView plaintext, const HandshakeLimits& limits) {
  if (limits.max_record_plaintext == 0) return make_error(ErrorCode::invalid_argument, "max plaintext cannot be zero");
  if (plaintext.size() > limits.max_record_plaintext) return make_error(ErrorCode::invalid_argument, "plaintext exceeds negotiated limit");
  return {};
}

Result<void> validate_close_notify_required(const HandshakeContext& ctx) {
  if (ctx.negotiated.limits.require_close_notify && !ctx.close_notify_seen) return make_error(ErrorCode::invalid_argument, "close_notify was required but not received");
  return {};
}

const char* state_name(HandshakeState state) noexcept {
  switch (state) {
    case HandshakeState::start: return "start";
    case HandshakeState::client_hello_sent: return "client_hello_sent";
    case HandshakeState::client_hello_received: return "client_hello_received";
    case HandshakeState::server_hello_sent: return "server_hello_sent";
    case HandshakeState::server_hello_received: return "server_hello_received";
    case HandshakeState::established: return "established";
    case HandshakeState::closed: return "closed";
    case HandshakeState::failed: return "failed";
  }
  return "unknown";
}

std::string describe_suite(const CipherSuite& suite) {
  return suite.name + " id=0x" + hex_encode(Bytes{static_cast<std::uint8_t>(suite.id >> 8), static_cast<std::uint8_t>(suite.id & 0xff)}) +
         " level=" + std::to_string(suite.security_level) + (suite.hybrid ? " hybrid" : " classical");
}

}  // namespace quantlib::protocol

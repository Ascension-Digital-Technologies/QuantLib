#include "quantlib/audit.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/key.hpp"
#include "quantlib/secure.hpp"
#include <array>

namespace quantlib::audit {
namespace {
constexpr std::array<std::uint8_t, 7> kMagic = {'A','A','U','D','I','T','1'};

void put_u16(Bytes& out, std::uint16_t v) { out.push_back(static_cast<std::uint8_t>(v >> 8)); out.push_back(static_cast<std::uint8_t>(v)); }
void put_u32(Bytes& out, std::uint32_t v) { for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8))); }
void put_u64(Bytes& out, std::uint64_t v) { for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8))); }
void put_bytes(Bytes& out, ByteView v) { put_u32(out, static_cast<std::uint32_t>(v.size())); out.insert(out.end(), v.begin(), v.end()); }
void put_string(Bytes& out, const std::string& s) { put_u32(out, static_cast<std::uint32_t>(s.size())); out.insert(out.end(), s.begin(), s.end()); }

bool take_u16(ByteView in, std::size_t& o, std::uint16_t& v) { if (o + 2 > in.size()) return false; v = (static_cast<std::uint16_t>(in[o]) << 8) | in[o + 1]; o += 2; return true; }
bool take_u32(ByteView in, std::size_t& o, std::uint32_t& v) { if (o + 4 > in.size()) return false; v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | in[o++]; return true; }
bool take_u64(ByteView in, std::size_t& o, std::uint64_t& v) { if (o + 8 > in.size()) return false; v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | in[o++]; return true; }
bool take_bytes(ByteView in, std::size_t& o, Bytes& v) { std::uint32_t len = 0; if (!take_u32(in, o, len) || o + len > in.size()) return false; v.assign(in.begin() + static_cast<std::ptrdiff_t>(o), in.begin() + static_cast<std::ptrdiff_t>(o + len)); o += len; return true; }
bool take_string(ByteView in, std::size_t& o, std::string& v) { Bytes raw; if (!take_bytes(in, o, raw)) return false; v.assign(raw.begin(), raw.end()); return true; }

Bytes hash_material(const AuditEvent& e, bool include_hash) {
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, e.version);
  put_u64(out, e.sequence);
  put_u64(out, e.timestamp);
  put_u16(out, static_cast<std::uint16_t>(e.type));
  put_string(out, e.subject);
  put_string(out, e.detail);
  put_bytes(out, e.previous_hash);
  if (include_hash) put_bytes(out, e.event_hash);
  return out;
}
}  // namespace

const char* event_type_name(EventType type) noexcept {
  switch (type) {
    case EventType::vault_created: return "vault_created";
    case EventType::vault_unlocked: return "vault_unlocked";
    case EventType::key_generated: return "key_generated";
    case EventType::key_used_sign: return "key_used_sign";
    case EventType::key_used_decapsulate: return "key_used_decapsulate";
    case EventType::key_erased: return "key_erased";
    case EventType::policy_changed: return "policy_changed";
    case EventType::failed_unlock: return "failed_unlock";
    case EventType::tamper_rejected: return "tamper_rejected";
    case EventType::vault_saved: return "vault_saved";
    case EventType::vault_loaded: return "vault_loaded";
    case EventType::session_opened: return "session_opened";
    case EventType::session_closed: return "session_closed";
    case EventType::session_expired: return "session_expired";
    case EventType::session_denied: return "session_denied";
    case EventType::session_permission_denied: return "session_permission_denied";
    case EventType::session_operation_limit_hit: return "session_operation_limit_hit";
    case EventType::key_rotated: return "key_rotated";
    case EventType::key_retired: return "key_retired";
    case EventType::key_marked_compromised: return "key_marked_compromised";
  }
  return "unknown";
}

Bytes genesis_hash() { return hash::sha256(Bytes{'A','e','g','i','s','C','r','y','p','t',' ','A','u','d','i','t',' ','G','e','n','e','s','i','s',' ','v','1'}); }

Bytes event_hash(const AuditEvent& event) { return hash::sha256(hash_material(event, false)); }

Result<AuditEvent> make_event(const AuditLog& log, EventType type, std::string subject, std::string detail) {
  auto verified = verify(log);
  if (!verified) return verified.error();
  AuditEvent e{};
  e.sequence = static_cast<std::uint64_t>(log.events.size());
  e.timestamp = key::unix_time_now();
  e.type = type;
  e.subject = std::move(subject);
  e.detail = std::move(detail);
  e.previous_hash = head_hash(log);
  e.event_hash = event_hash(e);
  return e;
}

Result<void> append(AuditLog& log, EventType type, std::string subject, std::string detail) {
  auto e = make_event(log, type, std::move(subject), std::move(detail));
  if (!e) return e.error();
  log.events.push_back(std::move(e).value());
  return {};
}

Bytes head_hash(const AuditLog& log) { return log.events.empty() ? genesis_hash() : log.events.back().event_hash; }

Result<void> verify(const AuditLog& log) {
  Bytes prev = genesis_hash();
  for (std::size_t i = 0; i < log.events.size(); ++i) {
    const auto& e = log.events[i];
    if (e.version != kAuditVersion) return make_error(ErrorCode::invalid_format, "unsupported audit event version");
    if (e.sequence != i) return make_error(ErrorCode::invalid_format, "audit sequence mismatch");
    if (e.previous_hash.size() != kAuditHashBytes || e.event_hash.size() != kAuditHashBytes) return make_error(ErrorCode::invalid_format, "audit hash length mismatch");
    if (!constant_time_equal(e.previous_hash, prev)) return make_error(ErrorCode::invalid_format, "audit previous hash mismatch");
    const auto expected = event_hash(e);
    if (!constant_time_equal(e.event_hash, expected)) return make_error(ErrorCode::invalid_format, "audit event hash mismatch");
    prev = e.event_hash;
  }
  return {};
}

Result<Bytes> encode_event(const AuditEvent& event) {
  if (event.version != kAuditVersion || event.previous_hash.size() != kAuditHashBytes || event.event_hash.size() != kAuditHashBytes) return make_error(ErrorCode::invalid_argument, "audit event is incomplete");
  if (!constant_time_equal(event.event_hash, event_hash(event))) return make_error(ErrorCode::invalid_argument, "audit event hash is invalid");
  return hash_material(event, true);
}

Result<AuditEvent> decode_event(ByteView encoded) {
  if (encoded.size() < kMagic.size() + 2) return make_error(ErrorCode::invalid_format, "audit event too short");
  for (std::size_t i = 0; i < kMagic.size(); ++i) if (encoded[i] != kMagic[i]) return make_error(ErrorCode::invalid_format, "invalid audit event magic");
  std::size_t o = kMagic.size();
  AuditEvent e{};
  std::uint16_t type = 0;
  if (!take_u16(encoded, o, e.version) || !take_u64(encoded, o, e.sequence) || !take_u64(encoded, o, e.timestamp) || !take_u16(encoded, o, type) ||
      !take_string(encoded, o, e.subject) || !take_string(encoded, o, e.detail) || !take_bytes(encoded, o, e.previous_hash) || !take_bytes(encoded, o, e.event_hash) || o != encoded.size()) {
    return make_error(ErrorCode::invalid_format, "truncated audit event");
  }
  e.type = static_cast<EventType>(type);
  if (e.version != kAuditVersion || e.previous_hash.size() != kAuditHashBytes || e.event_hash.size() != kAuditHashBytes) return make_error(ErrorCode::invalid_format, "invalid audit event fields");
  const auto expected = event_hash(e);
  if (!constant_time_equal(e.event_hash, expected)) return make_error(ErrorCode::invalid_format, "audit event hash mismatch");
  return e;
}

Result<Bytes> encode_log(const AuditLog& log) {
  auto verified = verify(log);
  if (!verified) return verified.error();
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, kAuditVersion);
  put_u32(out, static_cast<std::uint32_t>(log.events.size()));
  for (const auto& e : log.events) {
    auto raw = encode_event(e);
    if (!raw) return raw.error();
    put_bytes(out, raw.value());
  }
  return out;
}

Result<AuditLog> decode_log(ByteView encoded) {
  if (encoded.size() < kMagic.size() + 6) return make_error(ErrorCode::invalid_format, "audit log too short");
  for (std::size_t i = 0; i < kMagic.size(); ++i) if (encoded[i] != kMagic[i]) return make_error(ErrorCode::invalid_format, "invalid audit log magic");
  std::size_t o = kMagic.size();
  std::uint16_t version = 0;
  std::uint32_t count = 0;
  if (!take_u16(encoded, o, version) || version != kAuditVersion || !take_u32(encoded, o, count)) return make_error(ErrorCode::invalid_format, "invalid audit log header");
  if (count > encoded.size()) return make_error(ErrorCode::invalid_format, "audit log event count is invalid");
  AuditLog log;
  log.events.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) {
    Bytes raw;
    if (!take_bytes(encoded, o, raw)) return make_error(ErrorCode::invalid_format, "truncated audit log");
    auto e = decode_event(raw);
    if (!e) return e.error();
    log.events.push_back(std::move(e).value());
  }
  if (o != encoded.size()) return make_error(ErrorCode::invalid_format, "trailing audit log data");
  auto verified = verify(log);
  if (!verified) return verified.error();
  return log;
}

}  // namespace quantlib::audit

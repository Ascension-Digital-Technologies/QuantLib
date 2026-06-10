#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::audit {

inline constexpr std::uint16_t kAuditVersion = 1;
inline constexpr std::size_t kAuditHashBytes = 32;

enum class EventType : std::uint16_t {
  vault_created = 1,
  vault_unlocked = 2,
  key_generated = 3,
  key_used_sign = 4,
  key_used_decapsulate = 5,
  key_erased = 6,
  policy_changed = 7,
  failed_unlock = 8,
  tamper_rejected = 9,
  vault_saved = 10,
  vault_loaded = 11,
  session_opened = 12,
  session_closed = 13,
  session_expired = 14,
  session_denied = 15,
  session_permission_denied = 16,
  session_operation_limit_hit = 17,
  key_rotated = 18,
  key_retired = 19,
  key_marked_compromised = 20
};

struct AuditEvent {
  std::uint16_t version{kAuditVersion};
  std::uint64_t sequence{0};
  std::uint64_t timestamp{0};
  EventType type{EventType::vault_created};
  std::string subject{};
  std::string detail{};
  Bytes previous_hash{};
  Bytes event_hash{};
};

struct AuditLog {
  std::vector<AuditEvent> events{};
};

[[nodiscard]] const char* event_type_name(EventType type) noexcept;
[[nodiscard]] Bytes genesis_hash();
[[nodiscard]] Bytes event_hash(const AuditEvent& event);
[[nodiscard]] Result<AuditEvent> make_event(const AuditLog& log, EventType type, std::string subject, std::string detail = {});
[[nodiscard]] Result<void> append(AuditLog& log, EventType type, std::string subject, std::string detail = {});
[[nodiscard]] Result<void> verify(const AuditLog& log);
[[nodiscard]] Bytes head_hash(const AuditLog& log);
[[nodiscard]] Result<Bytes> encode_event(const AuditEvent& event);
[[nodiscard]] Result<AuditEvent> decode_event(ByteView encoded);
[[nodiscard]] Result<Bytes> encode_log(const AuditLog& log);
[[nodiscard]] Result<AuditLog> decode_log(ByteView encoded);

}  // namespace quantlib::audit

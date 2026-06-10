#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/bytes.hpp"
#include "quantlib/kem.hpp"
#include "quantlib/result.hpp"
#include "quantlib/sign.hpp"
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace quantlib::ssm {

inline constexpr std::size_t kMasterKeyBytes = 32;
inline constexpr std::uint16_t kSsmVersion = 3;

using Handle = std::string;

enum class ObjectType : std::uint16_t {
  symmetric = 1,
  sign = 2,
  kem = 3
};

enum class ObjectFlag : std::uint32_t {
  none = 0,
  exportable_public = 1u << 0,
  exportable_sealed = 1u << 1,
  allow_sign = 1u << 2,
  allow_decapsulate = 1u << 3,
  allow_unseal = 1u << 4
};

enum class KeyState : std::uint16_t {
  active = 1,
  locked = 2,
  disabled = 3,
  expired = 4,
  destroyed = 5,
  compromised = 6,
  retired = 7
};

enum class Operation : std::uint16_t {
  sign = 1,
  decapsulate = 2,
  public_export = 3,
  sealed_export = 4
};

enum class SessionPermission : std::uint32_t {
  none = 0,
  sign = 1u << 0,
  decapsulate = 1u << 1,
  export_public = 1u << 2,
  generate_key = 1u << 3,
  change_policy = 1u << 4,
  erase_key = 1u << 5,
  export_sealed = 1u << 6,
  import_sealed = 1u << 7,
  admin = 0xffff'ffffu
};

struct SessionOptions {
  std::uint64_t ttl_seconds{300};
  std::uint32_t permissions{static_cast<std::uint32_t>(SessionPermission::sign) |
                            static_cast<std::uint32_t>(SessionPermission::decapsulate) |
                            static_cast<std::uint32_t>(SessionPermission::export_public)};
  std::vector<Handle> allowed_handles{};
  std::vector<std::string> allowed_domains{};
  std::uint64_t max_sign_operations{0};
  std::uint64_t max_decapsulate_operations{0};
};

struct SessionToken {
  std::string value{};
};

struct SessionInfo {
  std::string token_hash{};
  std::uint64_t created_at{0};
  std::uint64_t expires_at{0};
  std::uint32_t permissions{0};
  std::uint64_t sign_operations{0};
  std::uint64_t decapsulate_operations{0};
  std::uint64_t max_sign_operations{0};
  std::uint64_t max_decapsulate_operations{0};
  bool closed{false};
};


struct MasterKey {
  Bytes bytes{};
};

struct CreateOptions {
  std::string label{};
  std::uint32_t flags{static_cast<std::uint32_t>(ObjectFlag::exportable_public) |
                      static_cast<std::uint32_t>(ObjectFlag::exportable_sealed)};
  std::string allowed_domain{};
  std::uint64_t max_operations{0};
};

struct RotationLink {
  Handle original_handle{};
  Handle replacement_handle{};
  std::uint64_t generation{0};
  std::uint64_t rotated_at{0};
  std::string reason{};
};


struct ObjectInfo {
  Handle handle{};
  ObjectType type{ObjectType::symmetric};
  std::uint16_t algorithm{0};
  std::uint32_t flags{0};
  std::uint64_t created_at{0};
  std::string label{};
  Bytes key_id{};
  Bytes public_key{};
  KeyState state{KeyState::active};
  std::string allowed_domain{};
  std::uint64_t max_operations{0};
  std::uint64_t used_operations{0};
  std::uint64_t last_used_at{0};
  RotationLink rotation{};
};

struct RotationResult {
  Handle old_handle{};
  Handle new_handle{};
  ObjectInfo old_info{};
  ObjectInfo new_info{};
};

struct SealedObject {
  ObjectInfo info{};
  Bytes nonce{};
  Bytes ciphertext{};
  Bytes tag{};
};

struct RotateOptions {
  std::string label{};
  std::string reason{"scheduled_rotation"};
  bool retire_old{true};
  bool preserve_policy{true};
};

[[nodiscard]] Result<MasterKey> generate_master_key();
[[nodiscard]] Result<MasterKey> import_master_key(ByteView raw);
[[nodiscard]] Result<Bytes> encode_sealed(const SealedObject& object);
[[nodiscard]] Result<SealedObject> decode_sealed(ByteView encoded);
[[nodiscard]] const char* object_type_name(ObjectType type) noexcept;
[[nodiscard]] const char* key_state_name(KeyState state) noexcept;

class SoftwareSecurityModule {
 public:
  explicit SoftwareSecurityModule(MasterKey master_key);
  ~SoftwareSecurityModule();

  SoftwareSecurityModule(const SoftwareSecurityModule&) = delete;
  SoftwareSecurityModule& operator=(const SoftwareSecurityModule&) = delete;
  SoftwareSecurityModule(SoftwareSecurityModule&&) = delete;
  SoftwareSecurityModule& operator=(SoftwareSecurityModule&&) = delete;

  [[nodiscard]] Result<Handle> generate_sign_key(sign::Algorithm algorithm, const CreateOptions& options = {});
  [[nodiscard]] Result<Handle> generate_kem_key(kem::Algorithm algorithm, const CreateOptions& options = {});
  [[nodiscard]] Result<Handle> generate_symmetric_key(std::size_t key_bytes, const CreateOptions& options = {});

  [[nodiscard]] Result<sign::Signature> sign_message(const Handle& handle, ByteView message) const;
  [[nodiscard]] Result<sign::Signature> sign_domain(const Handle& handle, const std::string& domain, ByteView message) const;
  [[nodiscard]] Result<Bytes> decapsulate(const Handle& handle, ByteView ciphertext) const;

  [[nodiscard]] Result<ObjectInfo> info(const Handle& handle) const;
  [[nodiscard]] Result<Bytes> public_key(const Handle& handle) const;
  [[nodiscard]] Result<SealedObject> export_sealed(const Handle& handle) const;
  [[nodiscard]] Result<Handle> import_sealed(const SealedObject& object);

  [[nodiscard]] std::vector<ObjectInfo> list() const;
  [[nodiscard]] bool contains(const Handle& handle) const;
  [[nodiscard]] Result<void> set_state(const Handle& handle, KeyState state);
  [[nodiscard]] Result<RotationResult> rotate_key(const Handle& handle, const RotateOptions& options = {});
  [[nodiscard]] Result<void> erase(const Handle& handle);
  void clear();

 private:
  struct Entry {
    ObjectInfo info{};
    Bytes nonce{};
    Bytes ciphertext{};
    Bytes tag{};
  };

  [[nodiscard]] Result<Handle> store_secret(ObjectInfo info, ByteView secret);
  [[nodiscard]] Result<Bytes> open_secret(const Entry& entry) const;
  [[nodiscard]] Result<Bytes> seal_secret(const ObjectInfo& info, ByteView secret, Bytes& nonce, Bytes& tag) const;
  [[nodiscard]] Result<void> validate_operation(const Entry& entry, Operation operation, const std::string& domain) const;
  void record_operation(const Handle& handle) const;
  [[nodiscard]] Bytes associated_data(const ObjectInfo& info) const;

  mutable std::mutex mutex_{};
  MasterKey master_{};
  mutable std::unordered_map<Handle, Entry> entries_{};
};


class SsmSessionManager {
 public:
  explicit SsmSessionManager(SoftwareSecurityModule& ssm);

  [[nodiscard]] Result<SessionToken> open_session(const SessionOptions& options = {});
  [[nodiscard]] Result<void> close_session(const SessionToken& token);
  [[nodiscard]] Result<SessionInfo> session_info(const SessionToken& token) const;
  [[nodiscard]] std::vector<SessionInfo> list_sessions() const;

  [[nodiscard]] Result<sign::Signature> sign_domain(const SessionToken& token, const Handle& handle, const std::string& domain, ByteView message);
  [[nodiscard]] Result<Bytes> decapsulate(const SessionToken& token, const Handle& handle, ByteView ciphertext);
  [[nodiscard]] Result<Bytes> public_key(const SessionToken& token, const Handle& handle);

 private:
  struct SessionEntry {
    SessionInfo info{};
    std::vector<Handle> allowed_handles{};
    std::vector<std::string> allowed_domains{};
  };

  [[nodiscard]] Result<SessionEntry*> mutable_session(const SessionToken& token, SessionPermission permission, const Handle& handle, const std::string& domain);
  [[nodiscard]] Result<const SessionEntry*> readonly_session(const SessionToken& token, SessionPermission permission, const Handle& handle, const std::string& domain) const;
  [[nodiscard]] bool allowed_handle(const SessionEntry& entry, const Handle& handle) const;
  [[nodiscard]] bool allowed_domain(const SessionEntry& entry, const std::string& domain) const;

  SoftwareSecurityModule& ssm_;
  mutable std::mutex mutex_{};
  std::unordered_map<std::string, SessionEntry> sessions_{};
};

[[nodiscard]] bool has_session_permission(std::uint32_t permissions, SessionPermission permission) noexcept;
[[nodiscard]] const char* session_permission_name(SessionPermission permission) noexcept;

[[nodiscard]] Result<bool> verify_domain_signature(const sign::PublicKey& public_key, const Handle& handle, const std::string& domain, ByteView message, const sign::Signature& signature);

}  // namespace quantlib::ssm

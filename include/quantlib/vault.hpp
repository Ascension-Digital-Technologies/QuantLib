#pragma once
#include "quantlib/audit.hpp"
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include "quantlib/ssm.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace quantlib::vault {

inline constexpr std::uint16_t kVaultVersion = 5;
inline constexpr std::uint32_t kDefaultKdfIterations = 210000;
inline constexpr std::uint32_t kMinimumKdfIterations = 10000;
inline constexpr std::uint32_t kRecommendedKdfIterations = 600000;
inline constexpr std::size_t kVaultSaltBytes = 16;
inline constexpr std::size_t kVaultWrapNonceBytes = 12;
inline constexpr std::size_t kVaultMasterKeyBytes = ssm::kMasterKeyBytes;

enum class VaultKdf {
  pbkdf2_hmac_sha256,
  argon2id,
  scrypt
};

struct VaultKdfInfo {
  VaultKdf algorithm{VaultKdf::pbkdf2_hmac_sha256};
  std::string name{};
  bool available{false};
  bool memory_hard{false};
  std::uint32_t iterations{kDefaultKdfIterations};
  std::uint32_t memory_kib{0};
  std::uint32_t parallelism{1};
  std::string notes{};
};

struct VaultKdfParams {
  VaultKdf algorithm{VaultKdf::pbkdf2_hmac_sha256};
  std::uint32_t iterations{kDefaultKdfIterations};
  std::uint32_t memory_kib{0};
  std::uint32_t parallelism{1};
};

struct VaultOptions {
  std::string label{"default"};
  std::uint32_t kdf_iterations{kDefaultKdfIterations};
  VaultKdfParams kdf{};
};

struct VaultMetadata {
  std::string vault_id{};
  std::string label{};
  std::string kdf{"pbkdf2-hmac-sha256"};
  std::uint32_t kdf_iterations{kDefaultKdfIterations};
  std::uint32_t kdf_memory_kib{0};
  std::uint32_t kdf_parallelism{1};
  std::uint64_t created_at{0};
  std::uint64_t updated_at{0};
  std::uint64_t generation{0};
  std::string previous_audit_head{};
};

struct VaultFile {
  VaultMetadata metadata{};
  Bytes salt{};
  Bytes wrap_nonce{};
  Bytes wrapped_master_key{};
  Bytes wrap_tag{};
  std::vector<Bytes> sealed_objects{};
  Bytes audit_log{};
  Bytes audit_head{};
};

struct UnlockedVault {
  VaultMetadata metadata{};
  ssm::MasterKey master_key{};
  std::vector<ssm::SealedObject> objects{};
  audit::AuditLog audit_log{};
};

struct VaultAnchor {
  std::string vault_id{};
  std::uint64_t generation{0};
  Bytes audit_head{};
};

struct VaultRecoveryReport {
  bool primary_present{false};
  bool backup_present{false};
  bool primary_decodable{false};
  bool backup_decodable{false};
  std::string selected{};
  std::string detail{};
};

[[nodiscard]] Result<UnlockedVault> create_vault(std::string_view passphrase, const VaultOptions& options = {});
[[nodiscard]] Result<Bytes> encode_vault(const UnlockedVault& vault, std::string_view passphrase);
[[nodiscard]] Result<UnlockedVault> decode_vault(ByteView encoded, std::string_view passphrase);
[[nodiscard]] Result<void> save_vault_atomic(const std::string& path, const UnlockedVault& vault, std::string_view passphrase);
[[nodiscard]] Result<UnlockedVault> load_vault(const std::string& path, std::string_view passphrase, VaultRecoveryReport* report = nullptr);
[[nodiscard]] Result<VaultFile> decode_vault_file(ByteView encoded);
[[nodiscard]] Result<Bytes> encode_vault_file(const VaultFile& file);
[[nodiscard]] Result<std::unique_ptr<ssm::SoftwareSecurityModule>> open_ssm(const UnlockedVault& vault);
[[nodiscard]] Result<void> append_audit(UnlockedVault& vault, audit::EventType type, std::string subject, std::string detail = {});
[[nodiscard]] Result<void> verify_audit(const UnlockedVault& vault);
[[nodiscard]] VaultAnchor anchor_for(const UnlockedVault& vault);
[[nodiscard]] Result<void> verify_anchor(const UnlockedVault& vault, const VaultAnchor& expected);
[[nodiscard]] Result<UnlockedVault> collect_from_ssm(const VaultMetadata& metadata, const ssm::MasterKey& master_key, const ssm::SoftwareSecurityModule& ssm);
[[nodiscard]] std::vector<VaultKdfInfo> supported_kdfs();
[[nodiscard]] Result<VaultKdfParams> recommended_kdf_params(VaultKdf algorithm);
[[nodiscard]] const char* vault_kdf_name(VaultKdf algorithm) noexcept;
[[nodiscard]] Result<VaultKdf> parse_vault_kdf(std::string_view name);
[[nodiscard]] Result<UnlockedVault> rewrap_vault_kdf(const UnlockedVault& vault, VaultKdfParams params);
[[nodiscard]] Result<Bytes> derive_vault_wrap_key(std::string_view passphrase, ByteView salt, const VaultMetadata& metadata);
[[nodiscard]] Bytes pbkdf2_hmac_sha256(std::string_view passphrase, ByteView salt, std::uint32_t iterations, std::size_t output_len);
[[nodiscard]] Result<Bytes> encode_vault_backup(const UnlockedVault& vault, std::string_view passphrase);
[[nodiscard]] const char* vault_kdf_name() noexcept;

}  // namespace quantlib::vault

#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include "quantlib/sign.hpp"
#include "quantlib/ssm.hpp"
#include "quantlib/vault.hpp"
#include <memory>
#include <string>
#include <vector>

namespace quantlib::easy {

struct EasyOptions {
  std::string label{"quantlib"};
  std::string default_domain{"quantlib.app.sign"};
  std::uint64_t session_ttl_seconds{300};
  bool autosave{true};
};

struct KeySummary {
  ssm::Handle handle{};
  std::string label{};
  std::string type{};
  std::string state{};
  std::string domain{};
  std::uint64_t used_operations{0};
};

struct SignedMessage {
  ssm::Handle handle{};
  std::string domain{};
  sign::Signature signature{};
};

struct EasyStatus {
  std::string version{};
  std::string vault_id{};
  std::string label{};
  std::size_t key_count{0};
  bool session_open{false};
  bool autosave{true};
};

class QuantVault {
 public:
  QuantVault() = default;
  [[nodiscard]] static Result<QuantVault> create(const std::string& path, std::string_view passphrase, const EasyOptions& options = {});
  [[nodiscard]] static Result<QuantVault> open(const std::string& path, std::string_view passphrase, const EasyOptions& options = {});

  QuantVault(QuantVault&&) noexcept = default;
  QuantVault& operator=(QuantVault&&) noexcept = default;
  QuantVault(const QuantVault&) = delete;
  QuantVault& operator=(const QuantVault&) = delete;

  [[nodiscard]] Result<ssm::Handle> generate_signing_key(std::string label = {}, std::string domain = {}, std::uint64_t max_operations = 0);
  [[nodiscard]] Result<ssm::Handle> generate_exchange_key(std::string label = {});
  [[nodiscard]] Result<SignedMessage> sign(const ssm::Handle& handle, std::string_view message, std::string domain = {});
  [[nodiscard]] Result<SignedMessage> sign(const ssm::Handle& handle, ByteView message, std::string domain = {});
  [[nodiscard]] Result<bool> verify(const ssm::Handle& handle, std::string_view message, const sign::Signature& signature, std::string domain = {}) const;
  [[nodiscard]] Result<bool> verify(const ssm::Handle& handle, ByteView message, const sign::Signature& signature, std::string domain = {}) const;
  [[nodiscard]] Result<Bytes> public_key(const ssm::Handle& handle) const;
  [[nodiscard]] Result<ssm::RotationResult> rotate(const ssm::Handle& handle, std::string label = {}, std::string reason = "scheduled_rotation");
  [[nodiscard]] Result<void> set_state(const ssm::Handle& handle, ssm::KeyState state);
  [[nodiscard]] Result<void> erase(const ssm::Handle& handle);
  [[nodiscard]] Result<void> save();

  [[nodiscard]] std::vector<KeySummary> keys() const;
  [[nodiscard]] EasyStatus status() const;
  [[nodiscard]] const std::string& path() const noexcept { return path_; }

 private:
  QuantVault(std::string path, std::string passphrase, EasyOptions options, vault::UnlockedVault vault, std::unique_ptr<ssm::SoftwareSecurityModule> ssm);

  [[nodiscard]] Result<void> ensure_session();
  [[nodiscard]] Result<void> persist_if_needed();
  [[nodiscard]] Result<void> refresh_vault_from_ssm();
  [[nodiscard]] std::string domain_or_default(std::string domain) const;

  std::string path_{};
  std::string passphrase_{};
  EasyOptions options_{};
  vault::UnlockedVault vault_{};
  std::unique_ptr<ssm::SoftwareSecurityModule> ssm_{};
  std::unique_ptr<ssm::SsmSessionManager> sessions_{};
  ssm::SessionToken session_{};
  bool has_session_{false};
};

[[nodiscard]] Result<void> quick_create_vault(const std::string& path, std::string_view passphrase, std::string label = "quantlib");
[[nodiscard]] Result<ssm::Handle> quick_generate_signing_key(const std::string& path, std::string_view passphrase, std::string label, std::string domain = "quantlib.app.sign");
[[nodiscard]] Result<SignedMessage> quick_sign(const std::string& path, std::string_view passphrase, const ssm::Handle& handle, std::string_view message, std::string domain = "quantlib.app.sign");

}  // namespace quantlib::easy

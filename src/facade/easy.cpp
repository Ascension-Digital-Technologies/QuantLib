#include "quantlib/easy.hpp"
#include "quantlib/quantlib.hpp"
#include "quantlib/key.hpp"
#include <utility>

namespace quantlib::easy {
namespace {
Bytes view_from_string(std::string_view text) {
  return Bytes(text.begin(), text.end());
}

std::uint32_t default_session_permissions() {
  return static_cast<std::uint32_t>(ssm::SessionPermission::sign) |
         static_cast<std::uint32_t>(ssm::SessionPermission::decapsulate) |
         static_cast<std::uint32_t>(ssm::SessionPermission::export_public);
}

Result<ssm::ObjectInfo> require_info(const ssm::SoftwareSecurityModule& ssm, const ssm::Handle& handle) {
  auto info = ssm.info(handle);
  if (!info) return info.error();
  return info;
}
}

QuantVault::QuantVault(std::string path, std::string passphrase, EasyOptions options, vault::UnlockedVault vault, std::unique_ptr<ssm::SoftwareSecurityModule> ssm)
    : path_(std::move(path)), passphrase_(std::move(passphrase)), options_(std::move(options)), vault_(std::move(vault)), ssm_(std::move(ssm)) {
  sessions_ = std::make_unique<ssm::SsmSessionManager>(*ssm_);
}

Result<QuantVault> QuantVault::create(const std::string& path, std::string_view passphrase, const EasyOptions& options) {
  vault::VaultOptions vault_options{};
  vault_options.label = options.label.empty() ? "quantlib" : options.label;
  auto unlocked = vault::create_vault(passphrase, vault_options);
  if (!unlocked) return unlocked.error();
  auto ssm = vault::open_ssm(unlocked.value());
  if (!ssm) return ssm.error();
  auto saved = vault::save_vault_atomic(path, unlocked.value(), passphrase);
  if (!saved) return saved.error();
  return QuantVault(path, std::string(passphrase), options, std::move(unlocked).value(), std::move(ssm).value());
}

Result<QuantVault> QuantVault::open(const std::string& path, std::string_view passphrase, const EasyOptions& options) {
  auto unlocked = vault::load_vault(path, passphrase);
  if (!unlocked) return unlocked.error();
  auto ssm = vault::open_ssm(unlocked.value());
  if (!ssm) return ssm.error();
  return QuantVault(path, std::string(passphrase), options, std::move(unlocked).value(), std::move(ssm).value());
}

std::string QuantVault::domain_or_default(std::string domain) const {
  if (!domain.empty()) return domain;
  if (!options_.default_domain.empty()) return options_.default_domain;
  return "quantlib.app.sign";
}

Result<void> QuantVault::ensure_session() {
  if (has_session_) {
    auto info = sessions_->session_info(session_);
    if (info && !info.value().closed && info.value().expires_at > key::unix_time_now()) return {};
    has_session_ = false;
  }
  ssm::SessionOptions opts{};
  opts.ttl_seconds = options_.session_ttl_seconds == 0 ? 300 : options_.session_ttl_seconds;
  opts.permissions = default_session_permissions();
  auto opened = sessions_->open_session(opts);
  if (!opened) return opened.error();
  session_ = std::move(opened).value();
  has_session_ = true;
  return {};
}

Result<void> QuantVault::refresh_vault_from_ssm() {
  auto collected = vault::collect_from_ssm(vault_.metadata, vault_.master_key, *ssm_);
  if (!collected) return collected.error();
  vault_ = std::move(collected).value();
  return {};
}

Result<void> QuantVault::save() {
  auto refreshed = refresh_vault_from_ssm();
  if (!refreshed) return refreshed.error();
  return vault::save_vault_atomic(path_, vault_, passphrase_);
}

Result<void> QuantVault::persist_if_needed() {
  if (!options_.autosave) return {};
  return save();
}

Result<ssm::Handle> QuantVault::generate_signing_key(std::string label, std::string domain, std::uint64_t max_operations) {
  ssm::CreateOptions create{};
  create.label = label.empty() ? "signing-key" : std::move(label);
  create.allowed_domain = domain_or_default(std::move(domain));
  create.max_operations = max_operations;
  auto handle = ssm_->generate_sign_key(sign::Algorithm::ed25519, create);
  if (!handle) return handle.error();
  auto saved = persist_if_needed();
  if (!saved) return saved.error();
  return handle;
}

Result<ssm::Handle> QuantVault::generate_exchange_key(std::string label) {
  ssm::CreateOptions create{};
  create.label = label.empty() ? "exchange-key" : std::move(label);
  auto handle = ssm_->generate_kem_key(kem::Algorithm::x25519, create);
  if (!handle) return handle.error();
  auto saved = persist_if_needed();
  if (!saved) return saved.error();
  return handle;
}

Result<SignedMessage> QuantVault::sign(const ssm::Handle& handle, std::string_view message, std::string domain) {
  auto bytes = view_from_string(message);
  return sign(handle, bytes, std::move(domain));
}

Result<SignedMessage> QuantVault::sign(const ssm::Handle& handle, ByteView message, std::string domain) {
  auto session = ensure_session();
  if (!session) return session.error();
  const auto d = domain_or_default(std::move(domain));
  auto signature = sessions_->sign_domain(session_, handle, d, message);
  if (!signature) return signature.error();
  auto saved = persist_if_needed();
  if (!saved) return saved.error();
  return SignedMessage{handle, d, std::move(signature).value()};
}

Result<bool> QuantVault::verify(const ssm::Handle& handle, std::string_view message, const sign::Signature& signature, std::string domain) const {
  auto bytes = view_from_string(message);
  return verify(handle, bytes, signature, std::move(domain));
}

Result<bool> QuantVault::verify(const ssm::Handle& handle, ByteView message, const sign::Signature& signature, std::string domain) const {
  auto info = require_info(*ssm_, handle);
  if (!info) return info.error();
  if (info.value().type != ssm::ObjectType::sign) return make_error(ErrorCode::invalid_key, "handle is not a signing key");
  sign::PublicKey public_key{static_cast<sign::Algorithm>(info.value().algorithm), info.value().public_key};
  return ssm::verify_domain_signature(public_key, handle, domain_or_default(std::move(domain)), message, signature);
}

Result<Bytes> QuantVault::public_key(const ssm::Handle& handle) const {
  return ssm_->public_key(handle);
}

Result<ssm::RotationResult> QuantVault::rotate(const ssm::Handle& handle, std::string label, std::string reason) {
  ssm::RotateOptions opts{};
  opts.label = std::move(label);
  opts.reason = reason.empty() ? "scheduled_rotation" : std::move(reason);
  auto rotated = ssm_->rotate_key(handle, opts);
  if (!rotated) return rotated.error();
  auto saved = persist_if_needed();
  if (!saved) return saved.error();
  return rotated;
}

Result<void> QuantVault::set_state(const ssm::Handle& handle, ssm::KeyState state) {
  auto set = ssm_->set_state(handle, state);
  if (!set) return set.error();
  return persist_if_needed();
}

Result<void> QuantVault::erase(const ssm::Handle& handle) {
  auto erased = ssm_->erase(handle);
  if (!erased) return erased.error();
  return persist_if_needed();
}

std::vector<KeySummary> QuantVault::keys() const {
  std::vector<KeySummary> out;
  for (const auto& key : ssm_->list()) {
    out.push_back(KeySummary{key.handle, key.label, ssm::object_type_name(key.type), ssm::key_state_name(key.state), key.allowed_domain, key.used_operations});
  }
  return out;
}

EasyStatus QuantVault::status() const {
  return EasyStatus{kVersion, vault_.metadata.vault_id, vault_.metadata.label, ssm_->list().size(), has_session_, options_.autosave};
}

Result<void> quick_create_vault(const std::string& path, std::string_view passphrase, std::string label) {
  EasyOptions options{};
  options.label = std::move(label);
  auto vault = QuantVault::create(path, passphrase, options);
  if (!vault) return vault.error();
  return {};
}

Result<ssm::Handle> quick_generate_signing_key(const std::string& path, std::string_view passphrase, std::string label, std::string domain) {
  EasyOptions options{};
  options.default_domain = domain.empty() ? "quantlib.app.sign" : domain;
  auto vault = QuantVault::open(path, passphrase, options);
  if (!vault) return vault.error();
  return vault.value().generate_signing_key(std::move(label), options.default_domain);
}

Result<SignedMessage> quick_sign(const std::string& path, std::string_view passphrase, const ssm::Handle& handle, std::string_view message, std::string domain) {
  EasyOptions options{};
  options.default_domain = domain.empty() ? "quantlib.app.sign" : domain;
  auto vault = QuantVault::open(path, passphrase, options);
  if (!vault) return vault.error();
  return vault.value().sign(handle, message, options.default_domain);
}

}  // namespace quantlib::easy

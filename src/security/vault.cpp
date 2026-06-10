#include "quantlib/vault.hpp"
#include "quantlib/aead.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/kdf.hpp"
#include "quantlib/key.hpp"
#include "quantlib/rng.hpp"
#include "quantlib/secure.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iterator>

namespace quantlib::vault {
namespace {
constexpr std::array<std::uint8_t, 7> kMagic = {'A','V','A','U','L','T','1'};

void put_u16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}
void put_u32(Bytes& out, std::uint32_t v) {
  for (int i = 3; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}
void put_u64(Bytes& out, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>(v >> (i * 8)));
}
void put_bytes(Bytes& out, ByteView v) {
  put_u32(out, static_cast<std::uint32_t>(v.size()));
  out.insert(out.end(), v.begin(), v.end());
}
void put_string(Bytes& out, const std::string& s) {
  put_u32(out, static_cast<std::uint32_t>(s.size()));
  out.insert(out.end(), s.begin(), s.end());
}
bool take_u16(ByteView in, std::size_t& o, std::uint16_t& v) {
  if (o + 2 > in.size()) return false;
  v = (static_cast<std::uint16_t>(in[o]) << 8) | in[o + 1];
  o += 2;
  return true;
}
bool take_u32(ByteView in, std::size_t& o, std::uint32_t& v) {
  if (o + 4 > in.size()) return false;
  v = 0;
  for (int i = 0; i < 4; ++i) v = (v << 8) | in[o++];
  return true;
}
bool take_u64(ByteView in, std::size_t& o, std::uint64_t& v) {
  if (o + 8 > in.size()) return false;
  v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8) | in[o++];
  return true;
}
bool take_bytes(ByteView in, std::size_t& o, Bytes& v) {
  std::uint32_t len = 0;
  if (!take_u32(in, o, len) || o + len > in.size()) return false;
  v.assign(in.begin() + static_cast<std::ptrdiff_t>(o), in.begin() + static_cast<std::ptrdiff_t>(o + len));
  o += len;
  return true;
}
bool take_string(ByteView in, std::size_t& o, std::string& v) {
  Bytes raw;
  if (!take_bytes(in, o, raw)) return false;
  v.assign(raw.begin(), raw.end());
  return true;
}

Bytes passphrase_bytes(std::string_view passphrase) {
  return Bytes(passphrase.begin(), passphrase.end());
}

std::string lowercase(std::string_view value) {
  std::string out(value.begin(), value.end());
  for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

Result<Bytes> derive_wrap_key(std::string_view passphrase, ByteView salt, const VaultMetadata& metadata) {
  return derive_vault_wrap_key(passphrase, salt, metadata);
}

Bytes vault_aad(const VaultMetadata& metadata, ByteView salt) {
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, kVaultVersion);
  put_string(out, metadata.vault_id);
  put_string(out, metadata.label);
  put_string(out, metadata.kdf);
  put_u32(out, metadata.kdf_iterations);
  put_u32(out, metadata.kdf_memory_kib);
  put_u32(out, metadata.kdf_parallelism);
  put_u64(out, metadata.created_at);
  put_u64(out, metadata.generation);
  put_string(out, metadata.previous_audit_head);
  put_bytes(out, salt);
  return out;
}

std::string make_vault_id(ByteView salt, std::uint64_t created_at) {
  Bytes material;
  material.insert(material.end(), kMagic.begin(), kMagic.end());
  put_bytes(material, salt);
  put_u64(material, created_at);
  const auto digest = hash::sha256(material);
  return hex_encode(ByteView(digest.data(), 16));
}

Result<VaultFile> lock_vault(const UnlockedVault& vault, std::string_view passphrase) {
  if (vault.master_key.bytes.size() != ssm::kMasterKeyBytes) {
    return make_error(ErrorCode::invalid_key, "vault master key is invalid");
  }
  VaultFile file{};
  file.metadata = vault.metadata;
  file.metadata.updated_at = key::unix_time_now();
  file.metadata.generation = vault.metadata.generation + 1;
  file.metadata.previous_audit_head = hex_encode(audit::head_hash(vault.audit_log));
  if (file.metadata.kdf.empty()) file.metadata.kdf = vault_kdf_name();
  if (file.metadata.kdf_iterations == 0) file.metadata.kdf_iterations = kDefaultKdfIterations;

  auto salt = rng::random_bytes(kVaultSaltBytes);
  if (!salt) return salt.error();
  auto nonce = rng::random_bytes(kVaultWrapNonceBytes);
  if (!nonce) return nonce.error();
  file.salt = std::move(salt).value();
  file.wrap_nonce = std::move(nonce).value();
  if (file.metadata.vault_id.empty()) file.metadata.vault_id = make_vault_id(file.salt, file.metadata.created_at);

  auto key = derive_wrap_key(passphrase, file.salt, file.metadata);
  if (!key) return key.error();
  auto aad = vault_aad(file.metadata, file.salt);
  auto sealed = aead::encrypt_with_nonce(aead::Algorithm::aes_256_gcm, key.value(), file.wrap_nonce, vault.master_key.bytes, aad);
  secure_zero(key.value().data(), key.value().size());
  if (!sealed) return sealed.error();
  auto sealed_value = std::move(sealed).value();
  file.wrapped_master_key = std::move(sealed_value.data);
  file.wrap_tag = std::move(sealed_value.tag);
  for (const auto& object : vault.objects) {
    auto encoded = ssm::encode_sealed(object);
    if (!encoded) return encoded.error();
    file.sealed_objects.push_back(std::move(encoded).value());
  }
  auto audit_raw = audit::encode_log(vault.audit_log);
  if (!audit_raw) return audit_raw.error();
  file.audit_log = std::move(audit_raw).value();
  file.audit_head = audit::head_hash(vault.audit_log);
  return file;
}

}  // namespace

const char* vault_kdf_name() noexcept { return vault_kdf_name(VaultKdf::pbkdf2_hmac_sha256); }

const char* vault_kdf_name(VaultKdf algorithm) noexcept {
  switch (algorithm) {
    case VaultKdf::pbkdf2_hmac_sha256: return "pbkdf2-hmac-sha256";
    case VaultKdf::argon2id: return "argon2id";
    case VaultKdf::scrypt: return "scrypt";
  }
  return "unknown";
}

Result<VaultKdf> parse_vault_kdf(std::string_view name) {
  const auto n = lowercase(name);
  if (n == "pbkdf2-hmac-sha256" || n == "pbkdf2") return VaultKdf::pbkdf2_hmac_sha256;
  if (n == "argon2id") return VaultKdf::argon2id;
  if (n == "scrypt") return VaultKdf::scrypt;
  return make_error(ErrorCode::unsupported_algorithm, "unsupported vault KDF");
}

std::vector<VaultKdfInfo> supported_kdfs() {
  return {
      {VaultKdf::pbkdf2_hmac_sha256, vault_kdf_name(VaultKdf::pbkdf2_hmac_sha256), true, false, kRecommendedKdfIterations, 0, 1, "portable built-in compatibility KDF"},
      {VaultKdf::argon2id, vault_kdf_name(VaultKdf::argon2id), false, true, 3, 65536, 1, "memory-hard provider hook; unavailable until an Argon2id backend is linked"},
      {VaultKdf::scrypt, vault_kdf_name(VaultKdf::scrypt), false, true, 8, 32768, 1, "memory-hard provider hook; unavailable until a scrypt backend is linked"},
  };
}

Result<VaultKdfParams> recommended_kdf_params(VaultKdf algorithm) {
  switch (algorithm) {
    case VaultKdf::pbkdf2_hmac_sha256: return VaultKdfParams{algorithm, kRecommendedKdfIterations, 0, 1};
    case VaultKdf::argon2id: return make_error(ErrorCode::unsupported_algorithm, "Argon2id provider not linked");
    case VaultKdf::scrypt: return make_error(ErrorCode::unsupported_algorithm, "scrypt provider not linked");
  }
  return make_error(ErrorCode::unsupported_algorithm, "unsupported vault KDF");
}

Result<UnlockedVault> rewrap_vault_kdf(const UnlockedVault& vault, VaultKdfParams params) {
  if (params.algorithm != VaultKdf::pbkdf2_hmac_sha256) {
    return make_error(ErrorCode::unsupported_algorithm, std::string(vault_kdf_name(params.algorithm)) + " provider not linked");
  }
  if (params.iterations < kMinimumKdfIterations) return make_error(ErrorCode::invalid_argument, "vault KDF iterations too low");
  auto copy = vault;
  copy.metadata.kdf = vault_kdf_name(params.algorithm);
  copy.metadata.kdf_iterations = params.iterations;
  copy.metadata.kdf_memory_kib = params.memory_kib;
  copy.metadata.kdf_parallelism = params.parallelism == 0 ? 1 : params.parallelism;
  copy.metadata.updated_at = key::unix_time_now();
  auto added = audit::append(copy.audit_log, audit::EventType::policy_changed, copy.metadata.vault_id, "vault KDF parameters changed");
  if (!added) return added.error();
  return copy;
}

Result<Bytes> derive_vault_wrap_key(std::string_view passphrase, ByteView salt, const VaultMetadata& metadata) {
  if (passphrase.empty()) return make_error(ErrorCode::invalid_argument, "vault passphrase is required");
  if (salt.size() != kVaultSaltBytes) return make_error(ErrorCode::invalid_format, "vault salt must be 16 bytes");
  auto parsed = parse_vault_kdf(metadata.kdf.empty() ? vault_kdf_name() : metadata.kdf);
  if (!parsed) return parsed.error();
  if (parsed.value() != VaultKdf::pbkdf2_hmac_sha256) {
    return make_error(ErrorCode::unsupported_algorithm, std::string(vault_kdf_name(parsed.value())) + " provider not linked");
  }
  if (metadata.kdf_iterations < kMinimumKdfIterations) return make_error(ErrorCode::invalid_argument, "vault KDF iterations too low");
  auto out = pbkdf2_hmac_sha256(passphrase, salt, metadata.kdf_iterations, 32);
  if (out.size() != 32) return make_error(ErrorCode::internal_error, "vault wrap key derivation failed");
  return out;
}

Bytes pbkdf2_hmac_sha256(std::string_view passphrase, ByteView salt, std::uint32_t iterations, std::size_t output_len) {
  Bytes out;
  if (iterations == 0 || output_len == 0) return out;
  const Bytes password = passphrase_bytes(passphrase);
  std::uint32_t block_index = 1;
  while (out.size() < output_len) {
    Bytes input(salt.begin(), salt.end());
    put_u32(input, block_index++);
    Bytes u = kdf::hmac_sha256(password, input);
    Bytes t = u;
    for (std::uint32_t i = 1; i < iterations; ++i) {
      u = kdf::hmac_sha256(password, u);
      for (std::size_t j = 0; j < t.size(); ++j) t[j] ^= u[j];
    }
    out.insert(out.end(), t.begin(), t.end());
    secure_zero(u.data(), u.size());
    secure_zero(t.data(), t.size());
  }
  out.resize(output_len);
  return out;
}

Result<UnlockedVault> create_vault(std::string_view passphrase, const VaultOptions& options) {
  if (passphrase.empty()) return make_error(ErrorCode::invalid_argument, "vault passphrase is required");
  const auto requested_kdf = options.kdf.algorithm;
  if (requested_kdf != VaultKdf::pbkdf2_hmac_sha256) {
    return make_error(ErrorCode::unsupported_algorithm, std::string(vault_kdf_name(requested_kdf)) + " provider not linked");
  }
  const auto iterations = options.kdf.iterations != kDefaultKdfIterations ? options.kdf.iterations : options.kdf_iterations;
  if (iterations < kMinimumKdfIterations) return make_error(ErrorCode::invalid_argument, "vault KDF iterations too low");
  auto master = ssm::generate_master_key();
  if (!master) return master.error();
  const auto now = key::unix_time_now();
  VaultMetadata metadata{};
  metadata.label = options.label;
  metadata.kdf = vault_kdf_name(requested_kdf);
  metadata.kdf_iterations = iterations;
  metadata.kdf_memory_kib = options.kdf.memory_kib;
  metadata.kdf_parallelism = options.kdf.parallelism == 0 ? 1 : options.kdf.parallelism;
  metadata.created_at = now;
  metadata.updated_at = now;
  metadata.generation = 1;
  auto id_salt = rng::random_bytes(kVaultSaltBytes);
  if (!id_salt) return id_salt.error();
  metadata.vault_id = make_vault_id(id_salt.value(), now);
  UnlockedVault vault{metadata, std::move(master).value(), {}, {}};
  auto added = audit::append(vault.audit_log, audit::EventType::vault_created, metadata.vault_id, metadata.label);
  if (!added) return added.error();
  return vault;
}

Result<Bytes> encode_vault(const UnlockedVault& vault, std::string_view passphrase) {
  auto file = lock_vault(vault, passphrase);
  if (!file) return file.error();
  return encode_vault_file(file.value());
}

Result<Bytes> encode_vault_backup(const UnlockedVault& vault, std::string_view passphrase) {
  return encode_vault(vault, passphrase);
}

Result<void> save_vault_atomic(const std::string& path, const UnlockedVault& vault, std::string_view passphrase) {
  if (path.empty()) return make_error(ErrorCode::invalid_argument, "vault path is required");
  auto encoded = encode_vault(vault, passphrase);
  if (!encoded) return encoded.error();
  const std::filesystem::path primary(path);
  const auto temp = primary.string() + ".tmp";
  const auto backup = primary.string() + ".bak";
  {
    std::ofstream out(temp, std::ios::binary | std::ios::trunc);
    if (!out) return make_error(ErrorCode::internal_error, "cannot open temporary vault file");
    out.write(reinterpret_cast<const char*>(encoded.value().data()), static_cast<std::streamsize>(encoded.value().size()));
    out.flush();
    if (!out) return make_error(ErrorCode::internal_error, "cannot write temporary vault file");
  }
  std::error_code ec;
  if (std::filesystem::exists(primary, ec)) {
    std::filesystem::copy_file(primary, backup, std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) return make_error(ErrorCode::internal_error, "cannot create vault backup");
  }
  std::filesystem::rename(temp, primary, ec);
  if (ec) {
    std::filesystem::remove(temp, ec);
    return make_error(ErrorCode::internal_error, "cannot atomically replace vault file");
  }
  return {};
}

Result<UnlockedVault> load_vault(const std::string& path, std::string_view passphrase, VaultRecoveryReport* report) {
  if (path.empty()) return make_error(ErrorCode::invalid_argument, "vault path is required");
  auto read_all = [](const std::string& p) -> Bytes {
    std::ifstream in(p, std::ios::binary);
    if (!in) return {};
    return Bytes(std::istreambuf_iterator<char>(in), {});
  };
  VaultRecoveryReport local{};
  const auto primary = read_all(path);
  local.primary_present = !primary.empty();
  if (!primary.empty()) {
    auto decoded = decode_vault(primary, passphrase);
    if (decoded) {
      local.primary_decodable = true;
      local.selected = "primary";
      local.detail = "primary vault opened";
      if (report) *report = local;
      return decoded;
    }
    local.detail = decoded.error().message;
  }
  const auto backup_path = path + ".bak";
  const auto backup = read_all(backup_path);
  local.backup_present = !backup.empty();
  if (!backup.empty()) {
    auto decoded = decode_vault(backup, passphrase);
    if (decoded) {
      local.backup_decodable = true;
      local.selected = "backup";
      local.detail = "primary failed; backup opened";
      if (report) *report = local;
      return decoded;
    }
    if (local.detail.empty()) local.detail = decoded.error().message;
  }
  if (report) *report = local;
  return make_error(ErrorCode::invalid_format, local.detail.empty() ? "no readable vault or backup" : local.detail);
}

Result<UnlockedVault> decode_vault(ByteView encoded, std::string_view passphrase) {
  auto file = decode_vault_file(encoded);
  if (!file) return file.error();
  auto key = derive_wrap_key(passphrase, file.value().salt, file.value().metadata);
  if (!key) return key.error();
  auto aad = vault_aad(file.value().metadata, file.value().salt);
  auto opened = aead::decrypt(aead::Algorithm::aes_256_gcm, key.value(), aead::Ciphertext{file.value().wrap_nonce, file.value().wrapped_master_key, file.value().wrap_tag}, aad);
  secure_zero(key.value().data(), key.value().size());
  if (!opened) return opened.error();
  auto master = ssm::import_master_key(opened.value());
  secure_zero(opened.value().data(), opened.value().size());
  if (!master) return master.error();
  UnlockedVault vault{file.value().metadata, std::move(master).value(), {}};
  for (const auto& raw : file.value().sealed_objects) {
    auto object = ssm::decode_sealed(raw);
    if (!object) return object.error();
    vault.objects.push_back(std::move(object).value());
  }
  if (!file.value().audit_log.empty()) {
    auto log = audit::decode_log(file.value().audit_log);
    if (!log) return log.error();
    vault.audit_log = std::move(log).value();
  }
  auto appended = audit::append(vault.audit_log, audit::EventType::vault_unlocked, vault.metadata.vault_id, "decode_vault");
  if (!appended) return appended.error();
  return vault;
}

Result<Bytes> encode_vault_file(const VaultFile& file) {
  if (file.metadata.vault_id.empty() || file.salt.size() != kVaultSaltBytes || file.wrap_nonce.size() != kVaultWrapNonceBytes ||
      file.wrapped_master_key.empty() || file.wrap_tag.empty()) {
    return make_error(ErrorCode::invalid_argument, "vault file is incomplete");
  }
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, kVaultVersion);
  put_string(out, file.metadata.vault_id);
  put_string(out, file.metadata.label);
  put_string(out, file.metadata.kdf);
  put_u32(out, file.metadata.kdf_iterations);
  put_u32(out, file.metadata.kdf_memory_kib);
  put_u32(out, file.metadata.kdf_parallelism);
  put_u64(out, file.metadata.created_at);
  put_u64(out, file.metadata.updated_at);
  put_u64(out, file.metadata.generation);
  put_string(out, file.metadata.previous_audit_head);
  put_bytes(out, file.salt);
  put_bytes(out, file.wrap_nonce);
  put_bytes(out, file.wrapped_master_key);
  put_bytes(out, file.wrap_tag);
  put_u32(out, static_cast<std::uint32_t>(file.sealed_objects.size()));
  for (const auto& object : file.sealed_objects) put_bytes(out, object);
  put_bytes(out, file.audit_log);
  put_bytes(out, file.audit_head);
  const auto checksum = hash::sha256(out);
  out.insert(out.end(), checksum.begin(), checksum.end());
  return out;
}

Result<VaultFile> decode_vault_file(ByteView encoded) {
  if (encoded.size() < kMagic.size() + 2 + 32) return make_error(ErrorCode::invalid_format, "vault file is too short");
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    if (encoded[i] != kMagic[i]) return make_error(ErrorCode::invalid_format, "invalid vault magic");
  }
  const ByteView body(encoded.data(), encoded.size() - 32);
  const ByteView got(encoded.data() + encoded.size() - 32, 32);
  const auto expected = hash::sha256(body);
  if (!constant_time_equal(expected, got)) return make_error(ErrorCode::invalid_format, "vault checksum mismatch");
  std::size_t o = kMagic.size();
  std::uint16_t version = 0;
  VaultFile file{};
  std::uint32_t object_count = 0;
  if (!take_u16(encoded, o, version) || version != kVaultVersion ||
      !take_string(encoded, o, file.metadata.vault_id) || !take_string(encoded, o, file.metadata.label) ||
      !take_string(encoded, o, file.metadata.kdf) || !take_u32(encoded, o, file.metadata.kdf_iterations) ||
      !take_u32(encoded, o, file.metadata.kdf_memory_kib) || !take_u32(encoded, o, file.metadata.kdf_parallelism) ||
      !take_u64(encoded, o, file.metadata.created_at) || !take_u64(encoded, o, file.metadata.updated_at) ||
      !take_u64(encoded, o, file.metadata.generation) || !take_string(encoded, o, file.metadata.previous_audit_head) ||
      !take_bytes(encoded, o, file.salt) || !take_bytes(encoded, o, file.wrap_nonce) ||
      !take_bytes(encoded, o, file.wrapped_master_key) || !take_bytes(encoded, o, file.wrap_tag) || !take_u32(encoded, o, object_count)) {
    return make_error(ErrorCode::invalid_format, "truncated vault file");
  }
  auto parsed_kdf = parse_vault_kdf(file.metadata.kdf);
  if (!parsed_kdf) return parsed_kdf.error();
  if (parsed_kdf.value() != VaultKdf::pbkdf2_hmac_sha256) return make_error(ErrorCode::unsupported_algorithm, std::string(file.metadata.kdf) + " provider not linked");
  if (file.metadata.kdf_iterations < kMinimumKdfIterations) return make_error(ErrorCode::invalid_format, "vault KDF iterations too low");
  if (file.metadata.kdf_parallelism == 0) return make_error(ErrorCode::invalid_format, "vault KDF parallelism cannot be zero");
  if (file.salt.size() != kVaultSaltBytes || file.wrap_nonce.size() != kVaultWrapNonceBytes) {
    return make_error(ErrorCode::invalid_format, "invalid vault salt or nonce length");
  }
  file.sealed_objects.reserve(object_count);
  for (std::uint32_t i = 0; i < object_count; ++i) {
    Bytes object;
    if (!take_bytes(encoded, o, object)) return make_error(ErrorCode::invalid_format, "truncated vault object list");
    file.sealed_objects.push_back(std::move(object));
  }
  if (!take_bytes(encoded, o, file.audit_log) || !take_bytes(encoded, o, file.audit_head)) return make_error(ErrorCode::invalid_format, "truncated vault audit log");
  if (!file.audit_log.empty()) {
    auto log = audit::decode_log(file.audit_log);
    if (!log) return log.error();
    const auto head = audit::head_hash(log.value());
    if (file.audit_head.size() != audit::kAuditHashBytes || !constant_time_equal(head, file.audit_head)) {
      return make_error(ErrorCode::invalid_format, "vault audit head mismatch");
    }
  } else if (file.audit_head.size() != audit::kAuditHashBytes || !constant_time_equal(file.audit_head, audit::genesis_hash())) {
    return make_error(ErrorCode::invalid_format, "vault empty audit head mismatch");
  }
  if (file.metadata.generation == 0) return make_error(ErrorCode::invalid_format, "vault generation cannot be zero");
  if (o + 32 != encoded.size()) return make_error(ErrorCode::invalid_format, "trailing vault data");
  return file;
}

Result<std::unique_ptr<ssm::SoftwareSecurityModule>> open_ssm(const UnlockedVault& vault) {
  auto module = std::make_unique<ssm::SoftwareSecurityModule>(vault.master_key);
  for (const auto& object : vault.objects) {
    auto imported = module->import_sealed(object);
    if (!imported) return imported.error();
  }
  return module;
}

Result<void> append_audit(UnlockedVault& vault, audit::EventType type, std::string subject, std::string detail) {
  return audit::append(vault.audit_log, type, std::move(subject), std::move(detail));
}

Result<void> verify_audit(const UnlockedVault& vault) { return audit::verify(vault.audit_log); }

VaultAnchor anchor_for(const UnlockedVault& vault) {
  return VaultAnchor{vault.metadata.vault_id, vault.metadata.generation, audit::head_hash(vault.audit_log)};
}

Result<void> verify_anchor(const UnlockedVault& vault, const VaultAnchor& expected) {
  if (vault.metadata.vault_id != expected.vault_id) return make_error(ErrorCode::invalid_format, "vault anchor id mismatch");
  if (vault.metadata.generation < expected.generation) return make_error(ErrorCode::invalid_format, "vault rollback detected by generation");
  const auto head = audit::head_hash(vault.audit_log);
  if (!expected.audit_head.empty() && vault.metadata.generation == expected.generation && !constant_time_equal(head, expected.audit_head)) {
    return make_error(ErrorCode::invalid_format, "vault anchor audit head mismatch");
  }
  return {};
}

Result<UnlockedVault> collect_from_ssm(const VaultMetadata& metadata, const ssm::MasterKey& master_key, const ssm::SoftwareSecurityModule& module) {
  UnlockedVault vault{metadata, master_key, {}, {}};
  for (const auto& info : module.list()) {
    auto object = module.export_sealed(info.handle);
    if (!object) return object.error();
    vault.objects.push_back(std::move(object).value());
  }
  auto appended = audit::append(vault.audit_log, audit::EventType::vault_saved, metadata.vault_id, "collect_from_ssm");
  if (!appended) return appended.error();
  return vault;
}

}  // namespace quantlib::vault

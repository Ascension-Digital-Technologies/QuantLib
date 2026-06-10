#include "quantlib/ssm.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/kdf.hpp"
#include "quantlib/key.hpp"
#include "quantlib/rng.hpp"
#include "quantlib/secure.hpp"
#include "quantlib/transcript.hpp"
#include <algorithm>
#include <array>
#include <utility>

namespace quantlib::ssm {
namespace {
constexpr std::array<std::uint8_t, 6> kMagic = {'A','S','S','M','0','1'};
constexpr std::uint32_t flag(ObjectFlag f) { return static_cast<std::uint32_t>(f); }

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

Bytes derive_seal_key(ByteView master) {
  static constexpr std::uint8_t info[] = {
      'A','e','g','i','s','C','r','y','p','t',' ','S','S','M',' ','S','e','a','l',' ','v','1'};
  Bytes salt = {'s','s','m','-','s','e','a','l','-','s','a','l','t'};
  auto key = kdf::hkdf_sha256(master, salt, ByteView(info, sizeof(info)), kMasterKeyBytes);
  if (!key) return {};
  return std::move(key).value();
}

Bytes make_handle(const ObjectInfo& info) {
  Bytes data;
  data.insert(data.end(), kMagic.begin(), kMagic.end());
  put_u16(data, kSsmVersion);
  put_u16(data, static_cast<std::uint16_t>(info.type));
  put_u16(data, info.algorithm);
  put_u64(data, info.created_at);
  put_bytes(data, info.public_key);
  put_string(data, info.label);
  const auto digest = hash::sha256(data);
  return Bytes(digest.begin(), digest.begin() + 16);
}

bool has_flag(std::uint32_t flags, ObjectFlag f) noexcept {
  return (flags & flag(f)) != 0;
}

Bytes ascii_bytes(const std::string& s) {
  return Bytes(s.begin(), s.end());
}

Bytes u16_bytes(std::uint16_t v) {
  return Bytes{static_cast<std::uint8_t>(v >> 8), static_cast<std::uint8_t>(v)};
}

Result<Bytes> domain_message(const Handle& handle, std::uint16_t algorithm, const std::string& domain, ByteView message) {
  if (domain.empty()) return make_error(ErrorCode::invalid_argument, "SSM signing domain is required");
  transcript::Transcript t("QuantLib SSM Domain Sign v1");
  auto h = ascii_bytes(handle);
  auto d = ascii_bytes(domain);
  auto a = u16_bytes(algorithm);
  if (!t.append("handle", h) || !t.append("domain", d) || !t.append("algorithm", a) || !t.append("message", message)) {
    return make_error(ErrorCode::invalid_argument, "SSM domain transcript append failed");
  }
  const auto digest = t.digest();
  return Bytes(digest.begin(), digest.end());
}
}

Result<MasterKey> generate_master_key() {
  auto raw = rng::random_bytes(kMasterKeyBytes);
  if (!raw) return raw.error();
  return MasterKey{std::move(raw).value()};
}

Result<MasterKey> import_master_key(ByteView raw) {
  if (raw.size() != kMasterKeyBytes) {
    return make_error(ErrorCode::invalid_key, "SSM master key must be 32 bytes");
  }
  return MasterKey{Bytes(raw.begin(), raw.end())};
}

const char* object_type_name(ObjectType type) noexcept {
  switch (type) {
    case ObjectType::symmetric: return "symmetric";
    case ObjectType::sign: return "sign";
    case ObjectType::kem: return "kem";
  }
  return "unknown";
}

const char* key_state_name(KeyState state) noexcept {
  switch (state) {
    case KeyState::active: return "active";
    case KeyState::locked: return "locked";
    case KeyState::disabled: return "disabled";
    case KeyState::expired: return "expired";
    case KeyState::destroyed: return "destroyed";
    case KeyState::compromised: return "compromised";
    case KeyState::retired: return "retired";
  }
  return "unknown";
}


namespace {
bool take_u16(ByteView in, std::size_t& o, std::uint16_t& v) {
  if (o + 2 > in.size()) return false;
  v = (static_cast<std::uint16_t>(in[o]) << 8) | in[o + 1]; o += 2; return true;
}
bool take_u32(ByteView in, std::size_t& o, std::uint32_t& v) {
  if (o + 4 > in.size()) return false;
  v = 0; for (int i = 0; i < 4; ++i) v = (v << 8) | in[o++]; return true;
}
bool take_u64(ByteView in, std::size_t& o, std::uint64_t& v) {
  if (o + 8 > in.size()) return false;
  v = 0; for (int i = 0; i < 8; ++i) v = (v << 8) | in[o++]; return true;
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
}

Result<Bytes> encode_sealed(const SealedObject& object) {
  if (object.info.handle.empty() || object.nonce.empty() || object.ciphertext.empty() || object.tag.empty()) {
    return make_error(ErrorCode::invalid_argument, "sealed SSM object is incomplete");
  }
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, kSsmVersion);
  put_string(out, object.info.handle);
  put_u16(out, static_cast<std::uint16_t>(object.info.type));
  put_u16(out, object.info.algorithm);
  put_u32(out, object.info.flags);
  put_u64(out, object.info.created_at);
  put_string(out, object.info.label);
  put_bytes(out, object.info.key_id);
  put_bytes(out, object.info.public_key);
  put_u16(out, static_cast<std::uint16_t>(object.info.state));
  put_string(out, object.info.allowed_domain);
  put_u64(out, object.info.max_operations);
  put_u64(out, object.info.used_operations);
  put_u64(out, object.info.last_used_at);
  put_string(out, object.info.rotation.original_handle);
  put_string(out, object.info.rotation.replacement_handle);
  put_u64(out, object.info.rotation.generation);
  put_u64(out, object.info.rotation.rotated_at);
  put_string(out, object.info.rotation.reason);
  put_bytes(out, object.nonce);
  put_bytes(out, object.ciphertext);
  put_bytes(out, object.tag);
  const auto checksum = hash::sha256(out);
  out.insert(out.end(), checksum.begin(), checksum.end());
  return out;
}

Result<SealedObject> decode_sealed(ByteView encoded) {
  if (encoded.size() < kMagic.size() + 2 + 32) return make_error(ErrorCode::invalid_format, "sealed SSM object is too short");
  for (std::size_t i = 0; i < kMagic.size(); ++i) {
    if (encoded[i] != kMagic[i]) return make_error(ErrorCode::invalid_format, "invalid SSM object magic");
  }
  const ByteView body(encoded.data(), encoded.size() - 32);
  const ByteView got(encoded.data() + encoded.size() - 32, 32);
  const auto expected = hash::sha256(body);
  if (!constant_time_equal(expected, got)) return make_error(ErrorCode::invalid_format, "sealed SSM checksum mismatch");

  std::size_t o = kMagic.size();
  std::uint16_t version = 0;
  std::uint16_t type = 0;
  std::uint16_t state = 0;
  SealedObject object{};
  if (!take_u16(encoded, o, version) || version != kSsmVersion) return make_error(ErrorCode::invalid_format, "unsupported SSM object version");
  if (!take_string(encoded, o, object.info.handle) || !take_u16(encoded, o, type) || !take_u16(encoded, o, object.info.algorithm) ||
      !take_u32(encoded, o, object.info.flags) || !take_u64(encoded, o, object.info.created_at) || !take_string(encoded, o, object.info.label) ||
      !take_bytes(encoded, o, object.info.key_id) || !take_bytes(encoded, o, object.info.public_key) ||
      !take_u16(encoded, o, state) || !take_string(encoded, o, object.info.allowed_domain) ||
      !take_u64(encoded, o, object.info.max_operations) || !take_u64(encoded, o, object.info.used_operations) ||
      !take_u64(encoded, o, object.info.last_used_at) || !take_string(encoded, o, object.info.rotation.original_handle) ||
      !take_string(encoded, o, object.info.rotation.replacement_handle) || !take_u64(encoded, o, object.info.rotation.generation) ||
      !take_u64(encoded, o, object.info.rotation.rotated_at) || !take_string(encoded, o, object.info.rotation.reason) ||
      !take_bytes(encoded, o, object.nonce) ||
      !take_bytes(encoded, o, object.ciphertext) || !take_bytes(encoded, o, object.tag)) {
    return make_error(ErrorCode::invalid_format, "truncated sealed SSM object");
  }
  if (o + 32 != encoded.size()) return make_error(ErrorCode::invalid_format, "trailing sealed SSM data");
  object.info.type = static_cast<ObjectType>(type);
  object.info.state = static_cast<KeyState>(state);
  return object;
}

SoftwareSecurityModule::SoftwareSecurityModule(MasterKey master_key) : master_(std::move(master_key)) {}

SoftwareSecurityModule::~SoftwareSecurityModule() {
  clear();
  secure_zero(master_.bytes.data(), master_.bytes.size());
}

Result<Handle> SoftwareSecurityModule::generate_sign_key(sign::Algorithm algorithm, const CreateOptions& options) {
  auto kp = sign::generate_keypair(algorithm);
  if (!kp) return kp.error();
  ObjectInfo info{};
  info.type = ObjectType::sign;
  info.algorithm = static_cast<std::uint16_t>(algorithm);
  info.flags = options.flags | flag(ObjectFlag::allow_sign);
  info.created_at = key::unix_time_now();
  info.label = options.label;
  info.allowed_domain = options.allowed_domain;
  info.max_operations = options.max_operations;
  info.public_key = kp.value().public_key.bytes;
  info.key_id = key::key_id(info.public_key);
  auto handle = store_secret(std::move(info), kp.value().secret_key.bytes);
  secure_zero(kp.value().secret_key.bytes.data(), kp.value().secret_key.bytes.size());
  return handle;
}

Result<Handle> SoftwareSecurityModule::generate_kem_key(kem::Algorithm algorithm, const CreateOptions& options) {
  auto kp = kem::generate_keypair(algorithm);
  if (!kp) return kp.error();
  ObjectInfo info{};
  info.type = ObjectType::kem;
  info.algorithm = static_cast<std::uint16_t>(algorithm);
  info.flags = options.flags | flag(ObjectFlag::allow_decapsulate);
  info.created_at = key::unix_time_now();
  info.label = options.label;
  info.allowed_domain = options.allowed_domain;
  info.max_operations = options.max_operations;
  info.public_key = kp.value().public_key.bytes;
  info.key_id = key::key_id(info.public_key);
  auto handle = store_secret(std::move(info), kp.value().secret_key.bytes);
  secure_zero(kp.value().secret_key.bytes.data(), kp.value().secret_key.bytes.size());
  return handle;
}

Result<Handle> SoftwareSecurityModule::generate_symmetric_key(std::size_t key_bytes, const CreateOptions& options) {
  if (key_bytes == 0 || key_bytes > 128) return make_error(ErrorCode::invalid_argument, "invalid symmetric key size");
  auto raw = rng::random_bytes(key_bytes);
  if (!raw) return raw.error();
  ObjectInfo info{};
  info.type = ObjectType::symmetric;
  info.algorithm = 0x9001;
  info.flags = options.flags;
  info.created_at = key::unix_time_now();
  info.label = options.label;
  info.allowed_domain = options.allowed_domain;
  info.max_operations = options.max_operations;
  info.key_id = key::key_id(raw.value());
  auto handle = store_secret(std::move(info), raw.value());
  secure_zero(raw.value().data(), raw.value().size());
  return handle;
}

Result<sign::Signature> SoftwareSecurityModule::sign_message(const Handle& handle, ByteView message) const {
  Entry entry{};
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
    entry = it->second;
  }
  auto allowed = validate_operation(entry, Operation::sign, {});
  if (!allowed) return allowed.error();
  auto secret = open_secret(entry);
  if (!secret) return secret.error();
  auto sig = sign::sign(sign::SecretKey{static_cast<sign::Algorithm>(entry.info.algorithm), secret.value()}, message);
  secure_zero(secret.value().data(), secret.value().size());
  if (sig) record_operation(handle);
  return sig;
}

Result<sign::Signature> SoftwareSecurityModule::sign_domain(const Handle& handle, const std::string& domain, ByteView message) const {
  Entry entry{};
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
    entry = it->second;
  }
  auto allowed = validate_operation(entry, Operation::sign, domain);
  if (!allowed) return allowed.error();
  auto bound = domain_message(handle, entry.info.algorithm, domain, message);
  if (!bound) return bound.error();
  auto secret = open_secret(entry);
  if (!secret) return secret.error();
  auto sig = sign::sign(sign::SecretKey{static_cast<sign::Algorithm>(entry.info.algorithm), secret.value()}, bound.value());
  secure_zero(secret.value().data(), secret.value().size());
  if (sig) record_operation(handle);
  return sig;
}

Result<Bytes> SoftwareSecurityModule::decapsulate(const Handle& handle, ByteView ciphertext) const {
  Entry entry{};
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
    entry = it->second;
  }
  auto allowed = validate_operation(entry, Operation::decapsulate, {});
  if (!allowed) return allowed.error();
  auto secret = open_secret(entry);
  if (!secret) return secret.error();
  auto shared = kem::decapsulate(kem::SecretKey{static_cast<kem::Algorithm>(entry.info.algorithm), secret.value()}, ciphertext);
  secure_zero(secret.value().data(), secret.value().size());
  if (shared) record_operation(handle);
  return shared;
}

Result<ObjectInfo> SoftwareSecurityModule::info(const Handle& handle) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(handle);
  if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
  return it->second.info;
}

Result<Bytes> SoftwareSecurityModule::public_key(const Handle& handle) const {
  auto object = info(handle);
  if (!object) return object.error();
  Entry entry{object.value(), {}, {}, {}};
  auto allowed = validate_operation(entry, Operation::public_export, {});
  if (!allowed) return allowed.error();
  return object.value().public_key;
}

Result<SealedObject> SoftwareSecurityModule::export_sealed(const Handle& handle) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(handle);
  if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
  auto allowed = validate_operation(it->second, Operation::sealed_export, {});
  if (!allowed) return allowed.error();
  return SealedObject{it->second.info, it->second.nonce, it->second.ciphertext, it->second.tag};
}

Result<Handle> SoftwareSecurityModule::import_sealed(const SealedObject& object) {
  if (object.info.handle.empty()) return make_error(ErrorCode::invalid_format, "sealed SSM object has no handle");
  Entry entry{object.info, object.nonce, object.ciphertext, object.tag};
  auto opened = open_secret(entry);
  if (!opened) return opened.error();
  secure_zero(opened.value().data(), opened.value().size());
  std::lock_guard<std::mutex> lock(mutex_);
  entries_[object.info.handle] = std::move(entry);
  return object.info.handle;
}

std::vector<ObjectInfo> SoftwareSecurityModule::list() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<ObjectInfo> out;
  out.reserve(entries_.size());
  for (const auto& [_, entry] : entries_) out.push_back(entry.info);
  std::sort(out.begin(), out.end(), [](const ObjectInfo& a, const ObjectInfo& b) { return a.created_at < b.created_at; });
  return out;
}

bool SoftwareSecurityModule::contains(const Handle& handle) const {
  std::lock_guard<std::mutex> lock(mutex_);
  return entries_.find(handle) != entries_.end();
}

Result<void> SoftwareSecurityModule::set_state(const Handle& handle, KeyState state) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(handle);
  if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
  if (it->second.info.state == KeyState::destroyed) return make_error(ErrorCode::invalid_key, "destroyed SSM key cannot change state");
  it->second.info.state = state;
  return {};
}

Result<RotationResult> SoftwareSecurityModule::rotate_key(const Handle& handle, const RotateOptions& options) {
  Entry old_entry{};
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(handle);
    if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
    old_entry = it->second;
  }
  if (old_entry.info.state == KeyState::destroyed || old_entry.info.state == KeyState::compromised) {
    return make_error(ErrorCode::invalid_key, "SSM key cannot be rotated from its current state");
  }

  CreateOptions create{};
  create.label = options.label.empty() ? (old_entry.info.label + " rotated") : options.label;
  create.flags = old_entry.info.flags;
  create.allowed_domain = options.preserve_policy ? old_entry.info.allowed_domain : std::string{};
  create.max_operations = options.preserve_policy ? old_entry.info.max_operations : 0;

  Result<Handle> generated = make_error(ErrorCode::invalid_argument, "unsupported SSM object type for rotation");
  if (old_entry.info.type == ObjectType::sign) {
    generated = generate_sign_key(static_cast<sign::Algorithm>(old_entry.info.algorithm), create);
  } else if (old_entry.info.type == ObjectType::kem) {
    generated = generate_kem_key(static_cast<kem::Algorithm>(old_entry.info.algorithm), create);
  } else if (old_entry.info.type == ObjectType::symmetric) {
    const auto secret = open_secret(old_entry);
    if (!secret) return secret.error();
    generated = generate_symmetric_key(secret.value().size(), create);
  }
  if (!generated) return generated.error();

  const auto now = key::unix_time_now();
  const auto new_handle = generated.value();
  RotationResult result{};
  result.old_handle = handle;
  result.new_handle = new_handle;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto old_it = entries_.find(handle);
    auto new_it = entries_.find(new_handle);
    if (old_it == entries_.end() || new_it == entries_.end()) return make_error(ErrorCode::internal_error, "SSM rotation bookkeeping failed");
    const std::uint64_t new_generation = old_it->second.info.rotation.generation + 1;
    old_it->second.info.rotation.replacement_handle = new_handle;
    old_it->second.info.rotation.generation = new_generation;
    old_it->second.info.rotation.rotated_at = now;
    old_it->second.info.rotation.reason = options.reason;
    if (options.retire_old) old_it->second.info.state = KeyState::retired;

    new_it->second.info.rotation.original_handle = handle;
    new_it->second.info.rotation.generation = new_generation;
    new_it->second.info.rotation.rotated_at = now;
    new_it->second.info.rotation.reason = options.reason;
    result.old_info = old_it->second.info;
    result.new_info = new_it->second.info;
  }
  return result;
}

Result<void> SoftwareSecurityModule::erase(const Handle& handle) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(handle);
  if (it == entries_.end()) return make_error(ErrorCode::invalid_key, "SSM key handle not found");
  secure_zero(it->second.ciphertext.data(), it->second.ciphertext.size());
  entries_.erase(it);
  return {};
}

void SoftwareSecurityModule::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& [_, entry] : entries_) secure_zero(entry.ciphertext.data(), entry.ciphertext.size());
  entries_.clear();
}

Result<Handle> SoftwareSecurityModule::store_secret(ObjectInfo info, ByteView secret) {
  info.handle = hex_encode(make_handle(info));
  Bytes nonce;
  Bytes tag;
  auto ciphertext = seal_secret(info, secret, nonce, tag);
  if (!ciphertext) return ciphertext.error();
  Entry entry{info, std::move(nonce), std::move(ciphertext).value(), std::move(tag)};
  std::lock_guard<std::mutex> lock(mutex_);
  entries_[entry.info.handle] = std::move(entry);
  return info.handle;
}

Result<Bytes> SoftwareSecurityModule::open_secret(const Entry& entry) const {
  if (master_.bytes.size() != kMasterKeyBytes) return make_error(ErrorCode::invalid_key, "SSM master key is invalid");
  auto seal_key = derive_seal_key(master_.bytes);
  if (seal_key.empty()) return make_error(ErrorCode::internal_error, "SSM seal key derivation failed");
  aead::Ciphertext sealed{entry.nonce, entry.ciphertext, entry.tag};
  auto aad = associated_data(entry.info);
  auto opened = aead::decrypt(aead::Algorithm::aes_256_gcm, seal_key, sealed, aad);
  secure_zero(seal_key.data(), seal_key.size());
  return opened;
}

Result<Bytes> SoftwareSecurityModule::seal_secret(const ObjectInfo& info, ByteView secret, Bytes& nonce, Bytes& tag) const {
  if (master_.bytes.size() != kMasterKeyBytes) return make_error(ErrorCode::invalid_key, "SSM master key is invalid");
  if (secret.empty()) return make_error(ErrorCode::invalid_key, "SSM refuses to seal empty private material");
  auto seal_key = derive_seal_key(master_.bytes);
  if (seal_key.empty()) return make_error(ErrorCode::internal_error, "SSM seal key derivation failed");
  auto rand_nonce = rng::random_bytes(12);
  if (!rand_nonce) {
    secure_zero(seal_key.data(), seal_key.size());
    return rand_nonce.error();
  }
  auto aad = associated_data(info);
  auto sealed = aead::encrypt_with_nonce(aead::Algorithm::aes_256_gcm, seal_key, rand_nonce.value(), secret, aad);
  secure_zero(seal_key.data(), seal_key.size());
  if (!sealed) return sealed.error();
  nonce = std::move(sealed.value().nonce);
  tag = std::move(sealed.value().tag);
  return std::move(sealed).value().data;
}

Bytes SoftwareSecurityModule::associated_data(const ObjectInfo& info) const {
  Bytes out;
  out.insert(out.end(), kMagic.begin(), kMagic.end());
  put_u16(out, kSsmVersion);
  put_string(out, info.handle);
  put_u16(out, static_cast<std::uint16_t>(info.type));
  put_u16(out, info.algorithm);
  put_u32(out, info.flags);
  put_u64(out, info.created_at);
  put_string(out, info.label);
  put_bytes(out, info.key_id);
  put_bytes(out, info.public_key);
  put_string(out, info.allowed_domain);
  put_u64(out, info.max_operations);
  return out;
}


Result<void> SoftwareSecurityModule::validate_operation(const Entry& entry, Operation operation, const std::string& domain) const {
  const bool active = entry.info.state == KeyState::active;
  const bool metadata_only = operation == Operation::public_export || operation == Operation::sealed_export;
  const bool exportable_retired = metadata_only && entry.info.state == KeyState::retired;
  if (!active && !exportable_retired) {
    return make_error(ErrorCode::invalid_key, std::string("SSM key is not active: ") + key_state_name(entry.info.state));
  }
  switch (operation) {
    case Operation::sign:
      if (entry.info.max_operations != 0 && entry.info.used_operations >= entry.info.max_operations) {
        return make_error(ErrorCode::authentication_failed, "SSM key operation limit reached");
      }
      if (!entry.info.allowed_domain.empty() && domain != entry.info.allowed_domain) {
        return make_error(ErrorCode::authentication_failed, "SSM signing domain is not allowed by key policy");
      }
      if (entry.info.type != ObjectType::sign || !has_flag(entry.info.flags, ObjectFlag::allow_sign)) {
        return make_error(ErrorCode::invalid_argument, "SSM object is not allowed to sign");
      }
      break;
    case Operation::decapsulate:
      if (entry.info.max_operations != 0 && entry.info.used_operations >= entry.info.max_operations) {
        return make_error(ErrorCode::authentication_failed, "SSM key operation limit reached");
      }
      if (entry.info.type != ObjectType::kem || !has_flag(entry.info.flags, ObjectFlag::allow_decapsulate)) {
        return make_error(ErrorCode::invalid_argument, "SSM object is not allowed to decapsulate");
      }
      break;
    case Operation::public_export:
      if (!has_flag(entry.info.flags, ObjectFlag::exportable_public)) {
        return make_error(ErrorCode::invalid_argument, "SSM public export is disabled for this key");
      }
      break;
    case Operation::sealed_export:
      if (!has_flag(entry.info.flags, ObjectFlag::exportable_sealed)) {
        return make_error(ErrorCode::invalid_argument, "SSM sealed export is disabled for this key");
      }
      break;
  }
  return {};
}

void SoftwareSecurityModule::record_operation(const Handle& handle) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = entries_.find(handle);
  if (it == entries_.end()) return;
  ++it->second.info.used_operations;
  it->second.info.last_used_at = key::unix_time_now();
}

Result<bool> verify_domain_signature(const sign::PublicKey& public_key, const Handle& handle, const std::string& domain, ByteView message, const sign::Signature& signature) {
  auto bound = domain_message(handle, static_cast<std::uint16_t>(public_key.algorithm), domain, message);
  if (!bound) return bound.error();
  return sign::verify(public_key, bound.value(), signature);
}

}  // namespace quantlib::ssm

namespace quantlib::ssm {
namespace {
std::string token_hash_hex(const std::string& token) {
  const Bytes raw(token.begin(), token.end());
  const auto digest = hash::sha256(raw);
  return hex_encode(ByteView(digest.data(), 16));
}

bool contains_string(const std::vector<std::string>& values, const std::string& value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

bool contains_handle(const std::vector<Handle>& values, const Handle& value) {
  return std::find(values.begin(), values.end(), value) != values.end();
}

Result<SessionToken> make_session_token() {
  auto raw = rng::random_bytes(32);
  if (!raw) return raw.error();
  return SessionToken{hex_encode(raw.value())};
}
}

bool has_session_permission(std::uint32_t permissions, SessionPermission permission) noexcept {
  const auto bit = static_cast<std::uint32_t>(permission);
  return (permissions & bit) == bit;
}

const char* session_permission_name(SessionPermission permission) noexcept {
  switch (permission) {
    case SessionPermission::none: return "none";
    case SessionPermission::sign: return "sign";
    case SessionPermission::decapsulate: return "decapsulate";
    case SessionPermission::export_public: return "export_public";
    case SessionPermission::generate_key: return "generate_key";
    case SessionPermission::change_policy: return "change_policy";
    case SessionPermission::erase_key: return "erase_key";
    case SessionPermission::export_sealed: return "export_sealed";
    case SessionPermission::import_sealed: return "import_sealed";
    case SessionPermission::admin: return "admin";
  }
  return "unknown";
}

SsmSessionManager::SsmSessionManager(SoftwareSecurityModule& ssm) : ssm_(ssm) {}

Result<SessionToken> SsmSessionManager::open_session(const SessionOptions& options) {
  if (options.ttl_seconds == 0) return make_error(ErrorCode::invalid_argument, "SSM session ttl must be non-zero");
  if (options.permissions == 0) return make_error(ErrorCode::invalid_argument, "SSM session needs at least one permission");
  auto token = make_session_token();
  if (!token) return token.error();
  const auto now = key::unix_time_now();
  SessionEntry entry{};
  entry.info.token_hash = token_hash_hex(token.value().value);
  entry.info.created_at = now;
  entry.info.expires_at = now + options.ttl_seconds;
  entry.info.permissions = options.permissions;
  entry.info.max_sign_operations = options.max_sign_operations;
  entry.info.max_decapsulate_operations = options.max_decapsulate_operations;
  entry.allowed_handles = options.allowed_handles;
  entry.allowed_domains = options.allowed_domains;
  std::lock_guard<std::mutex> lock(mutex_);
  sessions_[token.value().value] = std::move(entry);
  return token;
}

Result<void> SsmSessionManager::close_session(const SessionToken& token) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = sessions_.find(token.value);
  if (it == sessions_.end()) return make_error(ErrorCode::authentication_failed, "SSM session token not found");
  it->second.info.closed = true;
  return {};
}

Result<SessionInfo> SsmSessionManager::session_info(const SessionToken& token) const {
  std::lock_guard<std::mutex> lock(mutex_);
  auto it = sessions_.find(token.value);
  if (it == sessions_.end()) return make_error(ErrorCode::authentication_failed, "SSM session token not found");
  return it->second.info;
}

std::vector<SessionInfo> SsmSessionManager::list_sessions() const {
  std::lock_guard<std::mutex> lock(mutex_);
  std::vector<SessionInfo> out;
  out.reserve(sessions_.size());
  for (const auto& [_, entry] : sessions_) out.push_back(entry.info);
  std::sort(out.begin(), out.end(), [](const SessionInfo& a, const SessionInfo& b) { return a.created_at < b.created_at; });
  return out;
}

bool SsmSessionManager::allowed_handle(const SessionEntry& entry, const Handle& handle) const {
  return entry.allowed_handles.empty() || contains_handle(entry.allowed_handles, handle);
}

bool SsmSessionManager::allowed_domain(const SessionEntry& entry, const std::string& domain) const {
  return entry.allowed_domains.empty() || contains_string(entry.allowed_domains, domain);
}

Result<SsmSessionManager::SessionEntry*> SsmSessionManager::mutable_session(const SessionToken& token, SessionPermission permission, const Handle& handle, const std::string& domain) {
  auto it = sessions_.find(token.value);
  if (it == sessions_.end()) return make_error(ErrorCode::authentication_failed, "SSM session token not found");
  auto& entry = it->second;
  const auto now = key::unix_time_now();
  if (entry.info.closed) return make_error(ErrorCode::authentication_failed, "SSM session is closed");
  if (entry.info.expires_at <= now) {
    entry.info.closed = true;
    return make_error(ErrorCode::authentication_failed, "SSM session expired");
  }
  if (!has_session_permission(entry.info.permissions, permission)) return make_error(ErrorCode::authentication_failed, "SSM session permission denied");
  if (!handle.empty() && !allowed_handle(entry, handle)) return make_error(ErrorCode::authentication_failed, "SSM session handle denied");
  if (!domain.empty() && !allowed_domain(entry, domain)) return make_error(ErrorCode::authentication_failed, "SSM session domain denied");
  return &entry;
}

Result<const SsmSessionManager::SessionEntry*> SsmSessionManager::readonly_session(const SessionToken& token, SessionPermission permission, const Handle& handle, const std::string& domain) const {
  auto it = sessions_.find(token.value);
  if (it == sessions_.end()) return make_error(ErrorCode::authentication_failed, "SSM session token not found");
  const auto& entry = it->second;
  const auto now = key::unix_time_now();
  if (entry.info.closed) return make_error(ErrorCode::authentication_failed, "SSM session is closed");
  if (entry.info.expires_at <= now) return make_error(ErrorCode::authentication_failed, "SSM session expired");
  if (!has_session_permission(entry.info.permissions, permission)) return make_error(ErrorCode::authentication_failed, "SSM session permission denied");
  if (!handle.empty() && !allowed_handle(entry, handle)) return make_error(ErrorCode::authentication_failed, "SSM session handle denied");
  if (!domain.empty() && !allowed_domain(entry, domain)) return make_error(ErrorCode::authentication_failed, "SSM session domain denied");
  return &entry;
}

Result<sign::Signature> SsmSessionManager::sign_domain(const SessionToken& token, const Handle& handle, const std::string& domain, ByteView message) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto entry = mutable_session(token, SessionPermission::sign, handle, domain);
    if (!entry) return entry.error();
    if (entry.value()->info.max_sign_operations != 0 && entry.value()->info.sign_operations >= entry.value()->info.max_sign_operations) {
      return make_error(ErrorCode::authentication_failed, "SSM session sign operation limit reached");
    }
  }
  auto sig = ssm_.sign_domain(handle, domain, message);
  if (!sig) return sig.error();
  std::lock_guard<std::mutex> lock(mutex_);
  auto entry = mutable_session(token, SessionPermission::sign, handle, domain);
  if (!entry) return entry.error();
  ++entry.value()->info.sign_operations;
  return sig;
}

Result<Bytes> SsmSessionManager::decapsulate(const SessionToken& token, const Handle& handle, ByteView ciphertext) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto entry = mutable_session(token, SessionPermission::decapsulate, handle, {});
    if (!entry) return entry.error();
    if (entry.value()->info.max_decapsulate_operations != 0 && entry.value()->info.decapsulate_operations >= entry.value()->info.max_decapsulate_operations) {
      return make_error(ErrorCode::authentication_failed, "SSM session decapsulate operation limit reached");
    }
  }
  auto shared = ssm_.decapsulate(handle, ciphertext);
  if (!shared) return shared.error();
  std::lock_guard<std::mutex> lock(mutex_);
  auto entry = mutable_session(token, SessionPermission::decapsulate, handle, {});
  if (!entry) return entry.error();
  ++entry.value()->info.decapsulate_operations;
  return shared;
}

Result<Bytes> SsmSessionManager::public_key(const SessionToken& token, const Handle& handle) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto entry = mutable_session(token, SessionPermission::export_public, handle, {});
    if (!entry) return entry.error();
  }
  return ssm_.public_key(handle);
}

}  // namespace quantlib::ssm

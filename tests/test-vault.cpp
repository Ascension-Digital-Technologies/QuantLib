#include "quantlib/quantlib.hpp"
#include <cassert>
#include <cstdio>
#include <fstream>

namespace {
void test_vault_create_encode_decode() {
  auto vault = quantlib::vault::create_vault("correct horse battery staple", {.label = "test", .kdf_iterations = 10000});
  assert(vault);
  assert(vault.value().metadata.label == "test");
  auto encoded = quantlib::vault::encode_vault(vault.value(), "correct horse battery staple");
  assert(encoded);
  auto decoded = quantlib::vault::decode_vault(encoded.value(), "correct horse battery staple");
  assert(decoded);
  assert(decoded.value().metadata.vault_id == vault.value().metadata.vault_id);
  assert(decoded.value().master_key.bytes == vault.value().master_key.bytes);
  auto wrong = quantlib::vault::decode_vault(encoded.value(), "wrong password");
  assert(!wrong);
}

void test_vault_persists_ssm_objects() {
  auto vault = quantlib::vault::create_vault("pw", {.label = "objects", .kdf_iterations = 10000});
  assert(vault);
  quantlib::ssm::SoftwareSecurityModule module(vault.value().master_key);
  auto handle = module.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "signer"});
  assert(handle);
  auto collected = quantlib::vault::collect_from_ssm(vault.value().metadata, vault.value().master_key, module);
  assert(collected);
  assert(collected.value().objects.size() == 1);
  auto encoded = quantlib::vault::encode_vault(collected.value(), "pw");
  assert(encoded);
  auto decoded = quantlib::vault::decode_vault(encoded.value(), "pw");
  assert(decoded);
  auto opened = quantlib::vault::open_ssm(decoded.value());
  assert(opened);
  assert(opened.value()->contains(handle.value()));
  const quantlib::Bytes message{'h','i'};
  auto sig = opened.value()->sign_message(handle.value(), message);
  assert(sig);
}

void test_vault_tamper_rejected() {
  auto vault = quantlib::vault::create_vault("pw", {.label = "tamper", .kdf_iterations = 10000});
  assert(vault);
  auto encoded = quantlib::vault::encode_vault(vault.value(), "pw");
  assert(encoded);
  auto raw = encoded.value();
  raw[raw.size() / 2] ^= 0x01;
  auto decoded = quantlib::vault::decode_vault(raw, "pw");
  assert(!decoded);
}
void test_vault_kdf_metadata_and_rewrap() {
  auto infos = quantlib::vault::supported_kdfs();
  assert(infos.size() >= 3);
  assert(infos[0].available);
  assert(infos[0].name == std::string("pbkdf2-hmac-sha256"));
  auto parsed = quantlib::vault::parse_vault_kdf("argon2id");
  assert(parsed);
  auto unavailable = quantlib::vault::recommended_kdf_params(quantlib::vault::VaultKdf::argon2id);
  assert(!unavailable);

  auto vault = quantlib::vault::create_vault("pw", {.label = "kdf", .kdf_iterations = 10000});
  assert(vault);
  auto rewrapped = quantlib::vault::rewrap_vault_kdf(vault.value(), {quantlib::vault::VaultKdf::pbkdf2_hmac_sha256, 12000, 0, 1});
  assert(rewrapped);
  assert(rewrapped.value().metadata.kdf_iterations == 12000);
  auto encoded = quantlib::vault::encode_vault(rewrapped.value(), "pw");
  assert(encoded);
  auto file = quantlib::vault::decode_vault_file(encoded.value());
  assert(file);
  assert(file.value().metadata.kdf_iterations == 12000);
  assert(file.value().metadata.kdf_parallelism == 1);
  auto decoded = quantlib::vault::decode_vault(encoded.value(), "pw");
  assert(decoded);
  assert(decoded.value().master_key.bytes == vault.value().master_key.bytes);

  auto bad = quantlib::vault::create_vault("pw", {.label = "argon", .kdf = {quantlib::vault::VaultKdf::argon2id, 3, 65536, 1}});
  assert(!bad);
}

void test_vault_hardening_atomic_backup_anchor() {
  const std::string path = "quantlib-test-vault-hardening.avault";
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
  auto vault = quantlib::vault::create_vault("pw", {.label = "hardening", .kdf_iterations = 10000});
  assert(vault);
  auto saved = quantlib::vault::save_vault_atomic(path, vault.value(), "pw");
  assert(saved);
  quantlib::vault::VaultRecoveryReport report;
  auto loaded = quantlib::vault::load_vault(path, "pw", &report);
  assert(loaded);
  assert(report.primary_present);
  assert(report.primary_decodable);
  assert(report.selected == "primary");
  auto anchor = quantlib::vault::anchor_for(loaded.value());
  assert(anchor.generation >= 1);
  assert(anchor.audit_head.size() == quantlib::audit::kAuditHashBytes);
  auto ok_anchor = quantlib::vault::verify_anchor(loaded.value(), anchor);
  assert(ok_anchor);

  quantlib::ssm::SoftwareSecurityModule module(loaded.value().master_key);
  auto handle = module.generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = "backup-signer"});
  assert(handle);
  auto collected = quantlib::vault::collect_from_ssm(loaded.value().metadata, loaded.value().master_key, module);
  assert(collected);
  auto saved2 = quantlib::vault::save_vault_atomic(path, collected.value(), "pw");
  assert(saved2);
  auto loaded2 = quantlib::vault::load_vault(path, "pw", &report);
  assert(loaded2);
  { std::ifstream b(path + ".bak", std::ios::binary); assert(b.good()); }
  auto rollback_check = quantlib::vault::verify_anchor(loaded.value(), quantlib::vault::anchor_for(loaded2.value()));
  assert(!rollback_check);

  auto primary = quantlib::vault::encode_vault(loaded2.value(), "pw");
  assert(primary);
  auto corrupt = primary.value();
  corrupt[corrupt.size()/3] ^= 0x55;
  { std::ofstream f(path, std::ios::binary | std::ios::trunc); assert(f.good()); f.write(reinterpret_cast<const char*>(corrupt.data()), static_cast<std::streamsize>(corrupt.size())); assert(f.good()); }
  auto recovered = quantlib::vault::load_vault(path, "pw", &report);
  assert(recovered);
  assert(report.backup_decodable);
  assert(report.selected == "backup");
  std::remove(path.c_str());
  std::remove((path + ".bak").c_str());
}

}

int run_vault_tests() {
  test_vault_create_encode_decode();
  test_vault_persists_ssm_objects();
  test_vault_tamper_rejected();
  test_vault_kdf_metadata_and_rewrap();
  test_vault_hardening_atomic_backup_anchor();
  return 0;
}

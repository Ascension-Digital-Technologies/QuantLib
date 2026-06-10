#include "quantlib/quantlib.hpp"
#include <fstream>
#include <iostream>
#include <string>

namespace {

quantlib::Bytes read_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return {};
  return quantlib::Bytes(std::istreambuf_iterator<char>(in), {});
}

bool write_file(const std::string& path, quantlib::ByteView data) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) return false;
  out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  return static_cast<bool>(out);
}

void print_usage() {
  std::cerr << "usage:\n"
            << "  quantlib-ssm info\n"
            << "  quantlib-ssm init <vault-file> <passphrase> [label]\n"
            << "  quantlib-ssm inspect <vault-file>\n"
            << "  quantlib-ssm generate-ed25519 <vault-file> <passphrase> <label>\n"
            << "  quantlib-ssm list <vault-file> <passphrase>\n"
            << "  quantlib-ssm audit <vault-file>\n"
            << "  quantlib-ssm audit-verify <vault-file>\n"
            << "  quantlib-ssm session-sign <vault-file> <passphrase> <handle> <domain> <message>\n"
            << "  quantlib-ssm rotate <vault-file> <passphrase> <handle> [label] [reason]\n"
            << "  quantlib-ssm recover <vault-file> <passphrase>\n"
            << "  quantlib-ssm kdf-info\n"
            << "  quantlib-ssm kdf-rewrap <vault-file> <passphrase> <iterations>\n";
}

int command_info() {
  std::cout << "quantlib-ssm: Software Security Module vault tool\n";
  std::cout << "  vault_version: " << quantlib::vault::kVaultVersion << "\n";
  std::cout << "  kdf: " << quantlib::vault::vault_kdf_name() << "\n";
  std::cout << "  default_iterations: " << quantlib::vault::kDefaultKdfIterations << "\n";
  std::cout << "  recommended_iterations: " << quantlib::vault::kRecommendedKdfIterations << "\n";
  std::cout << "  master_key_bytes: " << quantlib::ssm::kMasterKeyBytes << "\n";
  std::cout << "  sealed_object_version: " << quantlib::ssm::kSsmVersion << "\n";
  std::cout << "  safety: encrypted vault, sealed SSM objects, handle-only private-key operations, hash-chained audit log, short-lived sessions, key rotation, atomic vault save/recovery\n";
  return 0;
}

int command_init(int argc, char** argv) {
  if (argc < 4) { print_usage(); return 1; }
  const std::string path = argv[2];
  const std::string passphrase = argv[3];
  quantlib::vault::VaultOptions options;
  if (argc >= 5) options.label = argv[4];
  auto vault = quantlib::vault::create_vault(passphrase, options);
  if (!vault) { std::cerr << "init error: " << vault.error().message << "\n"; return 2; }
  auto saved = quantlib::vault::save_vault_atomic(path, vault.value(), passphrase);
  if (!saved) { std::cerr << "save error: " << saved.error().message << "\n"; return 2; }
  std::cout << "vault initialized: " << path << "\n";
  std::cout << "  id: " << vault.value().metadata.vault_id << "\n";
  std::cout << "  label: " << vault.value().metadata.label << "\n";
  return 0;
}

int command_inspect(int argc, char** argv) {
  if (argc < 3) { print_usage(); return 1; }
  const auto raw = read_file(argv[2]);
  if (raw.empty()) { std::cerr << "read error: " << argv[2] << "\n"; return 2; }
  auto file = quantlib::vault::decode_vault_file(raw);
  if (!file) { std::cerr << "inspect error: " << file.error().message << "\n"; return 2; }
  std::cout << "vault: " << file.value().metadata.vault_id << "\n";
  std::cout << "  label: " << file.value().metadata.label << "\n";
  std::cout << "  kdf: " << file.value().metadata.kdf << "\n";
  std::cout << "  iterations: " << file.value().metadata.kdf_iterations << "\n";
  std::cout << "  memory_kib: " << file.value().metadata.kdf_memory_kib << "\n";
  std::cout << "  parallelism: " << file.value().metadata.kdf_parallelism << "\n";
  std::cout << "  sealed_objects: " << file.value().sealed_objects.size() << "\n";
  std::cout << "  audit_bytes: " << file.value().audit_log.size() << "\n";
  return 0;
}

int command_generate_ed25519(int argc, char** argv) {
  if (argc < 5) { print_usage(); return 1; }
  const std::string path = argv[2];
  const std::string passphrase = argv[3];
  const std::string label = argv[4];
  const auto raw = read_file(path);
  if (raw.empty()) { std::cerr << "read error: " << path << "\n"; return 2; }
  auto unlocked = quantlib::vault::decode_vault(raw, passphrase);
  if (!unlocked) { std::cerr << "unlock error: " << unlocked.error().message << "\n"; return 2; }
  auto module = quantlib::vault::open_ssm(unlocked.value());
  if (!module) { std::cerr << "open error: " << module.error().message << "\n"; return 2; }
  auto handle = module.value()->generate_sign_key(quantlib::sign::Algorithm::ed25519, {.label = label});
  if (!handle) { std::cerr << "generate error: " << handle.error().message << "\n"; return 2; }
  auto collected = quantlib::vault::collect_from_ssm(unlocked.value().metadata, unlocked.value().master_key, *module.value());
  if (!collected) { std::cerr << "collect error: " << collected.error().message << "\n"; return 2; }
  collected.value().audit_log = unlocked.value().audit_log;
  auto audit_added = quantlib::vault::append_audit(collected.value(), quantlib::audit::EventType::key_generated, handle.value(), label);
  if (!audit_added) { std::cerr << "audit error: " << audit_added.error().message << "\n"; return 2; }
  auto saved = quantlib::vault::save_vault_atomic(path, collected.value(), passphrase);
  if (!saved) { std::cerr << "save error: " << saved.error().message << "\n"; return 2; }
  std::cout << "generated ed25519 key: " << handle.value() << "\n";
  return 0;
}

int command_list(int argc, char** argv) {
  if (argc < 4) { print_usage(); return 1; }
  const auto raw = read_file(argv[2]);
  if (raw.empty()) { std::cerr << "read error: " << argv[2] << "\n"; return 2; }
  auto unlocked = quantlib::vault::decode_vault(raw, argv[3]);
  if (!unlocked) { std::cerr << "unlock error: " << unlocked.error().message << "\n"; return 2; }
  auto module = quantlib::vault::open_ssm(unlocked.value());
  if (!module) { std::cerr << "open error: " << module.error().message << "\n"; return 2; }
  for (const auto& info : module.value()->list()) {
    std::cout << info.handle << " " << quantlib::ssm::object_type_name(info.type) << " " << quantlib::ssm::key_state_name(info.state)
              << " label=\"" << info.label << "\" used=" << info.used_operations;
    if (!info.rotation.replacement_handle.empty()) std::cout << " replaced_by=" << info.rotation.replacement_handle;
    if (!info.rotation.original_handle.empty()) std::cout << " replaces=" << info.rotation.original_handle;
    if (info.rotation.generation != 0) std::cout << " generation=" << info.rotation.generation;
    std::cout << "\n";
  }
  return 0;
}

int command_audit(int argc, char** argv) {
  if (argc < 3) { print_usage(); return 1; }
  const auto raw = read_file(argv[2]);
  if (raw.empty()) { std::cerr << "read error: " << argv[2] << "\n"; return 2; }
  auto file = quantlib::vault::decode_vault_file(raw);
  if (!file) { std::cerr << "audit error: " << file.error().message << "\n"; return 2; }
  auto log = quantlib::audit::decode_log(file.value().audit_log);
  if (!log) { std::cerr << "audit decode error: " << log.error().message << "\n"; return 2; }
  std::cout << "audit: events=" << log.value().events.size() << " head=" << quantlib::hex_encode(quantlib::audit::head_hash(log.value())) << "\n";
  for (const auto& e : log.value().events) {
    std::cout << "  #" << e.sequence << " " << quantlib::audit::event_type_name(e.type) << " subject=\"" << e.subject
              << "\" detail=\"" << e.detail << "\" hash=" << quantlib::hex_encode(quantlib::ByteView(e.event_hash.data(), 8)) << "...\n";
  }
  return 0;
}

int command_audit_verify(int argc, char** argv) {
  if (argc < 3) { print_usage(); return 1; }
  const auto raw = read_file(argv[2]);
  if (raw.empty()) { std::cerr << "read error: " << argv[2] << "\n"; return 2; }
  auto file = quantlib::vault::decode_vault_file(raw);
  if (!file) { std::cerr << "audit verify error: " << file.error().message << "\n"; return 2; }
  auto log = quantlib::audit::decode_log(file.value().audit_log);
  if (!log) { std::cerr << "audit verify error: " << log.error().message << "\n"; return 2; }
  auto verified = quantlib::audit::verify(log.value());
  if (!verified) { std::cerr << "audit verify error: " << verified.error().message << "\n"; return 2; }
  std::cout << "audit: verified events=" << log.value().events.size() << " head=" << quantlib::hex_encode(quantlib::audit::head_hash(log.value())) << "\n";
  return 0;
}


int command_session_sign(int argc, char** argv) {
  if (argc < 7) { print_usage(); return 1; }
  const std::string path = argv[2];
  const std::string passphrase = argv[3];
  const std::string handle = argv[4];
  const std::string domain = argv[5];
  const std::string message = argv[6];
  const auto raw = read_file(path);
  if (raw.empty()) { std::cerr << "read error: " << path << "\n"; return 2; }
  auto unlocked = quantlib::vault::decode_vault(raw, passphrase);
  if (!unlocked) { std::cerr << "unlock error: " << unlocked.error().message << "\n"; return 2; }
  auto module = quantlib::vault::open_ssm(unlocked.value());
  if (!module) { std::cerr << "open error: " << module.error().message << "\n"; return 2; }
  quantlib::ssm::SsmSessionManager sessions(*module.value());
  quantlib::ssm::SessionOptions options;
  options.permissions = static_cast<std::uint32_t>(quantlib::ssm::SessionPermission::sign);
  options.allowed_handles = {handle};
  options.allowed_domains = {domain};
  options.max_sign_operations = 1;
  auto token = sessions.open_session(options);
  if (!token) { std::cerr << "session error: " << token.error().message << "\n"; return 2; }
  auto added = quantlib::vault::append_audit(unlocked.value(), quantlib::audit::EventType::session_opened, "session", "domain=" + domain);
  if (!added) { std::cerr << "audit error: " << added.error().message << "\n"; return 2; }
  auto sig = sessions.sign_domain(token.value(), handle, domain, quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
  if (!sig) { std::cerr << "sign error: " << sig.error().message << "\n"; return 2; }
  auto closed = sessions.close_session(token.value());
  if (!closed) { std::cerr << "close error: " << closed.error().message << "\n"; return 2; }
  auto collected = quantlib::vault::collect_from_ssm(unlocked.value().metadata, unlocked.value().master_key, *module.value());
  if (!collected) { std::cerr << "collect error: " << collected.error().message << "\n"; return 2; }
  collected.value().audit_log = unlocked.value().audit_log;
  auto used = quantlib::vault::append_audit(collected.value(), quantlib::audit::EventType::key_used_sign, handle, domain);
  if (!used) { std::cerr << "audit error: " << used.error().message << "\n"; return 2; }
  auto closed_event = quantlib::vault::append_audit(collected.value(), quantlib::audit::EventType::session_closed, "session", "domain=" + domain);
  if (!closed_event) { std::cerr << "audit error: " << closed_event.error().message << "\n"; return 2; }
  auto saved = quantlib::vault::save_vault_atomic(path, collected.value(), passphrase);
  if (!saved) { std::cerr << "save error: " << saved.error().message << "\n"; return 2; }
  std::cout << "session signed: " << handle << "\n";
  std::cout << "  domain: " << domain << "\n";
  std::cout << "  signature: " << quantlib::hex_encode(sig.value().bytes) << "\n";
  return 0;
}


int command_rotate(int argc, char** argv) {
  if (argc < 5) { print_usage(); return 1; }
  const std::string path = argv[2];
  const std::string passphrase = argv[3];
  const std::string handle = argv[4];
  const std::string label = argc >= 6 ? argv[5] : std::string{};
  const std::string reason = argc >= 7 ? argv[6] : std::string{"scheduled_rotation"};
  const auto raw = read_file(path);
  if (raw.empty()) { std::cerr << "read error: " << path << "\n"; return 2; }
  auto unlocked = quantlib::vault::decode_vault(raw, passphrase);
  if (!unlocked) { std::cerr << "unlock error: " << unlocked.error().message << "\n"; return 2; }
  auto module = quantlib::vault::open_ssm(unlocked.value());
  if (!module) { std::cerr << "open error: " << module.error().message << "\n"; return 2; }
  auto rotated = module.value()->rotate_key(handle, {.label = label, .reason = reason, .retire_old = true});
  if (!rotated) { std::cerr << "rotate error: " << rotated.error().message << "\n"; return 2; }
  auto collected = quantlib::vault::collect_from_ssm(unlocked.value().metadata, unlocked.value().master_key, *module.value());
  if (!collected) { std::cerr << "collect error: " << collected.error().message << "\n"; return 2; }
  collected.value().audit_log = unlocked.value().audit_log;
  auto audit_rotated = quantlib::vault::append_audit(collected.value(), quantlib::audit::EventType::key_rotated, handle, "new=" + rotated.value().new_handle + " reason=" + reason);
  if (!audit_rotated) { std::cerr << "audit error: " << audit_rotated.error().message << "\n"; return 2; }
  auto audit_retired = quantlib::vault::append_audit(collected.value(), quantlib::audit::EventType::key_retired, handle, "replaced_by=" + rotated.value().new_handle);
  if (!audit_retired) { std::cerr << "audit error: " << audit_retired.error().message << "\n"; return 2; }
  auto saved = quantlib::vault::save_vault_atomic(path, collected.value(), passphrase);
  if (!saved) { std::cerr << "save error: " << saved.error().message << "\n"; return 2; }
  std::cout << "rotated key: " << handle << "\n";
  std::cout << "  new_handle: " << rotated.value().new_handle << "\n";
  std::cout << "  old_state: " << quantlib::ssm::key_state_name(rotated.value().old_info.state) << "\n";
  std::cout << "  generation: " << rotated.value().new_info.rotation.generation << "\n";
  std::cout << "  reason: " << reason << "\n";
  return 0;
}

}  // namespace

int command_kdf_info() {
  std::cout << "vault KDF providers:\n";
  for (const auto& info : quantlib::vault::supported_kdfs()) {
    std::cout << "  " << info.name << " [" << (info.available ? "available" : "unavailable") << "]"
              << " memory_hard=" << (info.memory_hard ? "yes" : "no")
              << " iterations=" << info.iterations
              << " memory_kib=" << info.memory_kib
              << " parallelism=" << info.parallelism << "\n";
    if (!info.notes.empty()) std::cout << "    " << info.notes << "\n";
  }
  return 0;
}

int command_kdf_rewrap(int argc, char** argv) {
  if (argc < 5) { print_usage(); return 1; }
  const std::string path = argv[2];
  const std::string passphrase = argv[3];
  const auto iterations = static_cast<std::uint32_t>(std::stoul(argv[4]));
  const auto raw = read_file(path);
  if (raw.empty()) { std::cerr << "read error: " << path << "\n"; return 2; }
  auto unlocked = quantlib::vault::decode_vault(raw, passphrase);
  if (!unlocked) { std::cerr << "unlock error: " << unlocked.error().message << "\n"; return 2; }
  auto rewrapped = quantlib::vault::rewrap_vault_kdf(unlocked.value(), {quantlib::vault::VaultKdf::pbkdf2_hmac_sha256, iterations, 0, 1});
  if (!rewrapped) { std::cerr << "rewrap error: " << rewrapped.error().message << "\n"; return 2; }
  auto saved = quantlib::vault::save_vault_atomic(path, rewrapped.value(), passphrase);
  if (!saved) { std::cerr << "save error: " << saved.error().message << "\n"; return 2; }
  std::cout << "vault KDF rewrapped: " << path << "\n";
  std::cout << "  kdf: " << rewrapped.value().metadata.kdf << "\n";
  std::cout << "  iterations: " << rewrapped.value().metadata.kdf_iterations << "\n";
  return 0;
}

int command_recover(int argc, char** argv) {
  if (argc < 4) { print_usage(); return 1; }
  quantlib::vault::VaultRecoveryReport report;
  auto vault = quantlib::vault::load_vault(argv[2], argv[3], &report);
  if (!vault) {
    std::cerr << "recover error: " << vault.error().message << "\n";
    std::cerr << "  primary_present=" << (report.primary_present ? "yes" : "no")
              << " primary_decodable=" << (report.primary_decodable ? "yes" : "no")
              << " backup_present=" << (report.backup_present ? "yes" : "no")
              << " backup_decodable=" << (report.backup_decodable ? "yes" : "no") << "\n";
    return 2;
  }
  auto anchor = quantlib::vault::anchor_for(vault.value());
  std::cout << "vault recovered: " << report.selected << "\n";
  std::cout << "  id: " << vault.value().metadata.vault_id << "\n";
  std::cout << "  generation: " << anchor.generation << "\n";
  std::cout << "  audit_head: " << quantlib::hex_encode(anchor.audit_head) << "\n";
  std::cout << "  detail: " << report.detail << "\n";
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 2) { print_usage(); return 1; }
  const std::string cmd = argv[1];
  if (cmd == "info") return command_info();
  if (cmd == "init") return command_init(argc, argv);
  if (cmd == "inspect") return command_inspect(argc, argv);
  if (cmd == "generate-ed25519") return command_generate_ed25519(argc, argv);
  if (cmd == "list") return command_list(argc, argv);
  if (cmd == "audit") return command_audit(argc, argv);
  if (cmd == "audit-verify") return command_audit_verify(argc, argv);
  if (cmd == "session-sign") return command_session_sign(argc, argv);
  if (cmd == "rotate") return command_rotate(argc, argv);
  if (cmd == "recover") return command_recover(argc, argv);
  if (cmd == "kdf-info") return command_kdf_info();
  if (cmd == "kdf-rewrap") return command_kdf_rewrap(argc, argv);
  print_usage();
  return 1;
}

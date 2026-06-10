#include "quantlib/selftest.hpp"
#include "quantlib/quantlib.hpp"
#include <algorithm>

namespace quantlib::selftest {
namespace {
void add(Report& report, std::string name, bool passed, std::string detail = {}) {
  report.checks.push_back(CheckResult{std::move(name), passed, std::move(detail)});
}

Bytes from_ascii(const char* text) {
  Bytes out;
  while (*text) out.push_back(static_cast<std::uint8_t>(*text++));
  return out;
}

void check_sha256(Report& report) {
  const auto got = hash::sha256(from_ascii("abc"));
  const auto expected = hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  add(report, "sha256-known-answer", got == expected, hex_encode(got));
}

void check_hkdf(Report& report) {
  const Bytes ikm(22, 0x0b);
  const Bytes salt = hex_decode("000102030405060708090a0b0c");
  const Bytes info = hex_decode("f0f1f2f3f4f5f6f7f8f9");
  const auto got = kdf::hkdf_sha256(ikm, salt, info, 42);
  const auto expected = hex_decode("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  add(report, "hkdf-sha256-rfc5869", got.ok() && got.value() == expected, got.ok() ? hex_encode(got.value()) : got.error().message);
}

void check_key_blob(Report& report) {
  key::KeyBlob blob;
  blob.version = 1;
  blob.algorithm = 0x0101;
  blob.purpose = key::Purpose::symmetric;
  blob.flags = static_cast<std::uint32_t>(key::Flags::exportable_key);
  blob.created_at = 1;
  blob.payload = Bytes(32, 0x42);
  blob.key_id = key::key_id(blob.payload);
  auto encoded = key::encode(blob);
  if (!encoded) {
    add(report, "key-blob-roundtrip", false, encoded.error().message);
    return;
  }
  auto decoded = key::decode(encoded.value());
  const bool ok = decoded.ok() && decoded.value().version == blob.version && decoded.value().algorithm == blob.algorithm &&
                  decoded.value().purpose == blob.purpose && decoded.value().payload == blob.payload && decoded.value().key_id == blob.key_id;
  add(report, "key-blob-roundtrip", ok, ok ? "versioned blob accepted" : (decoded.ok() ? "mismatched decoded blob" : decoded.error().message));

  auto tampered = encoded.value();
  if (!tampered.empty()) tampered[tampered.size() / 2] ^= 0x01;
  auto rejected = key::decode(tampered);
  add(report, "key-blob-tamper-reject", !rejected.ok(), rejected.ok() ? "tampered blob accepted" : rejected.error().message);
}

void check_transcript(Report& report) {
  transcript::Transcript t1("QuantLib SelfTest v1");
  transcript::Transcript t2("QuantLib SelfTest v1");
  transcript::Transcript t3("QuantLib SelfTest v1");
  const Bytes field_a{1, 2, 3};
  const Bytes field_b{1, 2, 4};
  const bool ok = t1.append("field", field_a).ok() && t2.append("field", field_a).ok() && t3.append("field", field_b).ok();
  const auto d1 = t1.digest();
  const auto d2 = t2.digest();
  const auto d3 = t3.digest();
  add(report, "transcript-deterministic", ok && d1 == d2 && d1 != d3, ok ? hex_encode(d1) : "append failed");
}

void check_session_record_channel(Report& report) {
  const Bytes client_nonce(12, 0x11);
  const Bytes server_nonce(12, 0x22);
  const Bytes transcript_hash(32, 0x33);
  const Bytes shared_secret(32, 0x44);
  const Bytes context{0x0a, 0x0b};
  const Bytes aad{0x01};
  const Bytes plaintext{'p', 'i', 'n', 'g'};

  auto hello = session::make_hello(client_nonce, server_nonce, transcript_hash);
  if (!hello) { add(report, "channel-roundtrip", false, hello.error().message); return; }
  auto hs = session::derive_handshake_secret(shared_secret, hello.value());
  if (!hs) { add(report, "channel-roundtrip", false, hs.error().message); return; }
  auto material = session::derive_keys(hs.value(), hello.value());
  if (!material) { add(report, "channel-roundtrip", false, material.error().message); return; }

  channel::ChannelConfig config;
  config.algorithm = aead::Algorithm::chacha20_poly1305;
  config.associated_context = context;
  auto client = channel::make_channel(material.value(), session::Role::client);
  auto server = channel::make_channel(material.value(), session::Role::server);
  if (!client || !server) { add(report, "channel-roundtrip", false, "channel creation failed"); return; }
  auto sealed = channel::seal_data(client.value(), config, plaintext, aad);
  if (!sealed) { add(report, "channel-roundtrip", false, sealed.error().message); return; }
  auto opened = channel::open(server.value(), config, sealed.value(), aad);
  const bool roundtrip = opened.ok() && opened.value().plaintext == plaintext;
  add(report, "channel-roundtrip", roundtrip, roundtrip ? "encrypted record opened" : (opened.ok() ? "plaintext mismatch" : opened.error().message));
  auto replayed = channel::open(server.value(), config, sealed.value(), aad);
  add(report, "channel-replay-reject", !replayed.ok(), replayed.ok() ? "duplicate accepted" : replayed.error().message);
}

void check_ssm_policy(Report& report) {
  auto master = ssm::generate_master_key();
  if (!master) { add(report, "ssm-policy", false, master.error().message); return; }
  ssm::SoftwareSecurityModule module(std::move(master).value());
  ssm::CreateOptions options;
  options.allowed_domain = "selftest.sign";
  options.max_operations = 1;
  auto handle = module.generate_sign_key(sign::Algorithm::ed25519, options);
  if (!handle) { add(report, "ssm-policy", false, handle.error().message); return; }
  const Bytes message{'o','k'};
  auto sig = module.sign_domain(handle.value(), "selftest.sign", message);
  auto denied_domain = module.sign_domain(handle.value(), "wrong.domain", message);
  auto denied_limit = module.sign_domain(handle.value(), "selftest.sign", message);
  auto info = module.info(handle.value());
  const bool ok = sig.ok() && !denied_domain.ok() && !denied_limit.ok() && info.ok() && info.value().used_operations == 1;
  add(report, "ssm-policy-domain-limit", ok, ok ? "domain and operation limit enforced" : "SSM policy enforcement failed");
}



void check_ssm_session(Report& report) {
  auto master = ssm::generate_master_key();
  if (!master) { add(report, "ssm-session", false, master.error().message); return; }
  ssm::SoftwareSecurityModule module(std::move(master).value());
  auto handle = module.generate_sign_key(sign::Algorithm::ed25519, {.label = "session-key", .allowed_domain = "selftest.session"});
  if (!handle) { add(report, "ssm-session", false, handle.error().message); return; }
  ssm::SsmSessionManager sessions(module);
  ssm::SessionOptions options;
  options.allowed_handles = {handle.value()};
  options.allowed_domains = {"selftest.session"};
  options.max_sign_operations = 1;
  auto token = sessions.open_session(options);
  if (!token) { add(report, "ssm-session", false, token.error().message); return; }
  const Bytes message{'s','e','s','s'};
  auto sig = sessions.sign_domain(token.value(), handle.value(), "selftest.session", message);
  auto wrong_domain = sessions.sign_domain(token.value(), handle.value(), "wrong.session", message);
  auto over_limit = sessions.sign_domain(token.value(), handle.value(), "selftest.session", message);
  auto closed = sessions.close_session(token.value());
  auto after_close = sessions.public_key(token.value(), handle.value());
  const bool ok = sig.ok() && !wrong_domain.ok() && !over_limit.ok() && closed.ok() && !after_close.ok();
  add(report, "ssm-session-access-control", ok, ok ? "session domain, limit, and close enforced" : "SSM session enforcement failed");
}


void check_ssm_rotation(Report& report) {
  auto master = ssm::generate_master_key();
  if (!master) { add(report, "ssm-rotation", false, master.error().message); return; }
  ssm::SoftwareSecurityModule module(std::move(master).value());
  auto old_handle = module.generate_sign_key(sign::Algorithm::ed25519, {.label = "rotate-old", .allowed_domain = "selftest.rotate"});
  if (!old_handle) { add(report, "ssm-rotation", false, old_handle.error().message); return; }
  auto rotated = module.rotate_key(old_handle.value(), {.label = "rotate-new", .reason = "selftest_rotation", .retire_old = true});
  if (!rotated) { add(report, "ssm-rotation", false, rotated.error().message); return; }
  const Bytes message{'r','o','t','a','t','e'};
  auto old_sig = module.sign_domain(old_handle.value(), "selftest.rotate", message);
  auto new_sig = module.sign_domain(rotated.value().new_handle, "selftest.rotate", message);
  auto old_info = module.info(old_handle.value());
  auto new_info = module.info(rotated.value().new_handle);
  const bool ok = !old_sig.ok() && new_sig.ok() && old_info.ok() && new_info.ok() &&
                  old_info.value().state == ssm::KeyState::retired &&
                  old_info.value().rotation.replacement_handle == rotated.value().new_handle &&
                  new_info.value().rotation.original_handle == old_handle.value() &&
                  new_info.value().rotation.generation == old_info.value().rotation.generation;
  add(report, "ssm-key-rotation", ok, ok ? "replacement handle linked and old key retired" : "SSM rotation failed");
}

void check_audit(Report& report) {
  audit::AuditLog log;
  auto a = audit::append(log, audit::EventType::vault_created, "selftest-vault", "created");
  auto b = audit::append(log, audit::EventType::key_generated, "selftest-key", "ed25519");
  auto encoded = audit::encode_log(log);
  auto decoded = encoded ? audit::decode_log(encoded.value()) : Result<audit::AuditLog>(encoded.error());
  auto tampered = log;
  if (!tampered.events.empty()) tampered.events[0].detail = "tampered";
  const bool ok = a.ok() && b.ok() && encoded.ok() && decoded.ok() && audit::verify(decoded.value()).ok() && !audit::verify(tampered).ok();
  add(report, "audit-hash-chain", ok, ok ? "hash chain verifies and rejects tamper" : "audit chain check failed");
}

void check_vault_roundtrip(Report& report) {
  auto vault = vault::create_vault("selftest-passphrase", {.label = "selftest", .kdf_iterations = 10000});
  if (!vault) { add(report, "vault-roundtrip", false, vault.error().message); return; }
  ssm::SoftwareSecurityModule module(vault.value().master_key);
  auto handle = module.generate_sign_key(sign::Algorithm::ed25519, {.label = "selftest-key"});
  if (!handle) { add(report, "vault-roundtrip", false, handle.error().message); return; }
  auto collected = vault::collect_from_ssm(vault.value().metadata, vault.value().master_key, module);
  if (!collected) { add(report, "vault-roundtrip", false, collected.error().message); return; }
  auto encoded = vault::encode_vault(collected.value(), "selftest-passphrase");
  if (!encoded) { add(report, "vault-roundtrip", false, encoded.error().message); return; }
  auto decoded = vault::decode_vault(encoded.value(), "selftest-passphrase");
  auto wrong = vault::decode_vault(encoded.value(), "wrong-passphrase");
  const bool ok = decoded.ok() && decoded.value().objects.size() == 1 && !wrong.ok();
  add(report, "vault-roundtrip", ok, ok ? "vault locks, unlocks, and rejects wrong passphrase" : "vault roundtrip failed");
}

void check_vault_kdf(Report& report) {
  const auto infos = vault::supported_kdfs();
  const bool has_builtin = !infos.empty() && infos[0].available && infos[0].name == "pbkdf2-hmac-sha256";
  const auto argon = vault::recommended_kdf_params(vault::VaultKdf::argon2id);
  auto v = vault::create_vault("selftest-kdf", {.label = "kdf", .kdf_iterations = 10000});
  auto r = v ? vault::rewrap_vault_kdf(v.value(), {vault::VaultKdf::pbkdf2_hmac_sha256, 12000, 0, 1}) : Result<vault::UnlockedVault>(v.error());
  const bool ok = has_builtin && !argon.ok() && r.ok() && r.value().metadata.kdf_iterations == 12000;
  add(report, "vault-kdf-policy", ok, ok ? "PBKDF2 compatibility plus Argon2id/scrypt provider gates" : "vault KDF policy failed");
}

void check_vault_hardening(Report& report) {
  auto v = vault::create_vault("selftest-hardening", {.label = "hardening", .kdf_iterations = 10000});
  if (!v) { add(report, "vault-hardening", false, v.error().message); return; }
  auto encoded = vault::encode_vault(v.value(), "selftest-hardening");
  if (!encoded) { add(report, "vault-hardening", false, encoded.error().message); return; }
  auto decoded = vault::decode_vault(encoded.value(), "selftest-hardening");
  if (!decoded) { add(report, "vault-hardening", false, decoded.error().message); return; }
  auto anchor = vault::anchor_for(decoded.value());
  auto verified = vault::verify_anchor(decoded.value(), anchor);
  auto old = decoded.value();
  auto newer = decoded.value();
  newer.metadata.generation = old.metadata.generation + 1;
  auto rollback = vault::verify_anchor(old, vault::anchor_for(newer));
  auto file = vault::decode_vault_file(encoded.value());
  const bool ok = verified.ok() && !rollback.ok() && file.ok() && file.value().audit_head.size() == audit::kAuditHashBytes && file.value().metadata.generation > 0;
  add(report, "vault-hardening", ok, ok ? "generation anchors and audit head verification active" : "vault hardening check failed");
}

void check_secure_memory(Report& report) {
  const auto status = secure_memory_status();
  auto locked = LockedBytes::allocate(32);
  const bool ok = !status.backend.empty() && locked.ok() && locked.value().size() == 32;
  if (locked) locked.value().data()[0] = 0x5a;
  add(report, "secure-memory-status", ok, ok ? status.backend : "secure memory allocation failed");
}


void check_pq_provider_gate(Report& report) {
  const auto status = pq::backend_status();
  const auto sizes = pq::validate_algorithm_sizes();
  const auto wiring = pq::validate_provider_wiring();
  const auto kat = pq::run_kat_harness();
  const auto downgrade = pq::reject_downgrade(
      static_cast<std::uint16_t>(kem::Algorithm::ml_kem_1024),
      static_cast<std::uint16_t>(kem::Algorithm::ml_kem_768));
  const bool ok = !status.name.empty() && sizes.ok() && wiring.ok() && kat.vectors_planned >= 7 && !downgrade.ok();
  add(report, "pq-provider-gate", ok, ok ? "metadata, KAT harness, and downgrade guard present" : "PQ provider gate failed");
}

void check_protocol_stack(Report& report) {
  protocol::NegotiationInput input;
  input.policy = policy::make_policy(policy::Profile::fast);
  auto negotiated = protocol::negotiate(input, {0x0102, 0x0101});
  auto downgrade = protocol::reject_downgrade({0x0103, 0x0101}, *protocol::find_suite(0x0101, protocol::default_cipher_suites()));
  auto hello = session::make_hello(Bytes(12, 0x01), Bytes(12, 0x02), Bytes(32, 0x03));
  protocol::HandshakeContext client;
  client.role = session::Role::client;
  auto sent = protocol::mark_sent(client, record::ContentType::handshake);
  auto limits_ok = protocol::validate_plaintext_limits(Bytes{1,2,3,4}, protocol::HandshakeLimits{});
  protocol::HandshakeLimits tight;
  tight.max_record_plaintext = 4;
  auto limits_bad = protocol::validate_plaintext_limits(Bytes{1,2,3,4,5}, tight);
  const bool ok = negotiated.ok() && !downgrade.ok() && hello.ok() && sent.ok() &&
                  client.state == protocol::HandshakeState::client_hello_sent && limits_ok.ok() && !limits_bad.ok();
  add(report, "protocol-production-stack", ok, ok ? "suite negotiation, downgrade guard, state transitions, and limits active" : "protocol stack check failed");
}

void check_testing_system(Report& report) {
  const auto readiness = testing::readiness_report();
  const bool ok = readiness.passed() && readiness.fuzz_targets.size() >= 2 && !readiness.performance_budgets.empty();
  add(report, "test-fuzz-ci-system", ok, ok ? "sanitizer, coverage, fuzz, CI matrix, package-check, and performance budgets active" : "test/fuzz/CI readiness failed");
}

void check_release_manifest(Report& report) {
  const auto headers = release::stable_headers();
  const auto experimental = release::experimental_modules();
  const auto inventory = release::provider_inventory();
  const bool ok = std::find(headers.begin(), headers.end(), std::string("release.hpp")) != headers.end() &&
                  !experimental.empty() && inventory.size() >= 3;
  add(report, "release-manifest", ok, ok ? "stable API, experimental boundary, provider inventory present" : "release manifest incomplete");
}


void check_throughput_engine(Report& report) {
  std::vector<Bytes> messages(128, Bytes(32, 0x25));
  throughput::EngineOptions opts{};
  opts.min_parallel_items = 2;
  opts.target_chunk_items = 16;
  const auto r = throughput::sha256_parallel(messages, opts);
  const bool ok = r.ok() && r.value().digests.size() == messages.size() &&
                  r.value().digests[0] == hash::sha256(messages[0]) &&
                  r.value().report.zero_copy_input;
  add(report, "throughput-engine", ok, ok ? "zero-copy batch views and parallel hash scheduler active" : "throughput engine check failed");
}


void check_simd_engine(Report& report) {
  const auto f = cpu::detect();
  const auto table = simd::dispatch_table(f);
  const Bytes msg{'s','i','m','d'};
  const bool ok = f.logical_threads >= 1 && !table.backends.empty() &&
                  simd::sha256_dispatch(msg) == hash::sha256(msg) &&
                  simd::sha256_avx2(msg) == hash::sha256(msg) &&
                  simd::sha256_avx512(msg) == hash::sha256(msg) &&
                  simd::sha256_shani(msg) == hash::sha256(msg);
  add(report, "simd-engine", ok, ok ? cpu::summary(f) : "SIMD dispatch/equivalence check failed");
}

void check_v2_production_baseline(Report& report) {
  // Do not call run_release_gate() here because the release gate itself runs the self-test.
  // This check validates the v2 production baseline metadata directly and avoids recursion.
  const auto artifacts = release::required_release_artifacts();
  const auto docs = release::security_document_set();
  const auto boundary = release::production_boundary();
  const auto sbom = release::sbom_components();
  const bool ok = artifacts.size() >= 7 && docs.size() >= 8 &&
                  !boundary.production_ready.empty() && !boundary.provider_dependent.empty() &&
                  !boundary.explicitly_not_claimed.empty() && sbom.size() >= 4;
  add(report, "v2-production-baseline", ok, ok ? "release artifacts, SBOM, security docs, and production boundary declared" : "v2 production baseline incomplete");
}

void check_ops_deployment(Report& report) {
  const auto server = ops::validate_deployment(ops::default_profile(ops::DeploymentTarget::server));
  const auto profiles = ops::deployment_profiles();
  const auto runbook = ops::operator_runbook();
  const bool ok = server.passed() && profiles.size() >= 6 && runbook.size() >= 8 && !ops::config_templates().empty();
  add(report, "ops-deployment-readiness", ok, ok ? "deployment profiles, runbook, templates, and validation active" : "ops deployment readiness failed");
}

void check_policy(Report& report) {
  const auto balanced = policy::make_policy(policy::Profile::balanced);
  const bool accepts_hybrid = policy::validate_kem(kem::Algorithm::hybrid_x25519_ml_kem_768, balanced).ok();
  const bool rejects_low = !policy::validate_kem(kem::Algorithm::x25519, balanced).ok();
  add(report, "policy-balanced-kem", accepts_hybrid && rejects_low, policy::describe(balanced));
}
}  // namespace

bool Report::passed() const noexcept {
  return std::all_of(checks.begin(), checks.end(), [](const CheckResult& check) { return check.passed; });
}

std::size_t Report::passed_count() const noexcept {
  return static_cast<std::size_t>(std::count_if(checks.begin(), checks.end(), [](const CheckResult& check) { return check.passed; }));
}

std::size_t Report::failed_count() const noexcept { return checks.size() - passed_count(); }

Report run() {
  Report report;
  report.library_version = kVersion;
  check_sha256(report);
  check_hkdf(report);
  check_key_blob(report);
  check_transcript(report);
  check_session_record_channel(report);
  check_ssm_policy(report);
  check_ssm_session(report);
  check_ssm_rotation(report);
  check_audit(report);
  check_vault_roundtrip(report);
  check_vault_kdf(report);
  check_vault_hardening(report);
  check_policy(report);
  check_pq_provider_gate(report);
  check_secure_memory(report);
  check_release_manifest(report);
  check_protocol_stack(report);
  check_testing_system(report);
  check_v2_production_baseline(report);
  check_ops_deployment(report);
  check_throughput_engine(report);
  check_simd_engine(report);
  return report;
}

Result<void> require_pass() {
  const auto report = run();
  if (!report.passed()) return make_error(ErrorCode::internal_error, "self-test failed");
  return {};
}

}  // namespace quantlib::selftest

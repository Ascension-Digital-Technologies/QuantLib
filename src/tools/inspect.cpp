#include "quantlib/quantlib.hpp"
#include <iostream>
#include <string>

namespace {
void print_version() {
  std::cout << "QuantLib " << quantlib::kVersion << "\n";
}

void print_selftest() {
  const auto report = quantlib::selftest::run();
  std::cout << "selftest: " << (report.passed() ? "pass" : "fail") << "\n";
  std::cout << "  version: " << report.library_version << "\n";
  std::cout << "  passed: " << report.passed_count() << "\n";
  std::cout << "  failed: " << report.failed_count() << "\n";
  for (const auto& check : report.checks) {
    std::cout << "  " << (check.passed ? "[pass] " : "[fail] ") << check.name;
    if (!check.detail.empty()) std::cout << " - " << check.detail;
    std::cout << "\n";
  }
}

void print_providers() {
  for (const auto& provider : quantlib::provider::registered_providers()) {
    std::cout << provider.name << " [" << (provider.available ? "available" : "unavailable") << "] " << provider.version << "\n";
    std::cout << "  capabilities:";
    for (const auto cap : provider.capabilities) std::cout << " " << quantlib::provider::capability_name(cap);
    std::cout << "\n  algorithms:";
    for (const auto& algo : provider.algorithms) std::cout << " " << algo;
    std::cout << "\n";
  }
}


void print_pq() {
  std::cout << "PQ backend: " << quantlib::pq::backend_name() << " [" << (quantlib::pq::available() ? "available" : "unavailable") << "]\n";
  std::cout << "KEM algorithms:\n";
  for (const auto& algo : quantlib::pq::kem_algorithms()) {
    std::cout << "  " << algo.name << " level=" << algo.nist_security_level
              << " pk=" << algo.public_key_bytes << " sk=" << algo.secret_key_bytes
              << " ct=" << algo.ciphertext_bytes << " ss=" << algo.shared_secret_bytes
              << " supported=" << (algo.supported ? "yes" : "no") << "\n";
  }
  std::cout << "Signature algorithms:\n";
  for (const auto& algo : quantlib::pq::signature_algorithms()) {
    std::cout << "  " << algo.name << " level=" << algo.nist_security_level
              << " pk=" << algo.public_key_bytes << " sk=" << algo.secret_key_bytes
              << " sig=" << algo.signature_bytes
              << " supported=" << (algo.supported ? "yes" : "no") << "\n";
  }
}


void print_pq_provider() {
  const auto status = quantlib::pq::backend_status();
  std::cout << "pq-provider: QuantLib PQ Provider v1\n";
  std::cout << "  name: " << status.name << "\n";
  std::cout << "  version: " << status.version << "\n";
  std::cout << "  compile_time_enabled: " << (status.compile_time_enabled ? "yes" : "no") << "\n";
  std::cout << "  linked: " << (status.linked ? "yes" : "no") << "\n";
  std::cout << "  runtime_available: " << (status.runtime_available ? "yes" : "no") << "\n";
  std::cout << "  production_ready: " << (status.production_ready ? "yes" : "no") << "\n";
  std::cout << "  notes: " << status.notes << "\n";
  std::cout << "  downgrade_guard: reject lower NIST level inside the same PQ family\n";
  std::cout << "  hybrid_defaults: X25519+ML-KEM-768, Ed25519+ML-DSA-65\n";
}

void print_pq_kat() {
  const auto report = quantlib::pq::run_kat_harness();
  std::cout << "pq-kat: QuantLib PQ KAT Harness v1\n";
  std::cout << "  backend: " << report.backend << "\n";
  std::cout << "  provider_available: " << (report.provider_available ? "yes" : "no") << "\n";
  std::cout << "  vectors_planned: " << report.vectors_planned << "\n";
  std::cout << "  vectors_runnable: " << report.vectors_runnable << "\n";
  std::cout << "  vectors_passed: " << report.vectors_passed << "\n";
  std::cout << "  vectors_failed: " << report.vectors_failed << "\n";
  std::cout << "  planned_cases:\n";
  for (const auto& c : quantlib::pq::planned_kat_cases()) {
    std::cout << "    " << c.name << " pk=" << c.public_key_bytes << " sk=" << c.secret_key_bytes
              << " out=" << c.ciphertext_or_signature_bytes;
    if (c.shared_secret_bytes) std::cout << " ss=" << c.shared_secret_bytes;
    std::cout << "\n";
  }
}

void print_session() {
  std::cout << "session: QuantLib Session v1\n";
  std::cout << "  nonce_bytes: " << quantlib::session::kSessionNonceBytes << "\n";
  std::cout << "  key_bytes: " << quantlib::session::kSessionKeyBytes << "\n";
  std::cout << "  confirmation_bytes: " << quantlib::session::kConfirmationBytes << "\n";
  std::cout << "  features: transcript-bound handshake-secret client/server write-keys role-separated confirmation exporter-secret key-update\n";
}

void print_record() {
  std::cout << "record: QuantLib Record v1\n";
  std::cout << "  version: " << static_cast<int>(quantlib::record::kRecordVersion) << "\n";
  std::cout << "  header_bytes: " << static_cast<int>(quantlib::record::kRecordHeaderBytes) << "\n";
  std::cout << "  nonce_bytes: " << quantlib::session::kSessionNonceBytes << "\n";
  std::cout << "  tag_bytes: 16\n";
  std::cout << "  sequence_nonce: base-nonce-xor-uint64-sequence\n";
  std::cout << "  aad: transcript-bound header plus caller associated data\n";
  std::cout << "  content_types: data handshake alert key_update\n";
  std::cout << "  alerts: close_notify unexpected_message bad_record_mac protocol_error key_update_required\n";
}

void print_replay() {
  std::cout << "replay: QuantLib Replay Window v1\n";
  std::cout << "  window_bits: " << quantlib::replay::kDefaultWindowBits << "\n";
  std::cout << "  features: duplicate-reject out-of-window-reject out-of-order-accept resettable\n";
}

void print_audit() {
  std::cout << "audit: QuantLib Audit Log v1\n";
  std::cout << "  version: " << quantlib::audit::kAuditVersion << "\n";
  std::cout << "  hash_bytes: " << quantlib::audit::kAuditHashBytes << "\n";
  std::cout << "  chain: event_hash = SHA256(canonical_event_without_hash)\n";
  std::cout << "  genesis: domain-separated QuantLib audit genesis hash\n";
  std::cout << "  events: vault_created vault_unlocked key_generated key_used_sign key_used_decapsulate key_erased policy_changed failed_unlock tamper_rejected vault_saved vault_loaded session_opened session_closed session_expired session_denied session_permission_denied session_operation_limit_hit key_rotated key_retired key_marked_compromised\n";
  std::cout << "  safety: monotonic sequence, previous-hash link, tamper verification, vault persistence\n";
}

void print_vault() {
  std::cout << "vault: QuantLib Vault v5\n";
  std::cout << "  version: " << quantlib::vault::kVaultVersion << "\n";
  std::cout << "  file_magic: AVAULT1\n";
  std::cout << "  kdf: " << quantlib::vault::vault_kdf_name() << "\n";
  std::cout << "  default_iterations: " << quantlib::vault::kDefaultKdfIterations << "\n";
  std::cout << "  recommended_iterations: " << quantlib::vault::kRecommendedKdfIterations << "\n";
  std::cout << "  salt_bytes: " << quantlib::vault::kVaultSaltBytes << "\n";
  std::cout << "  wrap: AES-256-GCM encrypted SSM master key\n";
  std::cout << "  contents: sealed SSM objects, audit log, authenticated vault metadata, audit head\n";
  std::cout << "  hardening: atomic save, .bak recovery, generation anchors, rollback-check helper\n";
  std::cout << "  safety: checksum, authenticated metadata, wrong-passphrase rejection, no raw private-key export\n";
}

void print_vault_hardening() {
  std::cout << "vault-hardening: QuantLib Vault Hardening v1\n";
  std::cout << "  vault_version: " << quantlib::vault::kVaultVersion << "\n";
  std::cout << "  atomic_save: write .tmp, backup existing file to .bak, rename into place\n";
  std::cout << "  recovery: load_vault() opens primary first and falls back to .bak when primary is unreadable\n";
  std::cout << "  rollback: VaultAnchor{vault_id,generation,audit_head} can reject older vault generations\n";
  std::cout << "  audit: encoded vault stores and verifies audit_head against the decoded hash chain\n";
  std::cout << "  backup: encode_vault_backup() preserves the encrypted vault backup path format\n";
}

void print_ssm() {
  std::cout << "ssm: QuantLib Software Security Module v1\n";
  std::cout << "  master_key_bytes: " << quantlib::ssm::kMasterKeyBytes << "\n";
  std::cout << "  sealed_object_version: " << quantlib::ssm::kSsmVersion << "\n";
  std::cout << "  storage: encrypted sealed-object records\n";
  std::cout << "  sealing: HKDF-SHA256(master) + AES-256-GCM\n";
  std::cout << "  handles: SHA-256-derived opaque 128-bit hex handles\n";
  std::cout << "  operations: generate sign/kem/symmetric sign/domain-sign decapsulate public-export sealed-export import erase state rotate list\n";
  std::cout << "  sessions: short-lived tokens, permissions, handle/domain allow-lists, operation limits\n";
  std::cout << "  session_permissions: sign decapsulate export_public generate_key change_policy erase_key export_sealed import_sealed admin\n";
  std::cout << "  policy: key-state domain allow-list max-operation limits usage counters rotation lineage\n";
  std::cout << "  domain_signing: transcript-bound QuantLib SSM Domain Sign v1\n";
  std::cout << "  safety: no raw private-key export API, authenticated metadata, tamper rejection, zeroization on erase/destruct\n";
}




void print_rotation() {
  std::cout << "ssm-rotation: QuantLib Key Rotation v1\n";
  std::cout << "  behavior: creates replacement key, links old/new handles, optionally retires old key\n";
  std::cout << "  metadata: original_handle replacement_handle generation rotated_at reason\n";
  std::cout << "  states: active retired compromised destroyed locked disabled expired\n";
  std::cout << "  policy: replacement keys preserve allowed_domain/max_operations by default\n";
  std::cout << "  audit: key_rotated key_retired key_marked_compromised\n";
  std::cout << "  cli: quantlib-ssm rotate <vault-file> <passphrase> <handle> [label] [reason]\n";
}



void print_gpu() {
  const auto st = quantlib::gpu::status();
  std::cout << "gpu: QuantLib GPU Acceleration v2\n";
  std::cout << "  compiled: " << (st.gpu_support_compiled ? "yes" : "no") << "\n";
  std::cout << "  cuda_compiled: " << (st.cuda_compiled ? "yes" : "no") << "\n";
  std::cout << "  cuda_kernels_compiled: " << (st.cuda_kernels_compiled ? "yes" : "no") << "\n";
  std::cout << "  opencl_compiled: " << (st.opencl_compiled ? "yes" : "no") << "\n";
  std::cout << "  opencl_kernels_compiled: " << (st.opencl_kernels_compiled ? "yes" : "no") << "\n";
  std::cout << "  runtime_available: " << (st.runtime_available ? "yes" : "no") << "\n";
  std::cout << "  selected_backend: " << quantlib::gpu::backend_name(st.selected_backend) << "\n";
  std::cout << "  min_gpu_batch_items: " << st.default_policy.min_gpu_batch_items << "\n";
  std::cout << "  min_gpu_total_bytes: " << st.default_policy.min_gpu_total_bytes << "\n";
  std::cout << "  notes: " << st.notes << "\n";
  std::cout << "  devices:\n";
  for (const auto& d : st.devices) {
    std::cout << "    " << quantlib::gpu::backend_name(d.backend) << " [" << (d.available ? "available" : "unavailable") << "] " << d.name
              << " production_ready=" << (d.production_ready ? "yes" : "no") << "\n";
  }
  std::vector<quantlib::Bytes> sample(4096, quantlib::Bytes(1024, 0x51));
  const auto route = quantlib::gpu::route_for_batch(sample.size(), sample.size() * sample.front().size());
  std::cout << "  route: requested=" << quantlib::gpu::backend_name(route.requested_backend)
            << " selected=" << quantlib::gpu::backend_name(route.selected_backend)
            << " candidate=" << (route.gpu_candidate ? "yes" : "no")
            << " reason=" << route.reason << "\n";
  const auto batch = quantlib::gpu::batch_sha256(sample);
  if (batch.ok()) {
    std::cout << "  batch_sha256: ok messages=" << batch.value().report.messages
              << " backend=" << quantlib::gpu::backend_name(batch.value().report.backend_used)
              << " accelerated=" << (batch.value().report.accelerated ? "yes" : "no")
              << " cpu_fallback=" << (batch.value().report.cpu_fallback ? "yes" : "no") << "\n";
  }
}



void print_cpu() {
  const auto f = quantlib::cpu::detect();
  std::cout << "cpu: QuantLib CPU Feature Detection v1\n";
  std::cout << "  architecture: " << f.architecture << "\n";
  std::cout << "  logical_threads: " << f.logical_threads << "\n";
  std::cout << "  os_avx: " << (f.os_avx ? "yes" : "no") << "\n";
  std::cout << "  features:\n";
  std::cout << "    sse2: " << (f.sse2 ? "yes" : "no") << "\n";
  std::cout << "    sse4.2: " << (f.sse42 ? "yes" : "no") << "\n";
  std::cout << "    avx: " << (f.avx ? "yes" : "no") << "\n";
  std::cout << "    avx2: " << (f.avx2 ? "yes" : "no") << "\n";
  std::cout << "    avx512f: " << (f.avx512f ? "yes" : "no") << "\n";
  std::cout << "    avx512vl: " << (f.avx512vl ? "yes" : "no") << "\n";
  std::cout << "    avx512bw: " << (f.avx512bw ? "yes" : "no") << "\n";
  std::cout << "    aes-ni: " << (f.aesni ? "yes" : "no") << "\n";
  std::cout << "    sha-ni: " << (f.shani ? "yes" : "no") << "\n";
  std::cout << "    pclmulqdq: " << (f.pclmulqdq ? "yes" : "no") << "\n";
  std::cout << "    bmi2: " << (f.bmi2 ? "yes" : "no") << "\n";
  std::cout << "    adx: " << (f.adx ? "yes" : "no") << "\n";
  std::cout << "    neon: " << (f.neon ? "yes" : "no") << "\n";
}

void print_simd() {
  const auto features = quantlib::cpu::detect();
  const auto table = quantlib::simd::dispatch_table(features);
  std::cout << "simd: QuantLib SIMD Engine v1\n";
  std::cout << "  cpu: " << quantlib::cpu::summary(features) << "\n";
  std::cout << "  selected_sha256_backend: " << quantlib::simd::backend_name(table.sha256_backend) << "\n";
  std::cout << "  selected_aes_gcm_backend: " << quantlib::simd::backend_name(table.aes_gcm_backend) << "\n";
  std::cout << "  selected_chacha20_backend: " << quantlib::simd::backend_name(table.chacha20_backend) << "\n";
  std::cout << "  notes: " << table.notes << "\n";
  std::cout << "  backends:\n";
  for (const auto& b : table.backends) {
    std::cout << "    " << b.name
              << " compiled=" << (b.compiled ? "yes" : "no")
              << " runtime=" << (b.runtime_available ? "yes" : "no")
              << " selected=" << (b.selected ? "yes" : "no")
              << " accelerated=" << (b.accelerated ? "yes" : "no")
              << " - " << b.notes << "\n";
  }
  const auto got = quantlib::simd::sha256_dispatch(quantlib::ByteView{});
  std::cout << "  sha256_dispatch_empty: " << quantlib::hex_encode(got) << "\n";
}

void print_hardware() {
  const auto st = quantlib::hardware::dispatch_status();
  std::cout << "hardware: QuantLib Hardware Dispatcher v1\n";
  std::cout << "  native_cpu_enabled: " << (st.native_cpu_enabled ? "yes" : "no") << "\n";
  std::cout << "  gpu_enabled: " << (st.gpu_enabled ? "yes" : "no") << "\n";
  std::cout << "  selected_hash_backend: " << quantlib::hardware::backend_name(st.selected_hash_backend) << "\n";
  std::cout << "  selected_batch_backend: " << quantlib::hardware::backend_name(st.selected_batch_backend) << "\n";
  std::cout << "  notes: " << st.notes << "\n";
  std::cout << "  backends:\n";
  for (const auto& b : st.backends) {
    std::cout << "    " << quantlib::hardware::backend_name(b.kind)
              << " compiled=" << (b.compiled ? "yes" : "no")
              << " runtime=" << (b.runtime_available ? "yes" : "no")
              << " production_ready=" << (b.production_ready ? "yes" : "no")
              << " priority=" << b.priority << " - " << b.notes << "\n";
  }
}

void print_batch() {
  std::cout << "batch: QuantLib Batch Crypto v1\n";
  std::vector<quantlib::Bytes> messages{quantlib::Bytes{'Q','u','a','n','t'}, quantlib::Bytes{'L','i','b'}, quantlib::Bytes(1024, 0x42)};
  const auto r = quantlib::batch::sha256(messages);
  if (!r.ok()) {
    std::cout << "  sha256: fail " << r.error().message << "\n";
    return;
  }
  std::cout << "  sha256: ok\n";
  std::cout << "  items: " << r.value().report.items << "\n";
  std::cout << "  total_input_bytes: " << r.value().report.total_input_bytes << "\n";
  std::cout << "  backend: " << quantlib::hardware::backend_name(r.value().report.backend_used) << "\n";
  std::cout << "  accelerated: " << (r.value().report.accelerated ? "yes" : "no") << "\n";
  std::cout << "  notes: " << r.value().report.notes << "\n";
  const auto vr = quantlib::batch::verify_signatures({});
  std::cout << "  batch_verify_boundary: " << (!vr.ok() ? "fail-closed" : "available") << "\n";
}

void print_throughput() {
  const auto st = quantlib::throughput::engine_status();
  std::cout << "throughput: QuantLib Throughput Engine v1\n";
  std::cout << "  detected_threads: " << st.detected_threads << "\n";
  std::cout << "  selected_workers: " << st.selected_workers << "\n";
  std::cout << "  min_parallel_items: " << st.min_parallel_items << "\n";
  std::cout << "  target_chunk_items: " << st.target_chunk_items << "\n";
  std::cout << "  parallel_enabled: " << (st.parallel_enabled ? "yes" : "no") << "\n";
  std::cout << "  thread_local_scratch: " << (st.thread_local_scratch ? "yes" : "no") << "\n";
  std::cout << "  notes: " << st.notes << "\n";
  std::vector<quantlib::Bytes> sample(1024, quantlib::Bytes(128, 0x51));
  const auto r = quantlib::throughput::sha256_parallel(sample);
  if (r.ok()) {
    std::cout << "  sample_batch: ok items=" << r.value().report.items
              << " workers=" << r.value().report.workers_used
              << " chunks=" << r.value().report.chunks
              << " route=" << r.value().report.route << "\n";
  }
}

void print_release() {
  std::cout << "release: QuantLib Production Gate v1\n";
  for (const auto profile : quantlib::release::supported_profiles()) {
    std::cout << "  profile " << quantlib::release::profile_name(profile) << ": "
              << quantlib::release::describe_profile(profile) << "\n";
  }
  const auto report = quantlib::release::run_release_gate(quantlib::release::Profile::hardened);
  std::cout << "  hardened_gate: " << (report.passed() ? "pass" : "fail") << "\n";
  std::cout << "  passed: " << report.passed_count() << " failed: " << report.failed_count() << "\n";
  for (const auto& check : report.checks) {
    std::cout << "    " << (check.passed ? "[pass] " : "[fail] ") << check.name;
    if (!check.detail.empty()) std::cout << " - " << check.detail;
    std::cout << "\n";
  }
}


void print_testinfra() {
  const auto report = quantlib::testing::readiness_report();
  const auto matrix = quantlib::testing::default_ci_matrix();
  std::cout << "testing: QuantLib Test/Fuzz/CI v1\n";
  std::cout << "  version: " << report.version << "\n";
  std::cout << "  readiness: " << (report.passed() ? "pass" : "fail") << "\n";
  std::cout << "  capabilities: " << report.available_count() << " available, " << report.missing_count() << " missing\n";
  std::cout << "  profiles:";
  for (const auto profile : quantlib::testing::supported_build_profiles()) std::cout << " " << quantlib::testing::build_profile_name(profile);
  std::cout << "\n  platforms:";
  for (const auto& platform : matrix.platforms) std::cout << " " << platform;
  std::cout << "\n  jobs:";
  for (const auto& job : matrix.jobs) std::cout << " " << job;
  std::cout << "\n  fuzz_targets:\n";
  for (const auto& target : report.fuzz_targets) {
    std::cout << "    " << target.name << " source=" << target.source << " max=" << target.max_input_bytes << " purpose=" << target.purpose << "\n";
  }
  std::cout << "  coverage: line>=" << report.coverage.line_threshold << "% branch>=" << report.coverage.branch_threshold << "% fail=" << (report.coverage.fail_under_threshold ? "yes" : "no") << "\n";
  std::cout << "  performance_budgets:\n";
  for (const auto& budget : report.performance_budgets) {
    std::cout << "    " << budget.benchmark << " max_regression=" << budget.max_regression_percent << "% min_ops=" << budget.min_ops_per_second << "\n";
  }
  for (const auto& cap : report.capabilities) {
    std::cout << "    " << (cap.available ? "[pass] " : "[fail] ") << cap.name;
    if (!cap.detail.empty()) std::cout << " - " << cap.detail;
    std::cout << "\n";
  }
}



void print_production_ready() {
  const auto report = quantlib::production::readiness_report();
  std::cout << "production-ready: QuantLib v" << report.version << "\n";
  std::cout << "  level: " << quantlib::production::readiness_level_name(report.level) << "\n";
  std::cout << "  passed: " << (report.passed() ? "yes" : "no") << " checks=" << report.passed_count() << "/" << report.checks.size() << " required=" << report.required_count() << "\n";
  std::cout << "  hardening:\n";
  std::cout << "    platform: " << report.hardening.platform << "\n";
  std::cout << "    hardened_build: " << (report.hardening.hardened_build ? "yes" : "no") << "\n";
  std::cout << "    warnings_as_errors: " << (report.hardening.warnings_as_errors ? "yes" : "no") << "\n";
  std::cout << "    sanitizers_enabled: " << (report.hardening.sanitizers_enabled ? "yes" : "no") << "\n";
  std::cout << "    coverage_enabled: " << (report.hardening.coverage_enabled ? "yes" : "no") << "\n";
  std::cout << "    native_tuning_enabled: " << (report.hardening.native_tuning_enabled ? "yes" : "no") << "\n";
  std::cout << "    openssl_provider_enabled: " << (report.hardening.openssl_provider_enabled ? "yes" : "no") << "\n";
  std::cout << "    pq_provider_enabled: " << (report.hardening.pq_provider_enabled ? "yes" : "no") << "\n";
  std::cout << "    gpu_hooks_enabled: " << (report.hardening.gpu_hooks_enabled ? "yes" : "no") << "\n";
  std::cout << "    compile_defenses:\n";
  for (const auto& d : report.hardening.compile_defenses) std::cout << "      " << d << "\n";
  std::cout << "  checks:\n";
  for (const auto& check : report.checks) {
    std::cout << "    " << (check.passed ? "[pass] " : "[fail] ") << check.name << " required=" << (check.required ? "yes" : "no");
    if (!check.detail.empty()) std::cout << " - " << check.detail;
    std::cout << "\n";
  }
  const auto blockers = quantlib::production::production_blockers();
  std::cout << "  blockers:\n";
  if (blockers.empty()) std::cout << "    none\n";
  for (const auto& b : blockers) std::cout << "    " << b << "\n";
  std::cout << "  integration_rules:\n";
  for (const auto& r : quantlib::production::integration_rules()) std::cout << "    " << r << "\n";
}

void print_production() {
  const auto boundary = quantlib::release::production_boundary();
  std::cout << "production: QuantLib v" << quantlib::kVersion << " baseline\n";
  std::cout << "  production_ready:\n";
  for (const auto& item : boundary.production_ready) std::cout << "    " << item << "\n";
  std::cout << "  provider_dependent:\n";
  for (const auto& item : boundary.provider_dependent) std::cout << "    " << item << "\n";
  std::cout << "  explicitly_not_claimed:\n";
  for (const auto& item : boundary.explicitly_not_claimed) std::cout << "    " << item << "\n";
  std::cout << "  release_artifacts:\n";
  for (const auto& artifact : quantlib::release::required_release_artifacts()) {
    std::cout << "    " << artifact.name << " required=" << (artifact.required ? "yes" : "no") << " purpose=" << artifact.purpose << "\n";
  }
}

void print_sbom() {
  std::cout << "sbom: QuantLib v" << quantlib::kVersion << " component inventory\n";
  for (const auto& c : quantlib::release::sbom_components()) {
    std::cout << "  " << c.name << " type=" << c.type << " status=" << c.status << "\n";
  }
  std::cout << "  security_documents:\n";
  for (const auto& d : quantlib::release::security_document_set()) std::cout << "    " << d << "\n";
  std::cout << "  signing_steps:\n";
  for (const auto& step : quantlib::release::release_signing_steps()) std::cout << "    " << step << "\n";
}

void print_inventory() {
  std::cout << "provider-inventory: QuantLib v" << quantlib::kVersion << "\n";
  for (const auto& entry : quantlib::release::provider_inventory()) {
    std::cout << "  " << entry.provider << " [" << (entry.available ? "available" : "unavailable") << "] "
              << entry.version << " production=" << (entry.production ? "yes" : "no")
              << " experimental=" << (entry.experimental ? "yes" : "no") << "\n";
    std::cout << "    algorithms:";
    for (const auto& algo : entry.algorithms) std::cout << " " << algo;
    std::cout << "\n";
  }
}

void print_stable_api() {
  std::cout << "stable-api: QuantLib v" << quantlib::kVersion << "\n";
  std::cout << "  headers:\n";
  for (const auto& header : quantlib::release::stable_headers()) std::cout << "    include/quantlib/" << header << "\n";
  std::cout << "  experimental:\n";
  for (const auto& module : quantlib::release::experimental_modules()) std::cout << "    " << module << "\n";
}

void print_ops() {
  std::cout << "ops: QuantLib v" << quantlib::kVersion << " operational readiness\n";
  auto report = quantlib::ops::validate_deployment(quantlib::ops::default_profile(quantlib::ops::DeploymentTarget::server));
  std::cout << "  default_profile: " << report.profile.name << "\n";
  std::cout << "  passed: " << (report.passed() ? "yes" : "no") << " checks=" << report.passed_count() << "/" << report.checks.size() << "\n";
  std::cout << "  checks:\n";
  for (const auto& c : report.checks) std::cout << "    [" << (c.passed ? "pass" : "fail") << "] " << c.name << " - " << c.detail << "\n";
  std::cout << "  profiles:\n";
  for (const auto& p : quantlib::ops::deployment_profiles()) {
    std::cout << "    " << p.name << " ttl=" << p.recommended_session_ttl_seconds
              << " rekey_records=" << p.recommended_rekey_records
              << " experimental_pq=" << (p.allow_experimental_pq ? "yes" : "no") << "\n";
  }
}

void print_runbook() {
  std::cout << "runbook: QuantLib v" << quantlib::kVersion << " operator steps\n";
  for (const auto& step : quantlib::ops::operator_runbook()) {
    std::cout << "  [" << step.phase << "] " << step.action << " -> " << step.verification << "\n";
  }
  std::cout << "  config_templates:\n";
  for (const auto& t : quantlib::ops::config_templates()) {
    std::cout << "    " << t.name << " - " << t.purpose << "\n";
  }
}

void print_easy() {
  std::cout << "easy: QuantLib Easy Integration Wrapper v1\n";
  std::cout << "  header: include/quantlib/easy.hpp\n";
  std::cout << "  facade: quantlib::easy::QuantVault\n";
  std::cout << "  helpers: quick_create_vault quick_generate_signing_key quick_sign\n";
  std::cout << "  features: create/open vault generate keys session-gated domain-sign verify rotate erase autosave list status\n";
  std::cout << "  defaults: Ed25519 signing X25519 exchange short-lived SSM session domain-separated signing atomic vault save\n";
  std::cout << "  safety: wrapper uses vault + SSM + sessions; it does not expose raw private-key export\n";
}

void print_memory() {
  const auto status = quantlib::secure_memory_status();
  std::cout << "memory: QuantLib Secure Memory v1\n";
  std::cout << "  backend: " << status.backend << "\n";
  std::cout << "  locking_supported: " << (status.locking_supported ? "yes" : "no") << "\n";
  std::cout << "  dump_exclusion_supported: " << (status.dump_exclusion_supported ? "yes" : "no") << "\n";
  std::cout << "  guard_pages_supported: " << (status.guard_pages_supported ? "yes" : "no") << "\n";
  std::cout << "  secure_zero: yes\n";
  std::cout << "  secret_buffers: SecureBytes move-only zeroized, LockedBytes best-effort OS memory lock\n";
  std::cout << "  notes: " << status.notes << "\n";
}

void print_sessions() {
  std::cout << "ssm-sessions: QuantLib SSM Sessions v1\n";
  std::cout << "  token_bytes: 32 random bytes encoded as hex\n";
  std::cout << "  default_ttl_seconds: 300\n";
  std::cout << "  permissions: sign decapsulate export_public generate_key change_policy erase_key export_sealed import_sealed admin\n";
  std::cout << "  controls: allowed_handles allowed_domains max_sign_operations max_decapsulate_operations close/expire fail-closed\n";
  std::cout << "  safety: raw session tokens are never stored in audit entries; token hashes are used for display/audit correlation\n";
}

void print_kdfs() {
  std::cout << "vault-kdfs: QuantLib Vault KDF Providers v1\n";
  for (const auto& info : quantlib::vault::supported_kdfs()) {
    std::cout << "  " << info.name << " [" << (info.available ? "available" : "unavailable") << "]"
              << " memory_hard=" << (info.memory_hard ? "yes" : "no")
              << " iterations=" << info.iterations
              << " memory_kib=" << info.memory_kib
              << " parallelism=" << info.parallelism << "\n";
    if (!info.notes.empty()) std::cout << "    notes: " << info.notes << "\n";
  }
  std::cout << "  migration: rewrap_vault_kdf() preserves existing objects and changes future vault wrapping parameters\n";
}

void print_channel() {
  std::cout << "channel: QuantLib Channel v1\n";
  std::cout << "  state: local-role send-sequence generation receive-replay-window closed-flag\n";
  std::cout << "  defaults: rekey_interval=" << quantlib::channel::kDefaultRekeyInterval << " records\n";
  std::cout << "  features: encoded-frame-send receive-open replay-enforced peer-role-check close-notify key-update-apply\n";
  std::cout << "  aad: channel associated-context plus per-call associated-data\n";
}

void print_protocol() {
  std::cout << "protocol: QuantLink v1\n";
  std::cout << "  handshake_version: " << static_cast<int>(quantlib::protocol::kHandshakeVersion) << "\n";
  std::cout << "  max_record_plaintext_default: " << quantlib::protocol::kDefaultMaxRecordPlaintext << "\n";
  std::cout << "  max_frame_bytes_default: " << quantlib::protocol::kDefaultMaxFrameBytes << "\n";
  std::cout << "  features: handshake-state-machine suite-negotiation downgrade-protection record-limits close-notify-required rekey-thresholds\n";
  std::cout << "  suites:\n";
  for (const auto& suite : quantlib::protocol::default_cipher_suites()) {
    std::cout << "    " << quantlib::protocol::describe_suite(suite) << "\n";
  }
}

void print_policies() {
  const quantlib::policy::Profile profiles[] = {
      quantlib::policy::Profile::fast,
      quantlib::policy::Profile::balanced,
      quantlib::policy::Profile::conservative,
      quantlib::policy::Profile::pq_transition,
  };
  for (const auto profile : profiles) {
    const auto p = quantlib::policy::make_policy(profile);
    std::cout << quantlib::policy::profile_name(profile) << ": " << quantlib::policy::describe(p) << "\n";
  }
}


void print_full() {
  std::cout << "quantlib_full_health version=" << quantlib::kVersion << "\n";
  std::cout << "\n[version]\n";
  print_version();
  std::cout << "\n[selftest]\n";
  const auto self = quantlib::selftest::run();
  std::cout << "selftest_passed " << (self.passed() ? "yes" : "no") << " passed=" << self.passed_count() << " failed=" << self.failed_count() << "\n";
  std::cout << "\n[providers]\n";
  print_providers();
  std::cout << "\n[pq-provider]\n";
  print_pq_provider();
  std::cout << "\n[gpu]\n";
  print_gpu();
  std::cout << "\n[cpu]\n";
  print_cpu();
  std::cout << "\n[simd]\n";
  print_simd();
  std::cout << "\n[hardware]\n";
  print_hardware();
  std::cout << "\n[vault]\n";
  print_vault();
  std::cout << "\n[ssm]\n";
  print_ssm();
  std::cout << "\n[release]\n";
  const auto gate = quantlib::release::run_release_gate(quantlib::release::Profile::hardened);
  std::cout << "release_gate_passed " << (gate.passed() ? "yes" : "no") << " passed=" << gate.passed_count() << " failed=" << gate.failed_count() << "\n";
  std::cout << "\n[production-ready]\n";
  const auto prod = quantlib::production::readiness_report();
  std::cout << "production_ready_passed " << (prod.passed() ? "yes" : "no") << " checks=" << prod.checks.size() << "\n";
}

const char* purpose_name(quantlib::key::Purpose purpose) noexcept {
  switch (purpose) {
    case quantlib::key::Purpose::kem_public: return "kem_public";
    case quantlib::key::Purpose::kem_secret: return "kem_secret";
    case quantlib::key::Purpose::sign_public: return "sign_public";
    case quantlib::key::Purpose::sign_secret: return "sign_secret";
    case quantlib::key::Purpose::symmetric: return "symmetric";
  }
  return "unknown";
}
}

int main(int argc, char** argv) {
  if (argc == 2 && std::string(argv[1]) == "--version") {
    print_version();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--selftest") {
    print_selftest();
    return quantlib::selftest::require_pass().ok() ? 0 : 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--providers") {
    print_providers();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--pq") {
    print_pq();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--pq-provider") {
    print_pq_provider();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--pq-kat") {
    print_pq_kat();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--policies") {
    print_policies();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--session") {
    print_session();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--record") {
    print_record();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--replay") {
    print_replay();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--channel") {
    print_channel();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--protocol") {
    print_protocol();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--ssm") {
    print_ssm();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--audit") {
    print_audit();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--sessions") {
    print_sessions();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--vault") {
    print_vault();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--vault-hardening") {
    print_vault_hardening();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--kdfs") {
    print_kdfs();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--rotation") {
    print_rotation();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--memory") {
    print_memory();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--gpu") {
    print_gpu();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--cpu") {
    print_cpu();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--simd") {
    print_simd();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--hardware") {
    print_hardware();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--batch") {
    print_batch();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--throughput") {
    print_throughput();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--release") {
    print_release();
    return quantlib::release::run_release_gate(quantlib::release::Profile::hardened).passed() ? 0 : 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--test-infra") {
    print_testinfra();
    return quantlib::testing::readiness_report().passed() ? 0 : 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--inventory") {
    print_inventory();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--production") {
    print_production();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--production-ready") {
    print_production_ready();
    return quantlib::production::require_production_ready().ok() ? 0 : 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--sbom") {
    print_sbom();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--stable-api") {
    print_stable_api();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--ops") {
    print_ops();
    return quantlib::ops::validate_deployment(quantlib::ops::default_profile(quantlib::ops::DeploymentTarget::server)).passed() ? 0 : 2;
  }
  if (argc == 2 && std::string(argv[1]) == "--runbook") {
    print_runbook();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--easy") {
    print_easy();
    return 0;
  }
  if (argc == 2 && std::string(argv[1]) == "--full") {
    print_full();
    const bool ok = quantlib::selftest::require_pass().ok() && quantlib::release::run_release_gate(quantlib::release::Profile::hardened).passed() && quantlib::production::require_production_ready().ok();
    return ok ? 0 : 2;
  }
  if (argc != 2) {
    std::cerr << "usage: quantlib-inspect <hex-key-blob>|--version|--selftest|--providers|--pq|--pq-provider|--pq-kat|--policies|--session|--record|--replay|--channel|--protocol|--ssm|--audit|--sessions|--vault|--vault-hardening|--kdfs|--rotation|--memory|--gpu|--cpu|--simd|--hardware|--batch|--throughput|--release|--test-infra|--inventory|--production|--production-ready|--sbom|--stable-api|--ops|--runbook|--easy|--full\n";
    return 1;
  }
  const auto raw = quantlib::hex_decode(argv[1]);
  const auto blob = quantlib::key::decode(raw);
  if (!blob) {
    std::cerr << "decode error: " << blob.error().message << "\n";
    return 1;
  }
  std::cout << "version: " << blob.value().version << "\n";
  std::cout << "algorithm: " << blob.value().algorithm << "\n";
  std::cout << "purpose: " << purpose_name(blob.value().purpose) << "\n";
  std::cout << "flags: " << blob.value().flags << "\n";
  std::cout << "created_at: " << blob.value().created_at << "\n";
  std::cout << "payload_size: " << blob.value().payload.size() << "\n";
  std::cout << "key_id: " << quantlib::hex_encode(blob.value().key_id) << "\n";
  return 0;
}

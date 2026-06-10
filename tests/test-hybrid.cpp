#include "quantlib/quantlib.hpp"
#include <cassert>

int run_hybrid_tests() {
  const auto kp = quantlib::hybrid::generate_default_kem_keypair();
  if (!quantlib::pq::available()) {
    assert(!kp.ok());
    assert(kp.error().code == quantlib::ErrorCode::unsupported_algorithm);
  }

  quantlib::kem::PublicKey wrong{quantlib::kem::Algorithm::x25519, {}};
  const auto enc = quantlib::hybrid::encapsulate_default(wrong);
  assert(!enc.ok());
  assert(enc.error().code == quantlib::ErrorCode::invalid_key);

  const quantlib::Bytes classical{1, 2, 3, 4};
  const quantlib::Bytes pq{5, 6, 7, 8};
  const quantlib::Bytes ctx{9, 10};
  const auto combined1 = quantlib::hybrid::combine_kem_secrets({classical, pq, {}}, ctx, 32);
  const auto combined2 = quantlib::hybrid::combine_kem_secrets({classical, pq, {}}, ctx, 32);
  const auto combined3 = quantlib::hybrid::combine_kem_secrets({classical, pq, {}}, {}, 32);
  assert(combined1.ok());
  assert(combined2.ok());
  assert(combined3.ok());
  assert(combined1.value().size() == 32);
  assert(combined1.value() == combined2.value());
  assert(combined1.value() != combined3.value());
  const auto missing = quantlib::hybrid::combine_kem_secrets({classical, {}, {}}, ctx, 32);
  assert(!missing.ok());
  return 0;
}

int run_core_tests();
int run_hash_tests();
int run_key_tests();
int run_classical_tests();
int run_provider_tests();
int run_kdf_tests();
int run_pq_tests();
int run_policy_tests();
int run_transcript_tests();
int run_session_tests();
int run_replay_tests();
int run_channel_tests();
int run_audit_tests();
int run_selftest_tests();
int run_ssm_tests();
int run_vault_tests();
int run_ssm_session_tests();
int run_release_tests();
int run_protocol_tests();
int run_testing_tests();
int run_ops_tests();
void test_production_readiness_report();
void test_production_operator_lists();
void test_easy();
void test_hardware_dispatch_status();
void test_batch_sha256_dispatch();
void test_batch_accelerator_fail_closed();
void test_throughput_engine_status();
void test_throughput_parallel_sha256();
int main_gpu_tests();
void test_cpu_feature_detection();
void test_simd_dispatch_table();
void test_simd_sha256_equivalence();
void test_aligned_bytes();

int main() {
  run_core_tests();
  run_hash_tests();
  run_key_tests();
  run_hybrid_tests();
  run_classical_tests();
  run_provider_tests();
  run_kdf_tests();
  run_pq_tests();
  run_policy_tests();
  run_transcript_tests();
  run_session_tests();
  run_replay_tests();
  run_channel_tests();
  run_audit_tests();
  run_selftest_tests();
  run_ssm_tests();
  run_ssm_session_tests();
  run_vault_tests();
  run_release_tests();
  run_protocol_tests();
  run_testing_tests();
  run_ops_tests();
  test_production_readiness_report();
  test_production_operator_lists();
  test_easy();
  test_hardware_dispatch_status();
  test_batch_sha256_dispatch();
  test_batch_accelerator_fail_closed();
  test_throughput_engine_status();
  test_throughput_parallel_sha256();
  test_cpu_feature_detection();
  test_simd_dispatch_table();
  test_simd_sha256_equivalence();
  test_aligned_bytes();
  main_gpu_tests();
  return 0;
}

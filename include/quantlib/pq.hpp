#pragma once
#include "quantlib/result.hpp"
#include "quantlib/kem.hpp"
#include "quantlib/sign.hpp"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::pq {

enum class Family {
  ml_kem,
  ml_dsa,
  slh_dsa,
  hqc
};

struct AlgorithmInfo {
  Family family{};
  std::string name{};
  std::uint16_t algorithm_id{};
  int nist_security_level{};
  std::size_t public_key_bytes{};
  std::size_t secret_key_bytes{};
  std::size_t ciphertext_bytes{};
  std::size_t signature_bytes{};
  std::size_t shared_secret_bytes{};
  bool supported{false};
};

struct BackendStatus {
  std::string name{};
  std::string version{};
  bool compile_time_enabled{false};
  bool linked{false};
  bool runtime_available{false};
  bool production_ready{false};
  std::string notes{};
};

struct KatCase {
  std::string name{};
  Family family{};
  std::uint16_t algorithm_id{};
  std::size_t public_key_bytes{};
  std::size_t secret_key_bytes{};
  std::size_t ciphertext_or_signature_bytes{};
  std::size_t shared_secret_bytes{};
  bool provider_required{true};
};

struct KatReport {
  std::string backend{};
  std::size_t vectors_planned{0};
  std::size_t vectors_runnable{0};
  std::size_t vectors_passed{0};
  std::size_t vectors_failed{0};
  bool provider_available{false};
  bool passed() const noexcept { return vectors_failed == 0; }
};

[[nodiscard]] bool available() noexcept;
[[nodiscard]] const char* backend_name() noexcept;
[[nodiscard]] BackendStatus backend_status();
[[nodiscard]] Result<void> ensure_available();
[[nodiscard]] std::vector<AlgorithmInfo> kem_algorithms();
[[nodiscard]] std::vector<AlgorithmInfo> signature_algorithms();
[[nodiscard]] std::vector<KatCase> planned_kat_cases();
[[nodiscard]] KatReport run_kat_harness();
[[nodiscard]] Result<void> validate_algorithm_sizes();
[[nodiscard]] Result<void> validate_provider_wiring();
[[nodiscard]] Result<void> reject_downgrade(std::uint16_t negotiated_algorithm_id, std::uint16_t attempted_algorithm_id);
[[nodiscard]] const AlgorithmInfo* find_algorithm(std::uint16_t algorithm_id) noexcept;

[[nodiscard]] Result<kem::KeyPair> kem_generate_keypair(kem::Algorithm algorithm);
[[nodiscard]] Result<kem::Encapsulation> kem_encapsulate(const kem::PublicKey& public_key);
[[nodiscard]] Result<Bytes> kem_decapsulate(const kem::SecretKey& secret_key, ByteView ciphertext);
[[nodiscard]] Result<sign::KeyPair> sign_generate_keypair(sign::Algorithm algorithm);
[[nodiscard]] Result<sign::Signature> sign_message(const sign::SecretKey& secret_key, ByteView message);
[[nodiscard]] Result<bool> verify_message(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature);

[[nodiscard]] Result<kem::KeyPair> make_hybrid_kem_keypair();
[[nodiscard]] Result<kem::Encapsulation> encapsulate_hybrid_kem(const kem::PublicKey& public_key);
[[nodiscard]] Result<Bytes> decapsulate_hybrid_kem(const kem::SecretKey& secret_key, ByteView ciphertext);
[[nodiscard]] Result<sign::KeyPair> make_hybrid_sign_keypair();
[[nodiscard]] Result<sign::Signature> sign_hybrid(const sign::SecretKey& secret_key, ByteView message);
[[nodiscard]] Result<bool> verify_hybrid(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature);
[[nodiscard]] const char* family_name(Family family) noexcept;

}  // namespace quantlib::pq

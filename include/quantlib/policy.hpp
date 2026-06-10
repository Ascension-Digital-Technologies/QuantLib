#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/hash.hpp"
#include "quantlib/kem.hpp"
#include "quantlib/result.hpp"
#include "quantlib/sign.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::policy {

enum class Profile : std::uint8_t {
  fast,
  balanced,
  conservative,
  pq_transition
};

struct AlgorithmPolicy {
  Profile profile{Profile::balanced};
  int minimum_security_level{3};
  bool allow_classical_kem{true};
  bool allow_classical_signatures{true};
  bool prefer_hybrid{true};
  bool require_aead{true};
  std::vector<kem::Algorithm> allowed_kems{};
  std::vector<sign::Algorithm> allowed_signatures{};
  std::vector<aead::Algorithm> allowed_aeads{};
  std::vector<hash::Algorithm> allowed_hashes{};
};

[[nodiscard]] AlgorithmPolicy make_policy(Profile profile);
[[nodiscard]] const char* profile_name(Profile profile) noexcept;
[[nodiscard]] Result<void> validate_kem(kem::Algorithm algorithm, const AlgorithmPolicy& policy);
[[nodiscard]] Result<void> validate_signature(sign::Algorithm algorithm, const AlgorithmPolicy& policy);
[[nodiscard]] Result<void> validate_aead(aead::Algorithm algorithm, const AlgorithmPolicy& policy);
[[nodiscard]] Result<void> validate_hash(hash::Algorithm algorithm, const AlgorithmPolicy& policy);
[[nodiscard]] std::string describe(const AlgorithmPolicy& policy);

}  // namespace quantlib::policy

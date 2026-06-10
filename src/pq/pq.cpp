#include "quantlib/pq.hpp"
#include "quantlib/hybrid.hpp"
#include "quantlib/kdf.hpp"
#include "quantlib/rng.hpp"
#include "quantlib/secure.hpp"
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>

#if QUANTLIB_HAVE_LIBOQS
#include <oqs/oqs.h>
#endif

namespace quantlib::pq {
namespace {
constexpr std::uint32_t kHybridKemPublicMagic = 0x51484b50;   // QHKP
constexpr std::uint32_t kHybridKemSecretMagic = 0x51484b53;   // QHKS
constexpr std::uint32_t kHybridKemCipherMagic = 0x51484b43;   // QHKC
constexpr std::uint32_t kHybridSignPublicMagic = 0x51485350;  // QHSP
constexpr std::uint32_t kHybridSignSecretMagic = 0x51485353;  // QHSS
constexpr std::uint32_t kHybridSignSigMagic = 0x51485347;     // QHSG
constexpr std::uint16_t kPackedVersion = 1;

bool get_u16(ByteView in, std::size_t& off, std::uint16_t& v) {
  if (off + 2 > in.size()) return false;
  v = static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[off]) << 8) | in[off + 1]);
  off += 2;
  return true;
}
bool get_u32(ByteView in, std::size_t& off, std::uint32_t& v) {
  if (off + 4 > in.size()) return false;
  v = (static_cast<std::uint32_t>(in[off]) << 24) | (static_cast<std::uint32_t>(in[off + 1]) << 16) |
      (static_cast<std::uint32_t>(in[off + 2]) << 8) | static_cast<std::uint32_t>(in[off + 3]);
  off += 4;
  return true;
}
Result<Bytes> read_part(ByteView in, std::size_t& off, std::uint16_t len, const char* what) {
  if (off + len > in.size()) return make_error(ErrorCode::invalid_format, std::string("truncated packed ") + what);
  Bytes out(in.begin() + static_cast<std::ptrdiff_t>(off), in.begin() + static_cast<std::ptrdiff_t>(off + len));
  off += len;
  return out;
}

Bytes pack2(std::uint32_t magic, ByteView a, ByteView b) {
  // Hybrid key/ciphertext parts are intentionally length-prefixed with u16.
  // These are fixed-size provider outputs and must remain far below 64 KiB.
  if (a.size() > 0xffffu || b.size() > 0xffffu) return {};

  Bytes out(10 + a.size() + b.size());
  std::size_t off = 0;
  auto put8 = [&](std::uint8_t v) { out[off++] = v; };
  put8(static_cast<std::uint8_t>((magic >> 24) & 0xff));
  put8(static_cast<std::uint8_t>((magic >> 16) & 0xff));
  put8(static_cast<std::uint8_t>((magic >> 8) & 0xff));
  put8(static_cast<std::uint8_t>(magic & 0xff));
  put8(static_cast<std::uint8_t>((kPackedVersion >> 8) & 0xff));
  put8(static_cast<std::uint8_t>(kPackedVersion & 0xff));
  const auto a_len = static_cast<std::uint16_t>(a.size());
  const auto b_len = static_cast<std::uint16_t>(b.size());
  put8(static_cast<std::uint8_t>((a_len >> 8) & 0xff));
  put8(static_cast<std::uint8_t>(a_len & 0xff));
  put8(static_cast<std::uint8_t>((b_len >> 8) & 0xff));
  put8(static_cast<std::uint8_t>(b_len & 0xff));
  std::copy(a.begin(), a.end(), out.begin() + static_cast<std::ptrdiff_t>(off));
  off += a.size();
  std::copy(b.begin(), b.end(), out.begin() + static_cast<std::ptrdiff_t>(off));
  return out;
}
Result<std::pair<Bytes, Bytes>> unpack2(std::uint32_t magic, ByteView in, const char* what) {
  std::size_t off = 0;
  std::uint32_t got_magic = 0;
  std::uint16_t version = 0, a_len = 0, b_len = 0;
  if (!get_u32(in, off, got_magic) || !get_u16(in, off, version) || !get_u16(in, off, a_len) || !get_u16(in, off, b_len)) {
    return make_error(ErrorCode::invalid_format, std::string("truncated packed ") + what);
  }
  if (got_magic != magic || version != kPackedVersion) {
    return make_error(ErrorCode::invalid_format, std::string("invalid packed ") + what + " header");
  }
  auto a = read_part(in, off, a_len, what);
  if (!a) return a.error();
  auto b = read_part(in, off, b_len, what);
  if (!b) return b.error();
  if (off != in.size()) return make_error(ErrorCode::invalid_format, std::string("trailing data in packed ") + what);
  return std::make_pair(std::move(a).value(), std::move(b).value());
}

Result<Bytes> hybrid_combine(ByteView classical_secret, ByteView pq_secret, std::string_view label) {
  if (classical_secret.empty() || pq_secret.empty()) return make_error(ErrorCode::invalid_argument, "hybrid combiner requires both secrets");
  const ByteView label_view(reinterpret_cast<const std::uint8_t*>(label.data()), label.size());
  Bytes ikm;
  ikm.reserve(label_view.size() + classical_secret.size() + pq_secret.size());
  ikm.insert(ikm.end(), label_view.begin(), label_view.end());
  ikm.insert(ikm.end(), classical_secret.begin(), classical_secret.end());
  ikm.insert(ikm.end(), pq_secret.begin(), pq_secret.end());
  auto out = kdf::hkdf_sha256(ikm, {}, label_view, hybrid::kDefaultSharedSecretBytes);
  secure_zero(ikm.data(), ikm.size());
  return out;
}

#if QUANTLIB_HAVE_LIBOQS
const char* oqs_kem_name(kem::Algorithm algorithm) noexcept {
  switch (algorithm) {
    case kem::Algorithm::ml_kem_512: return "ML-KEM-512";
    case kem::Algorithm::ml_kem_768: return "ML-KEM-768";
    case kem::Algorithm::ml_kem_1024: return "ML-KEM-1024";
    default: return nullptr;
  }
}
const char* oqs_sig_name(sign::Algorithm algorithm) noexcept {
  switch (algorithm) {
    case sign::Algorithm::ml_dsa_44: return "ML-DSA-44";
    case sign::Algorithm::ml_dsa_65: return "ML-DSA-65";
    case sign::Algorithm::ml_dsa_87: return "ML-DSA-87";
    case sign::Algorithm::slh_dsa_sha2_128s: return "SLH-DSA-SHA2-128s";
    default: return nullptr;
  }
}
struct KemDeleter { void operator()(OQS_KEM* p) const noexcept { OQS_KEM_free(p); } };
struct SigDeleter { void operator()(OQS_SIG* p) const noexcept { OQS_SIG_free(p); } };
using KemPtr = std::unique_ptr<OQS_KEM, KemDeleter>;
using SigPtr = std::unique_ptr<OQS_SIG, SigDeleter>;
#endif

}  // namespace

bool available() noexcept {
#if QUANTLIB_HAVE_LIBOQS
  return true;
#else
  return false;
#endif
}

const char* backend_name() noexcept {
#if QUANTLIB_HAVE_LIBOQS
  return "liboqs";
#else
  return "unavailable";
#endif
}

BackendStatus backend_status() {
#if QUANTLIB_HAVE_LIBOQS
  return BackendStatus{"liboqs", OQS_VERSION_TEXT, true, true, true, true,
                       "liboqs is linked; ML-KEM/ML-DSA/SLH-DSA provider paths are active and gated by QuantLib KAT/provider checks"};
#else
  return BackendStatus{"unavailable", "not linked", false, false, false, false,
                       "post-quantum provider is fail-closed; build with QUANTLIB_ENABLE_LIBOQS and a vetted liboqs/PQ backend"};
#endif
}

Result<void> ensure_available() {
  if (available()) return {};
  return make_error(ErrorCode::unsupported_algorithm, "post-quantum provider is not enabled; build with a vetted PQ backend such as liboqs");
}

std::vector<AlgorithmInfo> kem_algorithms() {
  const bool ok = available();
  return {
      {Family::ml_kem, "ML-KEM-512", static_cast<std::uint16_t>(kem::Algorithm::ml_kem_512), 1, 800, 1632, 768, 0, 32, ok},
      {Family::ml_kem, "ML-KEM-768", static_cast<std::uint16_t>(kem::Algorithm::ml_kem_768), 3, 1184, 2400, 1088, 0, 32, ok},
      {Family::ml_kem, "ML-KEM-1024", static_cast<std::uint16_t>(kem::Algorithm::ml_kem_1024), 5, 1568, 3168, 1568, 0, 32, ok},
  };
}

std::vector<AlgorithmInfo> signature_algorithms() {
  const bool ok = available();
  return {
      {Family::ml_dsa, "ML-DSA-44", static_cast<std::uint16_t>(sign::Algorithm::ml_dsa_44), 2, 1312, 2560, 0, 2420, 0, ok},
      {Family::ml_dsa, "ML-DSA-65", static_cast<std::uint16_t>(sign::Algorithm::ml_dsa_65), 3, 1952, 4032, 0, 3309, 0, ok},
      {Family::ml_dsa, "ML-DSA-87", static_cast<std::uint16_t>(sign::Algorithm::ml_dsa_87), 5, 2592, 4896, 0, 4627, 0, ok},
      {Family::slh_dsa, "SLH-DSA-SHA2-128s", static_cast<std::uint16_t>(sign::Algorithm::slh_dsa_sha2_128s), 1, 32, 64, 0, 7856, 0, ok},
  };
}

std::vector<KatCase> planned_kat_cases() {
  std::vector<KatCase> out;
  for (const auto& a : kem_algorithms()) out.push_back(KatCase{a.name + " KAT", a.family, a.algorithm_id, a.public_key_bytes, a.secret_key_bytes, a.ciphertext_bytes, a.shared_secret_bytes, true});
  for (const auto& a : signature_algorithms()) out.push_back(KatCase{a.name + " KAT", a.family, a.algorithm_id, a.public_key_bytes, a.secret_key_bytes, a.signature_bytes, 0, true});
  return out;
}

KatReport run_kat_harness() {
  KatReport report;
  report.backend = backend_name();
  report.provider_available = available();
  const auto cases = planned_kat_cases();
  report.vectors_planned = cases.size();
  if (!available()) return report;
  report.vectors_runnable = cases.size();
#if QUANTLIB_HAVE_LIBOQS
  // Provider smoke-KAT: not a fixed NIST response corpus, but it exercises keygen/encaps/decaps/sign/verify
  // through the linked vetted backend and catches wiring/size/roundtrip failures.
  for (const auto& c : cases) {
    bool ok = false;
    if (c.family == Family::ml_kem) {
      auto kp = kem_generate_keypair(static_cast<kem::Algorithm>(c.algorithm_id));
      if (kp) {
        auto enc = kem_encapsulate(kp.value().public_key);
        auto dec = enc ? kem_decapsulate(kp.value().secret_key, enc.value().ciphertext) : Result<Bytes>(enc.error());
        ok = enc.ok() && dec.ok() && enc.value().shared_secret == dec.value();
      }
    } else {
      auto kp = sign_generate_keypair(static_cast<sign::Algorithm>(c.algorithm_id));
      if (kp) {
        const Bytes msg{'p','q','-','k','a','t'};
        auto sig = sign_message(kp.value().secret_key, msg);
        auto ver = sig ? verify_message(kp.value().public_key, msg, sig.value()) : Result<bool>(sig.error());
        ok = sig.ok() && ver.ok() && ver.value();
      }
    }
    if (ok) ++report.vectors_passed; else ++report.vectors_failed;
  }
#endif
  return report;
}

Result<void> validate_algorithm_sizes() {
  for (const auto& a : kem_algorithms()) {
    if (a.public_key_bytes == 0 || a.secret_key_bytes == 0 || a.ciphertext_bytes == 0 || a.shared_secret_bytes != 32) return make_error(ErrorCode::invalid_argument, "invalid PQ KEM metadata for " + a.name);
  }
  for (const auto& a : signature_algorithms()) {
    if (a.public_key_bytes == 0 || a.secret_key_bytes == 0 || a.signature_bytes == 0) return make_error(ErrorCode::invalid_argument, "invalid PQ signature metadata for " + a.name);
  }
  return {};
}

Result<void> validate_provider_wiring() {
  auto sizes = validate_algorithm_sizes();
  if (!sizes) return sizes.error();
  const auto status = backend_status();
  if (status.runtime_available != available()) return make_error(ErrorCode::internal_error, "PQ provider status mismatch");
  if (!available()) {
    const auto e = ensure_available();
    if (e.ok()) return make_error(ErrorCode::internal_error, "PQ provider should fail closed when unavailable");
    return {};
  }
  const auto kat = run_kat_harness();
  if (kat.vectors_failed != 0 || kat.vectors_passed == 0) return make_error(ErrorCode::internal_error, "PQ provider smoke-KAT failed");
  return {};
}

Result<void> reject_downgrade(std::uint16_t negotiated_algorithm_id, std::uint16_t attempted_algorithm_id) {
  const auto* negotiated = find_algorithm(negotiated_algorithm_id);
  const auto* attempted = find_algorithm(attempted_algorithm_id);
  if (!negotiated || !attempted) return make_error(ErrorCode::invalid_argument, "unknown PQ algorithm id in downgrade check");
  if (attempted->family != negotiated->family) return make_error(ErrorCode::invalid_argument, "cross-family PQ downgrade/change rejected");
  if (attempted->nist_security_level < negotiated->nist_security_level) return make_error(ErrorCode::invalid_argument, "PQ downgrade rejected: attempted lower security level than negotiated suite");
  return {};
}

const AlgorithmInfo* find_algorithm(std::uint16_t algorithm_id) noexcept {
  static const std::vector<AlgorithmInfo> all = [] {
    auto kems = kem_algorithms();
    auto sigs = signature_algorithms();
    kems.insert(kems.end(), sigs.begin(), sigs.end());
    return kems;
  }();
  for (const auto& info : all) if (info.algorithm_id == algorithm_id) return &info;
  return nullptr;
}

Result<kem::KeyPair> kem_generate_keypair(kem::Algorithm algorithm) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_kem_name(algorithm);
  if (!name) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ KEM algorithm");
  KemPtr kem(OQS_KEM_new(name));
  if (!kem) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs KEM not available: ") + name);
  Bytes pub(kem->length_public_key), sec(kem->length_secret_key);
  if (OQS_KEM_keypair(kem.get(), pub.data(), sec.data()) != OQS_SUCCESS) return make_error(ErrorCode::internal_error, std::string("PQ KEM keypair failed: ") + name);
  return kem::KeyPair{kem::PublicKey{algorithm, std::move(pub)}, kem::SecretKey{algorithm, std::move(sec)}};
#else
  (void)algorithm;
  return make_error(ErrorCode::unsupported_algorithm, "PQ KEM provider is not enabled");
#endif
}

Result<kem::Encapsulation> kem_encapsulate(const kem::PublicKey& public_key) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_kem_name(public_key.algorithm);
  if (!name) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ KEM algorithm");
  KemPtr kem(OQS_KEM_new(name));
  if (!kem) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs KEM not available: ") + name);
  if (public_key.bytes.size() != kem->length_public_key) return make_error(ErrorCode::invalid_key, "PQ KEM public key size mismatch");
  Bytes ct(kem->length_ciphertext), ss(kem->length_shared_secret);
  if (OQS_KEM_encaps(kem.get(), ct.data(), ss.data(), public_key.bytes.data()) != OQS_SUCCESS) return make_error(ErrorCode::internal_error, std::string("PQ KEM encapsulation failed: ") + name);
  return kem::Encapsulation{std::move(ct), std::move(ss)};
#else
  (void)public_key;
  return make_error(ErrorCode::unsupported_algorithm, "PQ KEM provider is not enabled");
#endif
}

Result<Bytes> kem_decapsulate(const kem::SecretKey& secret_key, ByteView ciphertext) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_kem_name(secret_key.algorithm);
  if (!name) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ KEM algorithm");
  KemPtr kem(OQS_KEM_new(name));
  if (!kem) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs KEM not available: ") + name);
  if (secret_key.bytes.size() != kem->length_secret_key) return make_error(ErrorCode::invalid_key, "PQ KEM secret key size mismatch");
  if (ciphertext.size() != kem->length_ciphertext) return make_error(ErrorCode::invalid_argument, "PQ KEM ciphertext size mismatch");
  Bytes ss(kem->length_shared_secret);
  if (OQS_KEM_decaps(kem.get(), ss.data(), ciphertext.data(), secret_key.bytes.data()) != OQS_SUCCESS) return make_error(ErrorCode::authentication_failed, std::string("PQ KEM decapsulation failed: ") + name);
  return ss;
#else
  (void)secret_key; (void)ciphertext;
  return make_error(ErrorCode::unsupported_algorithm, "PQ KEM provider is not enabled");
#endif
}

Result<sign::KeyPair> sign_generate_keypair(sign::Algorithm algorithm) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_sig_name(algorithm);
  if (!name) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ signature algorithm");
  SigPtr sig(OQS_SIG_new(name));
  if (!sig) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs signature algorithm not available: ") + name);
  Bytes pub(sig->length_public_key), sec(sig->length_secret_key);
  if (OQS_SIG_keypair(sig.get(), pub.data(), sec.data()) != OQS_SUCCESS) return make_error(ErrorCode::internal_error, std::string("PQ signature keypair failed: ") + name);
  return sign::KeyPair{sign::PublicKey{algorithm, std::move(pub)}, sign::SecretKey{algorithm, std::move(sec)}};
#else
  (void)algorithm;
  return make_error(ErrorCode::unsupported_algorithm, "PQ signature provider is not enabled");
#endif
}

Result<sign::Signature> sign_message(const sign::SecretKey& secret_key, ByteView message) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_sig_name(secret_key.algorithm);
  if (!name) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ signature algorithm");
  SigPtr sig_alg(OQS_SIG_new(name));
  if (!sig_alg) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs signature algorithm not available: ") + name);
  if (secret_key.bytes.size() != sig_alg->length_secret_key) return make_error(ErrorCode::invalid_key, "PQ signature secret key size mismatch");
  Bytes sig(sig_alg->length_signature);
  std::size_t sig_len = 0;
  if (OQS_SIG_sign(sig_alg.get(), sig.data(), &sig_len, message.data(), message.size(), secret_key.bytes.data()) != OQS_SUCCESS) return make_error(ErrorCode::internal_error, std::string("PQ signature signing failed: ") + name);
  sig.resize(sig_len);
  return sign::Signature{secret_key.algorithm, std::move(sig)};
#else
  (void)secret_key; (void)message;
  return make_error(ErrorCode::unsupported_algorithm, "PQ signature provider is not enabled");
#endif
}

Result<bool> verify_message(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature) {
#if QUANTLIB_HAVE_LIBOQS
  const char* name = oqs_sig_name(public_key.algorithm);
  if (!name || signature.algorithm != public_key.algorithm) return make_error(ErrorCode::unsupported_algorithm, "unsupported PQ signature algorithm");
  SigPtr sig_alg(OQS_SIG_new(name));
  if (!sig_alg) return make_error(ErrorCode::unsupported_algorithm, std::string("liboqs signature algorithm not available: ") + name);
  if (public_key.bytes.size() != sig_alg->length_public_key) return make_error(ErrorCode::invalid_key, "PQ signature public key size mismatch");
  if (signature.bytes.size() > sig_alg->length_signature || signature.bytes.empty()) return make_error(ErrorCode::invalid_argument, "PQ signature size mismatch");
  const auto ok = OQS_SIG_verify(sig_alg.get(), message.data(), message.size(), signature.bytes.data(), signature.bytes.size(), public_key.bytes.data());
  return ok == OQS_SUCCESS;
#else
  (void)public_key; (void)message; (void)signature;
  return make_error(ErrorCode::unsupported_algorithm, "PQ signature provider is not enabled");
#endif
}

const char* family_name(Family family) noexcept {
  switch (family) {
    case Family::ml_kem: return "ML-KEM";
    case Family::ml_dsa: return "ML-DSA";
    case Family::slh_dsa: return "SLH-DSA";
    case Family::hqc: return "HQC";
  }
  return "unknown";
}

// Hybrid helpers are implemented here because this is the only translation unit that knows both
// the classical and PQ provider boundaries.
Result<kem::KeyPair> make_hybrid_kem_keypair() {
  auto classic = kem::generate_keypair(kem::Algorithm::x25519);
  if (!classic) return classic.error();
  auto pq = kem_generate_keypair(kem::Algorithm::ml_kem_768);
  if (!pq) return pq.error();
  auto pub = pack2(kHybridKemPublicMagic, classic.value().public_key.bytes, pq.value().public_key.bytes);
  auto sec = pack2(kHybridKemSecretMagic, classic.value().secret_key.bytes, pq.value().secret_key.bytes);
  return kem::KeyPair{kem::PublicKey{kem::Algorithm::hybrid_x25519_ml_kem_768, std::move(pub)}, kem::SecretKey{kem::Algorithm::hybrid_x25519_ml_kem_768, std::move(sec)}};
}

Result<kem::Encapsulation> encapsulate_hybrid_kem(const kem::PublicKey& public_key) {
  auto parts = unpack2(kHybridKemPublicMagic, public_key.bytes, "hybrid KEM public key");
  if (!parts) return parts.error();
  auto classic = kem::encapsulate(kem::PublicKey{kem::Algorithm::x25519, parts.value().first});
  if (!classic) return classic.error();
  auto pq = kem_encapsulate(kem::PublicKey{kem::Algorithm::ml_kem_768, parts.value().second});
  if (!pq) return pq.error();
  auto shared = hybrid_combine(classic.value().shared_secret, pq.value().shared_secret, hybrid::kHybridKemV1);
  if (!shared) return shared.error();
  Bytes ct = pack2(kHybridKemCipherMagic, classic.value().ciphertext, pq.value().ciphertext);
  return kem::Encapsulation{std::move(ct), std::move(shared).value()};
}

Result<Bytes> decapsulate_hybrid_kem(const kem::SecretKey& secret_key, ByteView ciphertext) {
  auto sec_parts = unpack2(kHybridKemSecretMagic, secret_key.bytes, "hybrid KEM secret key");
  if (!sec_parts) return sec_parts.error();
  auto ct_parts = unpack2(kHybridKemCipherMagic, ciphertext, "hybrid KEM ciphertext");
  if (!ct_parts) return ct_parts.error();
  auto classic = kem::decapsulate(kem::SecretKey{kem::Algorithm::x25519, sec_parts.value().first}, ct_parts.value().first);
  if (!classic) return classic.error();
  auto pq = kem_decapsulate(kem::SecretKey{kem::Algorithm::ml_kem_768, sec_parts.value().second}, ct_parts.value().second);
  if (!pq) return pq.error();
  return hybrid_combine(classic.value(), pq.value(), hybrid::kHybridKemV1);
}

Result<sign::KeyPair> make_hybrid_sign_keypair() {
  auto classic = sign::generate_keypair(sign::Algorithm::ed25519);
  if (!classic) return classic.error();
  auto pq = sign_generate_keypair(sign::Algorithm::ml_dsa_65);
  if (!pq) return pq.error();
  auto pub = pack2(kHybridSignPublicMagic, classic.value().public_key.bytes, pq.value().public_key.bytes);
  auto sec = pack2(kHybridSignSecretMagic, classic.value().secret_key.bytes, pq.value().secret_key.bytes);
  return sign::KeyPair{sign::PublicKey{sign::Algorithm::hybrid_ed25519_ml_dsa_65, std::move(pub)}, sign::SecretKey{sign::Algorithm::hybrid_ed25519_ml_dsa_65, std::move(sec)}};
}

Result<sign::Signature> sign_hybrid(const sign::SecretKey& secret_key, ByteView message) {
  auto parts = unpack2(kHybridSignSecretMagic, secret_key.bytes, "hybrid signature secret key");
  if (!parts) return parts.error();
  auto classic = sign::sign(sign::SecretKey{sign::Algorithm::ed25519, parts.value().first}, message);
  if (!classic) return classic.error();
  auto pq = sign_message(sign::SecretKey{sign::Algorithm::ml_dsa_65, parts.value().second}, message);
  if (!pq) return pq.error();
  return sign::Signature{sign::Algorithm::hybrid_ed25519_ml_dsa_65, pack2(kHybridSignSigMagic, classic.value().bytes, pq.value().bytes)};
}

Result<bool> verify_hybrid(const sign::PublicKey& public_key, ByteView message, const sign::Signature& signature) {
  auto key_parts = unpack2(kHybridSignPublicMagic, public_key.bytes, "hybrid signature public key");
  if (!key_parts) return key_parts.error();
  auto sig_parts = unpack2(kHybridSignSigMagic, signature.bytes, "hybrid signature");
  if (!sig_parts) return sig_parts.error();
  auto classic = sign::verify(sign::PublicKey{sign::Algorithm::ed25519, key_parts.value().first}, message, sign::Signature{sign::Algorithm::ed25519, sig_parts.value().first});
  if (!classic || !classic.value()) return classic.ok() ? Result<bool>(false) : Result<bool>(classic.error());
  auto pq = verify_message(sign::PublicKey{sign::Algorithm::ml_dsa_65, key_parts.value().second}, message, sign::Signature{sign::Algorithm::ml_dsa_65, sig_parts.value().second});
  if (!pq) return pq.error();
  return pq.value();
}

}  // namespace quantlib::pq

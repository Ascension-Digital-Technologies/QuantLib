#include "quantlib/kem.hpp"
#include "quantlib/sign.hpp"
#include "quantlib/pq.hpp"
#include "quantlib/secure.hpp"

#if QUANTLIB_HAVE_OPENSSL
#include <openssl/evp.h>
#include <memory>
#endif

namespace {
#if QUANTLIB_HAVE_OPENSSL
struct PkeyDeleter { void operator()(EVP_PKEY* p) const noexcept { EVP_PKEY_free(p); } };
struct CtxDeleter { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct MdCtxDeleter { void operator()(EVP_MD_CTX* p) const noexcept { EVP_MD_CTX_free(p); } };
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, CtxDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;

PkeyPtr generate_raw_key(int type) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new_id(type, nullptr));
  if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1) return nullptr;
  EVP_PKEY* raw = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) return nullptr;
  return PkeyPtr(raw);
}

quantlib::Result<quantlib::Bytes> raw_public(EVP_PKEY* key) {
  std::size_t len = 0;
  if (EVP_PKEY_get_raw_public_key(key, nullptr, &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "read public key length failed");
  quantlib::Bytes out(len);
  if (EVP_PKEY_get_raw_public_key(key, out.data(), &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "read public key failed");
  out.resize(len);
  return out;
}

quantlib::Result<quantlib::Bytes> raw_private(EVP_PKEY* key) {
  std::size_t len = 0;
  if (EVP_PKEY_get_raw_private_key(key, nullptr, &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "read private key length failed");
  quantlib::Bytes out(len);
  if (EVP_PKEY_get_raw_private_key(key, out.data(), &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "read private key failed");
  out.resize(len);
  return out;
}

PkeyPtr new_raw_public(int type, quantlib::ByteView bytes) {
  return PkeyPtr(EVP_PKEY_new_raw_public_key(type, nullptr, bytes.data(), bytes.size()));
}

PkeyPtr new_raw_private(int type, quantlib::ByteView bytes) {
  return PkeyPtr(EVP_PKEY_new_raw_private_key(type, nullptr, bytes.data(), bytes.size()));
}

quantlib::Result<quantlib::Bytes> derive_x25519(EVP_PKEY* secret, EVP_PKEY* peer) {
  PkeyCtxPtr ctx(EVP_PKEY_CTX_new(secret, nullptr));
  if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer) != 1) {
    return quantlib::make_error(quantlib::ErrorCode::invalid_key, "X25519 derive setup failed");
  }
  std::size_t len = 0;
  if (EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "X25519 derive length failed");
  quantlib::Bytes out(len);
  if (EVP_PKEY_derive(ctx.get(), out.data(), &len) != 1) return quantlib::make_error(quantlib::ErrorCode::internal_error, "X25519 derive failed");
  out.resize(len);
  return out;
}
#endif
}

namespace quantlib::kem {

Result<KeyPair> generate_keypair(Algorithm algorithm) {
  switch (algorithm) {
    case Algorithm::x25519: {
#if QUANTLIB_HAVE_OPENSSL
      auto key = generate_raw_key(EVP_PKEY_X25519);
      if (!key) return make_error(ErrorCode::internal_error, "X25519 key generation failed");
      auto pub = raw_public(key.get());
      auto sec = raw_private(key.get());
      if (!pub) return pub.error();
      if (!sec) return sec.error();
      return KeyPair{PublicKey{algorithm, std::move(pub).value()}, SecretKey{algorithm, std::move(sec).value()}};
#else
      return make_error(ErrorCode::unsupported_algorithm, "OpenSSL X25519 backend is not enabled");
#endif
    }
    case Algorithm::ml_kem_512:
    case Algorithm::ml_kem_768:
    case Algorithm::ml_kem_1024:
      return pq::kem_generate_keypair(algorithm);
    case Algorithm::hybrid_x25519_ml_kem_768:
      return pq::make_hybrid_kem_keypair();
  }
  return make_error(ErrorCode::unsupported_algorithm, "unknown KEM algorithm");
}

Result<Encapsulation> encapsulate(const PublicKey& public_key) {
  if (public_key.algorithm == Algorithm::ml_kem_512 || public_key.algorithm == Algorithm::ml_kem_768 || public_key.algorithm == Algorithm::ml_kem_1024) {
    return pq::kem_encapsulate(public_key);
  }
  if (public_key.algorithm == Algorithm::hybrid_x25519_ml_kem_768) {
    return pq::encapsulate_hybrid_kem(public_key);
  }
  if (public_key.algorithm != Algorithm::x25519) {
    return make_error(ErrorCode::unsupported_algorithm, "unsupported KEM encapsulation algorithm");
  }
  if (public_key.bytes.size() != 32) return make_error(ErrorCode::invalid_key, "X25519 public key must be 32 bytes");

#if QUANTLIB_HAVE_OPENSSL
  auto recipient = new_raw_public(EVP_PKEY_X25519, public_key.bytes);
  auto ephemeral = generate_raw_key(EVP_PKEY_X25519);
  if (!recipient || !ephemeral) return make_error(ErrorCode::invalid_key, "X25519 key import/generation failed");
  auto eph_public = raw_public(ephemeral.get());
  if (!eph_public) return eph_public.error();
  auto secret = derive_x25519(ephemeral.get(), recipient.get());
  if (!secret) return secret.error();
  return Encapsulation{std::move(eph_public).value(), std::move(secret).value()};
#else
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL X25519 backend is not enabled");
#endif
}

Result<Bytes> decapsulate(const SecretKey& secret_key, ByteView ciphertext) {
  if (secret_key.algorithm == Algorithm::ml_kem_512 || secret_key.algorithm == Algorithm::ml_kem_768 || secret_key.algorithm == Algorithm::ml_kem_1024) {
    return pq::kem_decapsulate(secret_key, ciphertext);
  }
  if (secret_key.algorithm == Algorithm::hybrid_x25519_ml_kem_768) {
    return pq::decapsulate_hybrid_kem(secret_key, ciphertext);
  }
  if (secret_key.algorithm != Algorithm::x25519) {
    return make_error(ErrorCode::unsupported_algorithm, "unsupported KEM decapsulation algorithm");
  }
  if (secret_key.bytes.size() != 32) return make_error(ErrorCode::invalid_key, "X25519 secret key must be 32 bytes");
  if (ciphertext.size() != 32) return make_error(ErrorCode::invalid_argument, "X25519 encapsulation ciphertext must be 32 bytes");

#if QUANTLIB_HAVE_OPENSSL
  auto secret = new_raw_private(EVP_PKEY_X25519, secret_key.bytes);
  auto peer = new_raw_public(EVP_PKEY_X25519, ciphertext);
  if (!secret || !peer) return make_error(ErrorCode::invalid_key, "X25519 key import failed");
  return derive_x25519(secret.get(), peer.get());
#else
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL X25519 backend is not enabled");
#endif
}

const char* name(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::x25519: return "X25519";
    case Algorithm::ml_kem_512: return "ML-KEM-512";
    case Algorithm::ml_kem_768: return "ML-KEM-768";
    case Algorithm::ml_kem_1024: return "ML-KEM-1024";
    case Algorithm::hybrid_x25519_ml_kem_768: return "X25519+ML-KEM-768";
  }
  return "unknown";
}

}  // namespace quantlib::kem

namespace quantlib::sign {

Result<KeyPair> generate_keypair(Algorithm algorithm) {
  switch (algorithm) {
    case Algorithm::ed25519: {
#if QUANTLIB_HAVE_OPENSSL
      auto key = generate_raw_key(EVP_PKEY_ED25519);
      if (!key) return make_error(ErrorCode::internal_error, "Ed25519 key generation failed");
      auto pub = raw_public(key.get());
      auto sec = raw_private(key.get());
      if (!pub) return pub.error();
      if (!sec) return sec.error();
      return KeyPair{PublicKey{algorithm, std::move(pub).value()}, SecretKey{algorithm, std::move(sec).value()}};
#else
      return make_error(ErrorCode::unsupported_algorithm, "OpenSSL Ed25519 backend is not enabled");
#endif
    }
    case Algorithm::secp256k1:
      return make_error(ErrorCode::unsupported_algorithm, "secp256k1 backend is not wired yet");
    case Algorithm::ml_dsa_44:
    case Algorithm::ml_dsa_65:
    case Algorithm::ml_dsa_87:
    case Algorithm::slh_dsa_sha2_128s:
      return pq::sign_generate_keypair(algorithm);
    case Algorithm::hybrid_ed25519_ml_dsa_65:
      return pq::make_hybrid_sign_keypair();
  }
  return make_error(ErrorCode::unsupported_algorithm, "unknown signature algorithm");
}

Result<Signature> sign(const SecretKey& secret_key, ByteView message) {
  if (secret_key.algorithm == Algorithm::ml_dsa_44 || secret_key.algorithm == Algorithm::ml_dsa_65 || secret_key.algorithm == Algorithm::ml_dsa_87 || secret_key.algorithm == Algorithm::slh_dsa_sha2_128s) {
    return pq::sign_message(secret_key, message);
  }
  if (secret_key.algorithm == Algorithm::hybrid_ed25519_ml_dsa_65) {
    return pq::sign_hybrid(secret_key, message);
  }
  if (secret_key.algorithm != Algorithm::ed25519) {
    return make_error(ErrorCode::unsupported_algorithm, "unsupported signing algorithm");
  }
  if (secret_key.bytes.size() != 32) return make_error(ErrorCode::invalid_key, "Ed25519 secret key must be 32 bytes");

#if QUANTLIB_HAVE_OPENSSL
  auto key = new_raw_private(EVP_PKEY_ED25519, secret_key.bytes);
  if (!key) return make_error(ErrorCode::invalid_key, "Ed25519 secret key import failed");
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return make_error(ErrorCode::internal_error, "EVP_MD_CTX_new failed");
  std::size_t sig_len = 0;
  if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
      EVP_DigestSign(ctx.get(), nullptr, &sig_len, message.data(), message.size()) != 1) {
    return make_error(ErrorCode::internal_error, "Ed25519 sign length failed");
  }
  Bytes sig(sig_len);
  if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, message.data(), message.size()) != 1) {
    secure_zero(sig.data(), sig.size());
    return make_error(ErrorCode::internal_error, "Ed25519 sign failed");
  }
  sig.resize(sig_len);
  return Signature{Algorithm::ed25519, std::move(sig)};
#else
  (void)message;
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL Ed25519 backend is not enabled");
#endif
}

Result<bool> verify(const PublicKey& public_key, ByteView message, const Signature& signature) {
  if ((public_key.algorithm == Algorithm::ml_dsa_44 || public_key.algorithm == Algorithm::ml_dsa_65 || public_key.algorithm == Algorithm::ml_dsa_87 || public_key.algorithm == Algorithm::slh_dsa_sha2_128s) && signature.algorithm == public_key.algorithm) {
    return pq::verify_message(public_key, message, signature);
  }
  if (public_key.algorithm == Algorithm::hybrid_ed25519_ml_dsa_65 && signature.algorithm == Algorithm::hybrid_ed25519_ml_dsa_65) {
    return pq::verify_hybrid(public_key, message, signature);
  }
  if (public_key.algorithm != Algorithm::ed25519 || signature.algorithm != Algorithm::ed25519) {
    return make_error(ErrorCode::unsupported_algorithm, "unsupported verification algorithm");
  }
  if (public_key.bytes.size() != 32) return make_error(ErrorCode::invalid_key, "Ed25519 public key must be 32 bytes");
  if (signature.bytes.size() != 64) return make_error(ErrorCode::invalid_argument, "Ed25519 signature must be 64 bytes");

#if QUANTLIB_HAVE_OPENSSL
  auto key = new_raw_public(EVP_PKEY_ED25519, public_key.bytes);
  if (!key) return make_error(ErrorCode::invalid_key, "Ed25519 public key import failed");
  MdCtxPtr ctx(EVP_MD_CTX_new());
  if (!ctx) return make_error(ErrorCode::internal_error, "EVP_MD_CTX_new failed");
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1) {
    return make_error(ErrorCode::internal_error, "Ed25519 verify setup failed");
  }
  const int ok = EVP_DigestVerify(ctx.get(), signature.bytes.data(), signature.bytes.size(), message.data(), message.size());
  if (ok == 1) return true;
  if (ok == 0) return false;
  return make_error(ErrorCode::invalid_argument, "Ed25519 verify failed");
#else
  (void)message; (void)signature;
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL Ed25519 backend is not enabled");
#endif
}

const char* name(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::ed25519: return "Ed25519";
    case Algorithm::secp256k1: return "secp256k1";
    case Algorithm::ml_dsa_44: return "ML-DSA-44";
    case Algorithm::ml_dsa_65: return "ML-DSA-65";
    case Algorithm::ml_dsa_87: return "ML-DSA-87";
    case Algorithm::slh_dsa_sha2_128s: return "SLH-DSA-SHA2-128s";
    case Algorithm::hybrid_ed25519_ml_dsa_65: return "Ed25519+ML-DSA-65";
  }
  return "unknown";
}

}  // namespace quantlib::sign

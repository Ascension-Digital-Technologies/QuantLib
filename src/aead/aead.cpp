#include "quantlib/aead.hpp"
#include "quantlib/rng.hpp"
#include "quantlib/secure.hpp"

#if QUANTLIB_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace quantlib::aead {
namespace {

constexpr std::size_t kKeySize = 32;
constexpr std::size_t kNonceSize = 12;
constexpr std::size_t kTagSize = 16;

#if QUANTLIB_HAVE_OPENSSL
const EVP_CIPHER* cipher_for(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::aes_256_gcm: return EVP_aes_256_gcm();
    case Algorithm::chacha20_poly1305: return EVP_chacha20_poly1305();
  }
  return nullptr;
}
#endif

}  // namespace

Result<Ciphertext> encrypt(Algorithm algorithm, ByteView key, ByteView plaintext, ByteView associated_data) {
  auto nonce_result = rng::random_bytes(kNonceSize);
  if (!nonce_result) return nonce_result.error();
  return encrypt_with_nonce(algorithm, key, nonce_result.value(), plaintext, associated_data);
}

Result<Ciphertext> encrypt_with_nonce(Algorithm algorithm, ByteView key, ByteView nonce, ByteView plaintext, ByteView associated_data) {
  if (key.size() != kKeySize) return make_error(ErrorCode::invalid_key, "AEAD key must be 32 bytes");
  if (nonce.size() != kNonceSize) return make_error(ErrorCode::invalid_argument, "AEAD nonce must be 12 bytes");

#if QUANTLIB_HAVE_OPENSSL
  const EVP_CIPHER* cipher = cipher_for(algorithm);
  if (cipher == nullptr) return make_error(ErrorCode::unsupported_algorithm, "unknown AEAD algorithm");

  Ciphertext out{};
  out.nonce.assign(nonce.begin(), nonce.end());
  out.data.resize(plaintext.size() + kTagSize);
  out.tag.resize(kTagSize);

  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (raw == nullptr) return make_error(ErrorCode::internal_error, "EVP_CIPHER_CTX_new failed");

  int len = 0;
  int total = 0;
  bool ok = true;
  ok = ok && EVP_EncryptInit_ex(raw, cipher, nullptr, nullptr, nullptr) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(out.nonce.size()), nullptr) == 1;
  ok = ok && EVP_EncryptInit_ex(raw, nullptr, nullptr, key.data(), out.nonce.data()) == 1;
  if (!associated_data.empty()) {
    ok = ok && EVP_EncryptUpdate(raw, nullptr, &len, associated_data.data(), static_cast<int>(associated_data.size())) == 1;
  }
  if (!plaintext.empty()) {
    ok = ok && EVP_EncryptUpdate(raw, out.data.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1;
    total += len;
  }
  ok = ok && EVP_EncryptFinal_ex(raw, out.data.data() + total, &len) == 1;
  total += len;
  out.data.resize(static_cast<std::size_t>(total));
  ok = ok && EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(out.tag.size()), out.tag.data()) == 1;
  EVP_CIPHER_CTX_free(raw);

  if (!ok) return make_error(ErrorCode::internal_error, "AEAD encryption failed");
  return out;
#else
  (void)algorithm; (void)plaintext; (void)associated_data;
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL AEAD backend is not enabled");
#endif
}

Result<Bytes> decrypt(Algorithm algorithm, ByteView key, const Ciphertext& ciphertext, ByteView associated_data) {
  if (key.size() != kKeySize) return make_error(ErrorCode::invalid_key, "AEAD key must be 32 bytes");
  if (ciphertext.nonce.size() != kNonceSize) return make_error(ErrorCode::invalid_argument, "AEAD nonce must be 12 bytes");
  if (ciphertext.tag.size() != kTagSize) return make_error(ErrorCode::invalid_argument, "AEAD tag must be 16 bytes");

#if QUANTLIB_HAVE_OPENSSL
  const EVP_CIPHER* cipher = cipher_for(algorithm);
  if (cipher == nullptr) return make_error(ErrorCode::unsupported_algorithm, "unknown AEAD algorithm");

  Bytes out(ciphertext.data.size() + kTagSize);
  EVP_CIPHER_CTX* raw = EVP_CIPHER_CTX_new();
  if (raw == nullptr) return make_error(ErrorCode::internal_error, "EVP_CIPHER_CTX_new failed");

  int len = 0;
  int total = 0;
  bool ok = true;
  ok = ok && EVP_DecryptInit_ex(raw, cipher, nullptr, nullptr, nullptr) == 1;
  ok = ok && EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(ciphertext.nonce.size()), nullptr) == 1;
  ok = ok && EVP_DecryptInit_ex(raw, nullptr, nullptr, key.data(), ciphertext.nonce.data()) == 1;
  if (!associated_data.empty()) {
    ok = ok && EVP_DecryptUpdate(raw, nullptr, &len, associated_data.data(), static_cast<int>(associated_data.size())) == 1;
  }
  if (!ciphertext.data.empty()) {
    ok = ok && EVP_DecryptUpdate(raw, out.data(), &len, ciphertext.data.data(), static_cast<int>(ciphertext.data.size())) == 1;
    total += len;
  }
  ok = ok && EVP_CIPHER_CTX_ctrl(raw, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(ciphertext.tag.size()), const_cast<std::uint8_t*>(ciphertext.tag.data())) == 1;
  const int final_ok = EVP_DecryptFinal_ex(raw, out.data() + total, &len);
  EVP_CIPHER_CTX_free(raw);

  if (!ok || final_ok != 1) {
    secure_zero(out.data(), out.size());
    return make_error(ErrorCode::authentication_failed, "AEAD authentication failed");
  }
  total += len;
  out.resize(static_cast<std::size_t>(total));
  return out;
#else
  (void)algorithm; (void)ciphertext; (void)associated_data;
  return make_error(ErrorCode::unsupported_algorithm, "OpenSSL AEAD backend is not enabled");
#endif
}

const char* name(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::aes_256_gcm: return "AES-256-GCM";
    case Algorithm::chacha20_poly1305: return "ChaCha20-Poly1305";
  }
  return "unknown";
}

}  // namespace quantlib::aead

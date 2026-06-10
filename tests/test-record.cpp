#include "quantlib/aead.hpp"
#include "quantlib/record.hpp"
#include "quantlib/session.hpp"
#include <cstdlib>
#include <iostream>
#include <string_view>

namespace {
#define CHECK(expr) do { if (!(expr)) { std::cerr << "record check failed: " #expr "\n"; std::exit(1); } } while (false)

quantlib::ByteView view(std::string_view s) {
  return quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

void run_record_tests() {
  quantlib::Bytes client_nonce(12, 0x11);
  quantlib::Bytes server_nonce(12, 0x22);
  quantlib::Bytes transcript(32, 0x33);
  quantlib::Bytes shared(32, 0x44);

  auto hello = quantlib::session::make_hello(client_nonce, server_nonce, transcript);
  CHECK(hello);
  auto hs = quantlib::session::derive_handshake_secret(shared, hello.value());
  CHECK(hs);
  auto keys = quantlib::session::derive_keys(hs.value(), hello.value());
  CHECK(keys);

  auto n0 = quantlib::record::sequence_nonce(keys.value().client_write_nonce, 7);
  auto n1 = quantlib::record::sequence_nonce(keys.value().client_write_nonce, 8);
  CHECK(n0 && n1);
  CHECK(n0.value() != n1.value());

  auto sealed = quantlib::record::seal(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), quantlib::session::Role::client,
                                   quantlib::record::ContentType::data, 7, view("hello-record"), view("rpc:/submit"));
  CHECK(sealed);
  auto encoded = quantlib::record::encode_frame(sealed.value());
  CHECK(encoded);
  auto decoded = quantlib::record::decode_frame(encoded.value());
  CHECK(decoded);
  auto opened = quantlib::record::open(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), decoded.value(), view("rpc:/submit"));
  CHECK(opened);
  CHECK(std::string_view(reinterpret_cast<const char*>(opened.value().data()), opened.value().size()) == "hello-record");

  auto bad_aad = quantlib::record::open(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), decoded.value(), view("rpc:/other"));
  CHECK(!bad_aad);

  auto tampered = decoded.value();
  tampered.ciphertext[0] ^= 0x01;
  auto bad_ct = quantlib::record::open(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), tampered, view("rpc:/submit"));
  CHECK(!bad_ct);

  auto bad_nonce = decoded.value();
  bad_nonce.nonce[0] ^= 0x01;
  auto bad_nonce_open = quantlib::record::open(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), bad_nonce, view("rpc:/submit"));
  CHECK(!bad_nonce_open);

  auto alert = quantlib::record::seal_alert(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), quantlib::session::Role::server,
                                        9, quantlib::record::AlertCode::key_update_required, view("rpc:/control"));
  CHECK(alert);
  auto decoded_alert = quantlib::record::open_alert(quantlib::aead::Algorithm::chacha20_poly1305, keys.value(), alert.value(), view("rpc:/control"));
  CHECK(decoded_alert);
  CHECK(decoded_alert.value() == quantlib::record::AlertCode::key_update_required);
  CHECK(std::string_view(quantlib::record::alert_name(decoded_alert.value())) == "key_update_required");
}

struct Runner { Runner() { run_record_tests(); } } runner;
}  // namespace

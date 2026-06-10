#include "quantlib/quantlib.hpp"
#include <cassert>

int run_session_tests() {
  const quantlib::Bytes client_nonce(12, 0x11);
  const quantlib::Bytes server_nonce(12, 0x22);
  const quantlib::Bytes transcript_hash(32, 0x33);
  const quantlib::Bytes shared_secret(32, 0x44);
  const quantlib::Bytes context{0xaa, 0xbb, 0xcc};

  const auto bad = quantlib::session::make_hello(quantlib::Bytes{1}, server_nonce, transcript_hash);
  assert(!bad.ok());

  const auto hello = quantlib::session::make_hello(client_nonce, server_nonce, transcript_hash);
  assert(hello.ok());

  const auto hs1 = quantlib::session::derive_handshake_secret(shared_secret, hello.value());
  const auto hs2 = quantlib::session::derive_handshake_secret(shared_secret, hello.value());
  assert(hs1.ok());
  assert(hs2.ok());
  assert(hs1.value().size() == 32);
  assert(hs1.value() == hs2.value());

  const auto keys = quantlib::session::derive_keys(hs1.value(), hello.value());
  assert(keys.ok());
  assert(keys.value().client_write_key.size() == 32);
  assert(keys.value().server_write_key.size() == 32);
  assert(keys.value().client_write_nonce.size() == 12);
  assert(keys.value().server_write_nonce.size() == 12);
  assert(keys.value().client_write_key != keys.value().server_write_key);
  assert(keys.value().client_write_nonce != keys.value().server_write_nonce);

  const auto client_tag = quantlib::session::confirmation_tag(quantlib::session::Role::client, hs1.value(), hello.value(), context);
  const auto server_tag = quantlib::session::confirmation_tag(quantlib::session::Role::server, hs1.value(), hello.value(), context);
  assert(client_tag.ok());
  assert(server_tag.ok());
  assert(client_tag.value().size() == 32);
  assert(client_tag.value() != server_tag.value());
  assert(quantlib::session::verify_confirmation(quantlib::session::Role::client, client_tag.value(), hs1.value(), hello.value(), context).ok());

  quantlib::Bytes tampered = client_tag.value();
  tampered[0] ^= 0x01;
  const auto verify_bad = quantlib::session::verify_confirmation(quantlib::session::Role::client, tampered, hs1.value(), hello.value(), context);
  assert(!verify_bad.ok());
  assert(verify_bad.error().code == quantlib::ErrorCode::authentication_failed);

  const auto exported1 = quantlib::session::export_secret(keys.value().exporter_secret, "rpc channel", context, 32);
  const auto exported2 = quantlib::session::export_secret(keys.value().exporter_secret, "storage channel", context, 32);
  assert(exported1.ok());
  assert(exported2.ok());
  assert(exported1.value() != exported2.value());

  const auto updated1 = quantlib::session::update_keys(keys.value(), hello.value(), 1, context);
  const auto updated2 = quantlib::session::update_keys(keys.value(), hello.value(), 1, context);
  const auto updated3 = quantlib::session::update_keys(keys.value(), hello.value(), 2, context);
  assert(updated1.ok());
  assert(updated2.ok());
  assert(updated3.ok());
  assert(updated1.value().client_write_key == updated2.value().client_write_key);
  assert(updated1.value().client_write_key != keys.value().client_write_key);
  assert(updated1.value().client_write_key != updated3.value().client_write_key);
  const auto update_tag = quantlib::session::key_update_tag(keys.value(), hello.value(), 1, context);
  assert(update_tag.ok());
  assert(update_tag.value().size() == quantlib::session::kConfirmationBytes);
  assert(!quantlib::session::update_keys(keys.value(), hello.value(), 0, context).ok());
  return 0;
}

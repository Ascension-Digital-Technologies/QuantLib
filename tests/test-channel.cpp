#include "quantlib/quantlib.hpp"
#include <cassert>
#include <string_view>

namespace {
quantlib::ByteView view(std::string_view s) {
  return quantlib::ByteView(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
}

std::string as_string(const quantlib::Bytes& bytes) {
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}
}

int run_channel_tests() {
  const quantlib::Bytes client_nonce(12, 0x11);
  const quantlib::Bytes server_nonce(12, 0x22);
  const quantlib::Bytes transcript_hash(32, 0x33);
  const quantlib::Bytes shared_secret(32, 0x44);
  const quantlib::Bytes context{0x01, 0x02, 0x03};

  const auto hello = quantlib::session::make_hello(client_nonce, server_nonce, transcript_hash);
  assert(hello.ok());
  const auto hs = quantlib::session::derive_handshake_secret(shared_secret, hello.value());
  assert(hs.ok());
  const auto material = quantlib::session::derive_keys(hs.value(), hello.value());
  assert(material.ok());

  quantlib::channel::ChannelConfig config;
  config.algorithm = quantlib::aead::Algorithm::chacha20_poly1305;
  config.rekey_interval = 2;
  config.associated_context = context;

  auto client = quantlib::channel::make_channel(material.value(), quantlib::session::Role::client);
  auto server = quantlib::channel::make_channel(material.value(), quantlib::session::Role::server);
  assert(client.ok());
  assert(server.ok());

  auto frame1 = quantlib::channel::seal_data(client.value(), config, view("hello"), view("rpc:/submit"));
  assert(frame1.ok());
  assert(client.value().send_sequence == 1);
  auto opened1 = quantlib::channel::open(server.value(), config, frame1.value(), view("rpc:/submit"));
  assert(opened1.ok());
  assert(opened1.value().type == quantlib::record::ContentType::data);
  assert(as_string(opened1.value().plaintext) == "hello");

  const auto duplicate = quantlib::channel::open(server.value(), config, frame1.value(), view("rpc:/submit"));
  assert(!duplicate.ok());

  auto frame2 = quantlib::channel::seal_data(client.value(), config, view("again"), view("rpc:/submit"));
  assert(frame2.ok());
  assert(quantlib::channel::should_rekey(client.value(), config));
  auto opened2 = quantlib::channel::open(server.value(), config, frame2.value(), view("rpc:/submit"));
  assert(opened2.ok());
  assert(as_string(opened2.value().plaintext) == "again");

  auto update_frame = quantlib::channel::seal_key_update(client.value(), config, hello.value(), context, view("rpc:/control"));
  assert(update_frame.ok());
  assert(client.value().generation == 1);
  assert(client.value().send_sequence == 0);
  auto update_record = quantlib::channel::open(server.value(), config, update_frame.value(), view("rpc:/control"));
  assert(update_record.ok());
  assert(update_record.value().type == quantlib::record::ContentType::key_update);
  auto apply = quantlib::channel::apply_key_update(server.value(), update_record.value(), hello.value(), context);
  assert(apply.ok());
  assert(server.value().generation == 1);

  auto after_update = quantlib::channel::seal_data(client.value(), config, view("post-rekey"), view("rpc:/submit"));
  assert(after_update.ok());
  auto opened3 = quantlib::channel::open(server.value(), config, after_update.value(), view("rpc:/submit"));
  assert(opened3.ok());
  assert(as_string(opened3.value().plaintext) == "post-rekey");

  auto reply = quantlib::channel::seal_data(server.value(), config, view("reply"), view("rpc:/reply"));
  assert(reply.ok());
  auto opened_reply = quantlib::channel::open(client.value(), config, reply.value(), view("rpc:/reply"));
  assert(opened_reply.ok());
  assert(as_string(opened_reply.value().plaintext) == "reply");

  auto close_frame = quantlib::channel::seal_alert(server.value(), config, quantlib::record::AlertCode::close_notify, view("rpc:/control"));
  assert(close_frame.ok());
  assert(server.value().closed);
  auto close_record = quantlib::channel::open(client.value(), config, close_frame.value(), view("rpc:/control"));
  assert(close_record.ok());
  assert(client.value().closed);

  const auto closed_send = quantlib::channel::seal_data(client.value(), config, view("nope"), view("rpc:/submit"));
  assert(!closed_send.ok());
  return 0;
}

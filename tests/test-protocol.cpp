#include "quantlib/quantlib.hpp"
#include <cassert>

static void test_protocol_negotiation_and_downgrade() {
  quantlib::protocol::NegotiationInput input;
  input.policy = quantlib::policy::make_policy(quantlib::policy::Profile::fast);
  const std::vector<std::uint16_t> offered{0x0102, 0x0101};
  auto negotiated = quantlib::protocol::negotiate(input, offered);
  assert(negotiated.ok());
  assert(negotiated.value().suite.id == 0x0102 || negotiated.value().suite.id == 0x0101);
  auto downgrade = quantlib::protocol::reject_downgrade({0x0103, 0x0101}, *quantlib::protocol::find_suite(0x0101, quantlib::protocol::default_cipher_suites()));
  assert(!downgrade.ok());
}

static void test_protocol_hello_and_state_machine() {
  auto hello = quantlib::session::make_hello(quantlib::Bytes(12, 0x01), quantlib::Bytes(12, 0x02), quantlib::Bytes(32, 0x03));
  assert(hello.ok());
  quantlib::protocol::HandshakeLimits limits;
  auto ch = quantlib::protocol::encode_client_hello(hello.value(), quantlib::protocol::default_cipher_suites(), limits);
  assert(ch.ok());
  quantlib::protocol::HandshakeContext client;
  client.role = quantlib::session::Role::client;
  assert(quantlib::protocol::mark_sent(client, quantlib::record::ContentType::handshake).ok());
  assert(client.state == quantlib::protocol::HandshakeState::client_hello_sent);
  assert(quantlib::protocol::absorb_handshake(client, ch.value()).ok());
  quantlib::protocol::HandshakeContext server;
  server.role = quantlib::session::Role::server;
  assert(quantlib::protocol::mark_received(server, quantlib::record::ContentType::handshake).ok());
  assert(server.state == quantlib::protocol::HandshakeState::client_hello_received);
}

static void test_protocol_limits() {
  quantlib::protocol::HandshakeLimits limits;
  limits.max_frame_bytes = 64;
  limits.max_record_plaintext = 4;
  assert(quantlib::protocol::validate_plaintext_limits(quantlib::Bytes{1,2,3,4}, limits).ok());
  assert(!quantlib::protocol::validate_plaintext_limits(quantlib::Bytes{1,2,3,4,5}, limits).ok());
  assert(!quantlib::protocol::validate_frame_limits(quantlib::Bytes(65, 0), limits).ok());
}

int run_protocol_tests() {
  test_protocol_negotiation_and_downgrade();
  test_protocol_hello_and_state_machine();
  test_protocol_limits();
  return 0;
}

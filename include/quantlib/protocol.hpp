#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/bytes.hpp"
#include "quantlib/kem.hpp"
#include "quantlib/policy.hpp"
#include "quantlib/record.hpp"
#include "quantlib/result.hpp"
#include "quantlib/session.hpp"
#include "quantlib/sign.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace quantlib::protocol {

inline constexpr const char* kQuantLinkV1 = "QuantLink v1";
inline constexpr std::uint8_t kHandshakeVersion = 1;
inline constexpr std::uint32_t kDefaultMaxRecordPlaintext = 1u << 20; // 1 MiB
inline constexpr std::uint32_t kDefaultMaxFrameBytes = kDefaultMaxRecordPlaintext + record::kRecordHeaderBytes + session::kSessionNonceBytes + 16;

enum class HandshakeState : std::uint8_t {
  start,
  client_hello_sent,
  client_hello_received,
  server_hello_sent,
  server_hello_received,
  established,
  closed,
  failed
};

struct CipherSuite {
  std::uint16_t id{0x0101};
  std::string name{"QUANTLIBLINK_X25519_ED25519_CHACHA20_SHA256"};
  kem::Algorithm kem_algorithm{kem::Algorithm::x25519};
  sign::Algorithm signature_algorithm{sign::Algorithm::ed25519};
  aead::Algorithm aead_algorithm{aead::Algorithm::chacha20_poly1305};
  int security_level{3};
  bool hybrid{false};
  bool pq{false};
};

struct HandshakeLimits {
  std::uint32_t max_record_plaintext{kDefaultMaxRecordPlaintext};
  std::uint32_t max_frame_bytes{kDefaultMaxFrameBytes};
  std::uint64_t rekey_after_records{1'000'000};
  std::uint64_t rekey_after_seconds{3600};
  bool require_close_notify{true};
};

struct NegotiationInput {
  std::vector<CipherSuite> offered_suites{};
  policy::AlgorithmPolicy policy{policy::make_policy(policy::Profile::balanced)};
  HandshakeLimits limits{};
};

struct NegotiatedProtocol {
  CipherSuite suite{};
  HandshakeLimits limits{};
  Bytes transcript_hash{};
};

struct HandshakeContext {
  session::Role role{session::Role::client};
  HandshakeState state{HandshakeState::start};
  NegotiatedProtocol negotiated{};
  session::Hello local_hello{};
  session::Hello peer_hello{};
  Bytes transcript_hash{};
  bool downgrade_rejected{false};
  bool close_notify_seen{false};
};

[[nodiscard]] std::vector<CipherSuite> default_cipher_suites();
[[nodiscard]] const CipherSuite* find_suite(std::uint16_t id, const std::vector<CipherSuite>& suites) noexcept;
[[nodiscard]] Result<NegotiatedProtocol> negotiate(const NegotiationInput& local, const std::vector<std::uint16_t>& peer_offered_suite_ids);
[[nodiscard]] Result<void> reject_downgrade(const std::vector<std::uint16_t>& offered_suite_ids, const CipherSuite& selected);
[[nodiscard]] Result<Bytes> encode_client_hello(const session::Hello& hello, const std::vector<CipherSuite>& suites, const HandshakeLimits& limits);
[[nodiscard]] Result<Bytes> encode_server_hello(const session::Hello& hello, const CipherSuite& selected, const HandshakeLimits& limits);
[[nodiscard]] Result<void> absorb_handshake(HandshakeContext& ctx, ByteView message);
[[nodiscard]] Result<void> mark_sent(HandshakeContext& ctx, record::ContentType type);
[[nodiscard]] Result<void> mark_received(HandshakeContext& ctx, record::ContentType type);
[[nodiscard]] Result<void> validate_frame_limits(ByteView encoded_frame, const HandshakeLimits& limits);
[[nodiscard]] Result<void> validate_plaintext_limits(ByteView plaintext, const HandshakeLimits& limits);
[[nodiscard]] Result<void> validate_close_notify_required(const HandshakeContext& ctx);
[[nodiscard]] const char* state_name(HandshakeState state) noexcept;
[[nodiscard]] std::string describe_suite(const CipherSuite& suite);

}  // namespace quantlib::protocol

#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include "quantlib/session.hpp"
#include <cstdint>

namespace quantlib::record {

inline constexpr const char* kRecordV1 = "QuantLib Record v1";
inline constexpr std::uint8_t kRecordVersion = 1;
inline constexpr std::uint8_t kRecordHeaderBytes = 19;
inline constexpr std::uint64_t kMaxSequence = 0xffff'ffff'ffff'fffeULL;

enum class AlertCode : std::uint8_t {
  close_notify = 0x00,
  unexpected_message = 0x0a,
  bad_record_mac = 0x14,
  protocol_error = 0x2f,
  key_update_required = 0x40,
};

enum class ContentType : std::uint8_t {
  data = 0x01,
  handshake = 0x02,
  alert = 0x03,
  key_update = 0x04,
};

struct Header {
  std::uint8_t version{kRecordVersion};
  ContentType type{ContentType::data};
  session::Role role{session::Role::client};
  std::uint64_t sequence{0};
  std::uint32_t ciphertext_len{0};
  std::uint32_t tag_len{16};
};

struct Frame {
  Header header{};
  Bytes nonce{};
  Bytes ciphertext{};
  Bytes tag{};
};

[[nodiscard]] Result<Bytes> sequence_nonce(ByteView base_nonce, std::uint64_t sequence);
[[nodiscard]] Result<Bytes> encode_header(const Header& header);
[[nodiscard]] Result<Header> decode_header(ByteView header);
[[nodiscard]] Result<Frame> seal(aead::Algorithm algorithm, const session::KeyMaterial& material, session::Role role,
                                 ContentType type, std::uint64_t sequence, ByteView plaintext, ByteView associated_data = {});
[[nodiscard]] Result<Bytes> open(aead::Algorithm algorithm, const session::KeyMaterial& material, const Frame& frame,
                                 ByteView associated_data = {});
[[nodiscard]] Result<Frame> seal_alert(aead::Algorithm algorithm, const session::KeyMaterial& material, session::Role role,
                                      std::uint64_t sequence, AlertCode code, ByteView associated_data = {});
[[nodiscard]] Result<AlertCode> open_alert(aead::Algorithm algorithm, const session::KeyMaterial& material, const Frame& frame,
                                           ByteView associated_data = {});
[[nodiscard]] Result<Bytes> encode_frame(const Frame& frame);
[[nodiscard]] Result<Frame> decode_frame(ByteView frame);
[[nodiscard]] const char* content_type_name(ContentType type) noexcept;
[[nodiscard]] const char* alert_name(AlertCode code) noexcept;

}  // namespace quantlib::record

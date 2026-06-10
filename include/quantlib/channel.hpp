#pragma once
#include "quantlib/aead.hpp"
#include "quantlib/bytes.hpp"
#include "quantlib/record.hpp"
#include "quantlib/replay.hpp"
#include "quantlib/result.hpp"
#include "quantlib/session.hpp"
#include <cstdint>

namespace quantlib::channel {

inline constexpr const char* kChannelV1 = "QuantLib Channel v1";
inline constexpr std::uint64_t kDefaultRekeyInterval = 1'000'000;

struct ChannelConfig {
  aead::Algorithm algorithm{aead::Algorithm::chacha20_poly1305};
  std::uint64_t rekey_interval{kDefaultRekeyInterval};
  Bytes associated_context{};
};

struct ChannelState {
  session::KeyMaterial material{};
  session::Role local_role{session::Role::client};
  std::uint64_t send_sequence{0};
  std::uint64_t generation{0};
  replay::ReplayWindow receive_window{};
  bool closed{false};
};

struct ReceivedRecord {
  record::ContentType type{record::ContentType::data};
  session::Role sender{session::Role::client};
  std::uint64_t sequence{0};
  Bytes plaintext{};
};

[[nodiscard]] Result<ChannelState> make_channel(const session::KeyMaterial& material, session::Role local_role,
                                                std::uint64_t generation = 0);
[[nodiscard]] session::Role peer_role(session::Role local_role) noexcept;
[[nodiscard]] Result<Bytes> seal(ChannelState& state, const ChannelConfig& config, record::ContentType type,
                                 ByteView plaintext, ByteView associated_data = {});
[[nodiscard]] Result<Bytes> seal_data(ChannelState& state, const ChannelConfig& config, ByteView plaintext,
                                      ByteView associated_data = {});
[[nodiscard]] Result<ReceivedRecord> open(ChannelState& state, const ChannelConfig& config, ByteView encoded_frame,
                                          ByteView associated_data = {});
[[nodiscard]] Result<Bytes> seal_alert(ChannelState& state, const ChannelConfig& config, record::AlertCode code,
                                       ByteView associated_data = {});
[[nodiscard]] Result<Bytes> seal_key_update(ChannelState& state, const ChannelConfig& config, const session::Hello& hello,
                                            ByteView context = {}, ByteView associated_data = {});
[[nodiscard]] Result<void> apply_key_update(ChannelState& state, const ReceivedRecord& record, const session::Hello& hello,
                                            ByteView context = {});
[[nodiscard]] bool should_rekey(const ChannelState& state, const ChannelConfig& config) noexcept;
void close(ChannelState& state) noexcept;

}  // namespace quantlib::channel

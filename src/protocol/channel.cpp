#include "quantlib/channel.hpp"
#include "quantlib/secure.hpp"
#include <limits>

namespace quantlib::channel {
namespace {
void put_u64(Bytes& out, std::uint64_t value) {
  const std::size_t off = out.size();
  out.resize(off + 8);
  for (std::size_t i = 0; i < 8; ++i) {
    const int shift = 56 - static_cast<int>(i * 8);
    out[off + i] = static_cast<std::uint8_t>((value >> shift) & 0xff);
  }
}

std::uint64_t read_u64(ByteView in) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | in[i];
  return value;
}

Result<Bytes> merged_aad(const ChannelConfig& config, ByteView associated_data) {
  if (config.associated_context.size() > std::numeric_limits<std::uint32_t>::max() ||
      associated_data.size() > std::numeric_limits<std::uint32_t>::max()) {
    return make_error(ErrorCode::invalid_argument, "associated data too large");
  }
  Bytes out;
  out.reserve(8 + config.associated_context.size() + associated_data.size());
  const auto put_u32 = [&](std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<std::uint8_t>(value & 0xff));
  };
  put_u32(static_cast<std::uint32_t>(config.associated_context.size()));
  out.insert(out.end(), config.associated_context.begin(), config.associated_context.end());
  put_u32(static_cast<std::uint32_t>(associated_data.size()));
  out.insert(out.end(), associated_data.begin(), associated_data.end());
  return out;
}

Result<void> validate_material(const session::KeyMaterial& material) {
  if (material.client_write_key.size() != session::kSessionKeyBytes) return make_error(ErrorCode::invalid_key, "client write key must be 32 bytes");
  if (material.server_write_key.size() != session::kSessionKeyBytes) return make_error(ErrorCode::invalid_key, "server write key must be 32 bytes");
  if (material.client_write_nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_key, "client write nonce must be 12 bytes");
  if (material.server_write_nonce.size() != session::kSessionNonceBytes) return make_error(ErrorCode::invalid_key, "server write nonce must be 12 bytes");
  return {};
}

Result<Bytes> make_key_update_payload(const session::KeyMaterial& material, const session::Hello& hello,
                                      std::uint64_t generation, ByteView context) {
  auto tag = session::key_update_tag(material, hello, generation, context);
  if (!tag) return tag.error();
  Bytes payload;
  payload.reserve(8 + tag.value().size());
  put_u64(payload, generation);
  payload.insert(payload.end(), tag.value().begin(), tag.value().end());
  return payload;
}
}  // namespace

Result<ChannelState> make_channel(const session::KeyMaterial& material, session::Role local_role, std::uint64_t generation) {
  auto valid = validate_material(material);
  if (!valid) return valid.error();
  ChannelState state;
  state.material = material;
  state.local_role = local_role;
  state.send_sequence = 0;
  state.generation = generation;
  state.receive_window = {};
  state.closed = false;
  return state;
}

session::Role peer_role(session::Role local_role) noexcept {
  return local_role == session::Role::client ? session::Role::server : session::Role::client;
}

Result<Bytes> seal(ChannelState& state, const ChannelConfig& config, record::ContentType type,
                   ByteView plaintext, ByteView associated_data) {
  if (state.closed) return make_error(ErrorCode::invalid_argument, "channel is closed");
  if (state.send_sequence > record::kMaxSequence) return make_error(ErrorCode::invalid_argument, "send sequence exhausted");
  auto aad = merged_aad(config, associated_data);
  if (!aad) return aad.error();
  auto frame = record::seal(config.algorithm, state.material, state.local_role, type, state.send_sequence, plaintext, aad.value());
  if (!frame) return frame.error();
  auto encoded = record::encode_frame(frame.value());
  if (!encoded) return encoded.error();
  ++state.send_sequence;
  return encoded.value();
}

Result<Bytes> seal_data(ChannelState& state, const ChannelConfig& config, ByteView plaintext, ByteView associated_data) {
  return seal(state, config, record::ContentType::data, plaintext, associated_data);
}

Result<ReceivedRecord> open(ChannelState& state, const ChannelConfig& config, ByteView encoded_frame, ByteView associated_data) {
  if (state.closed) return make_error(ErrorCode::invalid_argument, "channel is closed");
  auto frame = record::decode_frame(encoded_frame);
  if (!frame) return frame.error();
  if (frame.value().header.role != peer_role(state.local_role)) {
    return make_error(ErrorCode::invalid_format, "record sender role is not the expected peer");
  }
  auto check = replay::check(state.receive_window, frame.value().header.sequence);
  if (!check) return check.error();
  auto aad = merged_aad(config, associated_data);
  if (!aad) return aad.error();
  auto plaintext = record::open(config.algorithm, state.material, frame.value(), aad.value());
  if (!plaintext) return plaintext.error();
  auto accepted = replay::accept(state.receive_window, frame.value().header.sequence);
  if (!accepted) return accepted.error();

  ReceivedRecord out;
  out.type = frame.value().header.type;
  out.sender = frame.value().header.role;
  out.sequence = frame.value().header.sequence;
  out.plaintext = plaintext.value();
  if (out.type == record::ContentType::alert && out.plaintext.size() == 1 &&
      static_cast<record::AlertCode>(out.plaintext[0]) == record::AlertCode::close_notify) {
    state.closed = true;
  }
  return out;
}

Result<Bytes> seal_alert(ChannelState& state, const ChannelConfig& config, record::AlertCode code, ByteView associated_data) {
  const Bytes payload{static_cast<std::uint8_t>(code)};
  auto out = seal(state, config, record::ContentType::alert, payload, associated_data);
  if (out && code == record::AlertCode::close_notify) state.closed = true;
  return out;
}

Result<Bytes> seal_key_update(ChannelState& state, const ChannelConfig& config, const session::Hello& hello,
                              ByteView context, ByteView associated_data) {
  if (state.closed) return make_error(ErrorCode::invalid_argument, "channel is closed");
  const std::uint64_t new_generation = state.generation + 1;
  if (new_generation == 0) return make_error(ErrorCode::invalid_argument, "key generation exhausted");
  auto payload = make_key_update_payload(state.material, hello, new_generation, context);
  if (!payload) return payload.error();
  auto encoded = seal(state, config, record::ContentType::key_update, payload.value(), associated_data);
  if (!encoded) return encoded.error();
  auto updated = session::update_keys(state.material, hello, new_generation, context);
  if (!updated) return updated.error();
  state.material = updated.value();
  state.generation = new_generation;
  state.send_sequence = 0;
  return encoded.value();
}

Result<void> apply_key_update(ChannelState& state, const ReceivedRecord& record, const session::Hello& hello, ByteView context) {
  if (record.type != record::ContentType::key_update) return make_error(ErrorCode::invalid_format, "record is not a key update");
  if (record.plaintext.size() != 8 + session::kConfirmationBytes) return make_error(ErrorCode::invalid_format, "invalid key update payload length");
  const std::uint64_t new_generation = read_u64(ByteView(record.plaintext).subspan(0, 8));
  if (new_generation != state.generation + 1) return make_error(ErrorCode::invalid_argument, "unexpected key generation");
  auto expected = session::key_update_tag(state.material, hello, new_generation, context);
  if (!expected) return expected.error();
  const auto supplied = ByteView(record.plaintext).subspan(8, session::kConfirmationBytes);
  if (!constant_time_equal(expected.value(), supplied)) return make_error(ErrorCode::authentication_failed, "invalid key update tag");
  auto updated = session::update_keys(state.material, hello, new_generation, context);
  if (!updated) return updated.error();
  state.material = updated.value();
  state.generation = new_generation;
  replay::reset(state.receive_window);
  return {};
}

bool should_rekey(const ChannelState& state, const ChannelConfig& config) noexcept {
  return config.rekey_interval > 0 && state.send_sequence >= config.rekey_interval;
}

void close(ChannelState& state) noexcept {
  state.closed = true;
}

}  // namespace quantlib::channel

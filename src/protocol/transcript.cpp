#include "quantlib/transcript.hpp"
#include "quantlib/hash.hpp"
#include <limits>

namespace quantlib::transcript {
namespace {
void append_u32(Bytes& out, std::uint32_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
  out.push_back(static_cast<std::uint8_t>(value & 0xff));
}

void append_u64_be(Bytes& out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xff));
}

Result<void> append_field(Bytes& out, const std::string& label, ByteView value) {
  if (label.empty()) return make_error(ErrorCode::invalid_argument, "transcript label cannot be empty");
  if (label.size() > std::numeric_limits<std::uint32_t>::max() || value.size() > std::numeric_limits<std::uint32_t>::max()) {
    return make_error(ErrorCode::invalid_argument, "transcript field too large");
  }
  append_u32(out, static_cast<std::uint32_t>(label.size()));
  out.insert(out.end(), label.begin(), label.end());
  append_u32(out, static_cast<std::uint32_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
  return {};
}
}

Transcript::Transcript(std::string domain) : domain_(std::move(domain)) {
  const ByteView v(reinterpret_cast<const std::uint8_t*>(domain_.data()), domain_.size());
  (void)append_field(buffer_, "domain", v);
}

Result<void> Transcript::append(std::string label, ByteView value) {
  return append_field(buffer_, label, value);
}

Result<void> Transcript::append_u64(std::string label, std::uint64_t value) {
  Bytes encoded;
  encoded.reserve(8);
  append_u64_be(encoded, value);
  return append(std::move(label), encoded);
}

Bytes Transcript::digest() const {
  return hash::sha256(buffer_);
}

Bytes digest(std::string domain, ByteView message) {
  Transcript t(std::move(domain));
  (void)t.append("message", message);
  return t.digest();
}

}  // namespace quantlib::transcript

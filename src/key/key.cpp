#include "quantlib/key.hpp"
#include "quantlib/hash.hpp"
#include <chrono>

namespace quantlib::key {

Bytes key_id(ByteView public_key) {
  return hash::sha256(public_key);
}

std::uint64_t unix_time_now() noexcept {
  using namespace std::chrono;
  return static_cast<std::uint64_t>(duration_cast<seconds>(system_clock::now().time_since_epoch()).count());
}

}  // namespace quantlib::key

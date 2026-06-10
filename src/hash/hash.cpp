#include "quantlib/hash.hpp"

namespace quantlib::hash {

Result<Bytes> digest(Algorithm algorithm, ByteView message) {
  switch (algorithm) {
    case Algorithm::sha256: return sha256(message);
    case Algorithm::sha512:
    case Algorithm::sha3_256:
    case Algorithm::blake3:
      return make_error(ErrorCode::unsupported_algorithm, "hash backend is not wired yet");
  }
  return make_error(ErrorCode::unsupported_algorithm, "unknown hash algorithm");
}

const char* name(Algorithm algorithm) noexcept {
  switch (algorithm) {
    case Algorithm::sha256: return "SHA-256";
    case Algorithm::sha512: return "SHA-512";
    case Algorithm::sha3_256: return "SHA3-256";
    case Algorithm::blake3: return "BLAKE3";
  }
  return "unknown";
}

}  // namespace quantlib::hash

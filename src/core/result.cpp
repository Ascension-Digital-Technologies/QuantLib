#include "quantlib/result.hpp"

namespace quantlib {

const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::ok: return "ok";
    case ErrorCode::invalid_argument: return "invalid_argument";
    case ErrorCode::invalid_key: return "invalid_key";
    case ErrorCode::invalid_format: return "invalid_format";
    case ErrorCode::authentication_failed: return "authentication_failed";
    case ErrorCode::unsupported_algorithm: return "unsupported_algorithm";
    case ErrorCode::entropy_failure: return "entropy_failure";
    case ErrorCode::internal_error: return "internal_error";
  }
  return "unknown";
}

Error make_error(ErrorCode code, std::string message) {
  return Error{code, std::move(message)};
}

}  // namespace quantlib

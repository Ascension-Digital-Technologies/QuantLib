#pragma once
#include <string>
#include <utility>

namespace quantlib {

enum class ErrorCode {
  ok = 0,
  invalid_argument,
  invalid_key,
  invalid_format,
  authentication_failed,
  unsupported_algorithm,
  entropy_failure,
  internal_error
};

struct Error {
  ErrorCode code{ErrorCode::ok};
  std::string message{};

  [[nodiscard]] bool ok() const noexcept { return code == ErrorCode::ok; }
};

template <class T>
class Result {
 public:
  Result(T value) : has_value_(true), value_(std::move(value)) {}
  Result(Error error) : has_value_(false), error_(std::move(error)) {}

  [[nodiscard]] bool ok() const noexcept { return has_value_; }
  [[nodiscard]] explicit operator bool() const noexcept { return has_value_; }

  [[nodiscard]] const T& value() const& { return value_; }
  [[nodiscard]] T& value() & { return value_; }
  [[nodiscard]] T&& value() && { return std::move(value_); }

  [[nodiscard]] const Error& error() const noexcept { return error_; }

 private:
  bool has_value_{false};
  T value_{};
  Error error_{ErrorCode::internal_error, "uninitialized result"};
};

template <>
class Result<void> {
 public:
  Result() : error_{ErrorCode::ok, {}} {}
  Result(Error error) : error_(std::move(error)) {}

  [[nodiscard]] bool ok() const noexcept { return error_.ok(); }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] const Error& error() const noexcept { return error_; }

 private:
  Error error_{};
};

[[nodiscard]] const char* to_string(ErrorCode code) noexcept;
[[nodiscard]] Error make_error(ErrorCode code, std::string message);

}  // namespace quantlib

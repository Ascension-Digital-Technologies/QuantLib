#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstdint>
#include <string>

namespace quantlib::transcript {

class Transcript {
 public:
  explicit Transcript(std::string domain);
  [[nodiscard]] Result<void> append(std::string label, ByteView value);
  [[nodiscard]] Result<void> append_u64(std::string label, std::uint64_t value);
  [[nodiscard]] Bytes digest() const;
  [[nodiscard]] const std::string& domain() const noexcept { return domain_; }

 private:
  std::string domain_{};
  Bytes buffer_{};
};

[[nodiscard]] Bytes digest(std::string domain, ByteView message);

}  // namespace quantlib::transcript

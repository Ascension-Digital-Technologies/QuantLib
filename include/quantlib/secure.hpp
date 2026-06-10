#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace quantlib {

void secure_zero(void* ptr, std::size_t len) noexcept;
[[nodiscard]] bool constant_time_equal(ByteView a, ByteView b) noexcept;

struct SecureMemoryStatus {
  bool locking_supported{false};
  bool dump_exclusion_supported{false};
  bool guard_pages_supported{false};
  std::string backend{};
  std::string notes{};
};

[[nodiscard]] SecureMemoryStatus secure_memory_status();
[[nodiscard]] Result<void> lock_memory(void* ptr, std::size_t len) noexcept;
[[nodiscard]] Result<void> unlock_memory(void* ptr, std::size_t len) noexcept;
[[nodiscard]] Result<void> exclude_from_core_dump(void* ptr, std::size_t len) noexcept;

class SecureBytes {
 public:
  SecureBytes() = default;
  explicit SecureBytes(std::size_t size) : data_(size) {}
  explicit SecureBytes(Bytes bytes) : data_(std::move(bytes)) {}
  SecureBytes(const SecureBytes&) = delete;
  SecureBytes& operator=(const SecureBytes&) = delete;
  SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {}
  SecureBytes& operator=(SecureBytes&& other) noexcept;
  ~SecureBytes();

  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
  [[nodiscard]] std::uint8_t* data() noexcept { return data_.data(); }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return data_.data(); }
  [[nodiscard]] ByteView view() const noexcept { return ByteView(data_.data(), data_.size()); }
  [[nodiscard]] Bytes& raw() noexcept { return data_; }
  [[nodiscard]] const Bytes& raw() const noexcept { return data_; }

 private:
  Bytes data_{};
};

class LockedBytes {
 public:
  LockedBytes() = default;
  static Result<LockedBytes> allocate(std::size_t size) noexcept;

  LockedBytes(const LockedBytes&) = delete;
  LockedBytes& operator=(const LockedBytes&) = delete;
  LockedBytes(LockedBytes&& other) noexcept;
  LockedBytes& operator=(LockedBytes&& other) noexcept;
  ~LockedBytes();

  [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
  [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
  [[nodiscard]] bool locked() const noexcept { return locked_; }
  [[nodiscard]] bool dump_excluded() const noexcept { return dump_excluded_; }
  [[nodiscard]] std::uint8_t* data() noexcept { return data_.data(); }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return data_.data(); }
  [[nodiscard]] ByteView view() const noexcept { return ByteView(data_.data(), data_.size()); }

 private:
  explicit LockedBytes(std::size_t size) : data_(size) {}
  void release() noexcept;

  Bytes data_{};
  bool locked_{false};
  bool dump_excluded_{false};
};

}  // namespace quantlib

#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace quantlib {

class AlignedBytes {
 public:
  AlignedBytes() = default;
  explicit AlignedBytes(std::size_t size, std::size_t alignment = 64);
  AlignedBytes(const AlignedBytes&) = delete;
  AlignedBytes& operator=(const AlignedBytes&) = delete;
  AlignedBytes(AlignedBytes&& other) noexcept;
  AlignedBytes& operator=(AlignedBytes&& other) noexcept;
  ~AlignedBytes();

  [[nodiscard]] std::uint8_t* data() noexcept { return data_; }
  [[nodiscard]] const std::uint8_t* data() const noexcept { return data_; }
  [[nodiscard]] std::size_t size() const noexcept { return size_; }
  [[nodiscard]] std::size_t alignment() const noexcept { return alignment_; }
  [[nodiscard]] bool empty() const noexcept { return size_ == 0; }

 private:
  void release() noexcept;
  std::uint8_t* data_{nullptr};
  std::size_t size_{0};
  std::size_t alignment_{64};
};

[[nodiscard]] bool is_aligned(const void* ptr, std::size_t alignment) noexcept;

}  // namespace quantlib

#include "quantlib/aligned.hpp"
#include <cstdlib>
#include <cstring>
#include <new>

#if defined(_MSC_VER)
#include <malloc.h>
#endif

namespace quantlib {
namespace {
std::size_t normalize_alignment(std::size_t alignment) {
  if (alignment < alignof(void*)) alignment = alignof(void*);
  // Round up to power of two.
  std::size_t p = 1;
  while (p < alignment) p <<= 1;
  return p;
}
}  // namespace

AlignedBytes::AlignedBytes(std::size_t size, std::size_t alignment) : size_(size), alignment_(normalize_alignment(alignment)) {
  if (size_ == 0) return;
#if defined(_MSC_VER)
  data_ = static_cast<std::uint8_t*>(_aligned_malloc(size_, alignment_));
  if (!data_) throw std::bad_alloc();
#else
  void* p = nullptr;
  if (posix_memalign(&p, alignment_, size_) != 0) throw std::bad_alloc();
  data_ = static_cast<std::uint8_t*>(p);
#endif
  std::memset(data_, 0, size_);
}

AlignedBytes::AlignedBytes(AlignedBytes&& other) noexcept
    : data_(other.data_), size_(other.size_), alignment_(other.alignment_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

AlignedBytes& AlignedBytes::operator=(AlignedBytes&& other) noexcept {
  if (this != &other) {
    release();
    data_ = other.data_;
    size_ = other.size_;
    alignment_ = other.alignment_;
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}

AlignedBytes::~AlignedBytes() { release(); }

void AlignedBytes::release() noexcept {
  if (!data_) return;
  std::memset(data_, 0, size_);
#if defined(_MSC_VER)
  _aligned_free(data_);
#else
  std::free(data_);
#endif
  data_ = nullptr;
  size_ = 0;
}

bool is_aligned(const void* ptr, std::size_t alignment) noexcept {
  if (alignment == 0) return false;
  return (reinterpret_cast<std::uintptr_t>(ptr) % alignment) == 0;
}

}  // namespace quantlib

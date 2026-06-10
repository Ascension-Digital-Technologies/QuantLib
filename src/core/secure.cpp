#include "quantlib/secure.hpp"
#include <algorithm>
#include <cstring>

#if defined(_WIN32)
  #define NOMINMAX
  #include <windows.h>
#elif defined(__unix__) || defined(__APPLE__)
  #include <cerrno>
  #include <sys/mman.h>
  #include <unistd.h>
#endif

namespace quantlib {
namespace {

Error os_error(const char* operation) {
#if defined(_WIN32)
  return make_error(ErrorCode::internal_error, std::string(operation) + " failed");
#else
  return make_error(ErrorCode::internal_error, std::string(operation) + " failed: errno=" + std::to_string(errno));
#endif
}

}  // namespace

void secure_zero(void* ptr, std::size_t len) noexcept {
  if (ptr == nullptr || len == 0) return;
#if defined(_WIN32)
  SecureZeroMemory(ptr, len);
#else
  volatile auto* p = static_cast<volatile std::uint8_t*>(ptr);
  while (len--) *p++ = 0;
#endif
}

bool constant_time_equal(ByteView a, ByteView b) noexcept {
  if (a.size() != b.size()) return false;
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < a.size(); ++i) diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
  return diff == 0;
}

SecureMemoryStatus secure_memory_status() {
  SecureMemoryStatus status;
#if defined(_WIN32)
  status.locking_supported = true;
  status.dump_exclusion_supported = false;
  status.guard_pages_supported = false;
  status.backend = "windows-virtual-lock";
  status.notes = "VirtualLock/SecureZeroMemory available; guarded allocation is not enabled in this build";
#elif defined(__APPLE__)
  status.locking_supported = true;
  status.dump_exclusion_supported = false;
  status.guard_pages_supported = false;
  status.backend = "posix-mlock";
  status.notes = "mlock available; portable dump exclusion is not available on this platform path";
#elif defined(__unix__)
  status.locking_supported = true;
  #if defined(MADV_DONTDUMP)
    status.dump_exclusion_supported = true;
  #else
    status.dump_exclusion_supported = false;
  #endif
  status.guard_pages_supported = false;
  status.backend = "posix-mlock";
  status.notes = "mlock available; MADV_DONTDUMP used where the platform exposes it";
#else
  status.locking_supported = false;
  status.dump_exclusion_supported = false;
  status.guard_pages_supported = false;
  status.backend = "portable-zeroize-only";
  status.notes = "secure zeroization available; OS memory locking not detected";
#endif
  return status;
}

Result<void> lock_memory(void* ptr, std::size_t len) noexcept {
  if (ptr == nullptr || len == 0) return {};
#if defined(_WIN32)
  if (VirtualLock(ptr, len) == 0) return os_error("VirtualLock");
  return {};
#elif defined(__unix__) || defined(__APPLE__)
  if (::mlock(ptr, len) != 0) return os_error("mlock");
  return {};
#else
  (void)ptr;
  (void)len;
  return make_error(ErrorCode::unsupported_algorithm, "memory locking is not supported on this platform");
#endif
}

Result<void> unlock_memory(void* ptr, std::size_t len) noexcept {
  if (ptr == nullptr || len == 0) return {};
#if defined(_WIN32)
  if (VirtualUnlock(ptr, len) == 0) return os_error("VirtualUnlock");
  return {};
#elif defined(__unix__) || defined(__APPLE__)
  if (::munlock(ptr, len) != 0) return os_error("munlock");
  return {};
#else
  (void)ptr;
  (void)len;
  return make_error(ErrorCode::unsupported_algorithm, "memory unlocking is not supported on this platform");
#endif
}

Result<void> exclude_from_core_dump(void* ptr, std::size_t len) noexcept {
  if (ptr == nullptr || len == 0) return {};
#if defined(__unix__) && !defined(__APPLE__) && defined(MADV_DONTDUMP)
  const long page_size = ::sysconf(_SC_PAGESIZE);
  if (page_size <= 0) return os_error("sysconf(_SC_PAGESIZE)");
  const auto addr = reinterpret_cast<std::uintptr_t>(ptr);
  const auto page = static_cast<std::uintptr_t>(page_size);
  const auto aligned = addr & ~(page - 1U);
  const auto end = addr + len;
  const auto aligned_len = ((end - aligned + page - 1U) / page) * page;
  if (::madvise(reinterpret_cast<void*>(aligned), aligned_len, MADV_DONTDUMP) != 0) return os_error("madvise(MADV_DONTDUMP)");
  return {};
#else
  (void)ptr;
  (void)len;
  return make_error(ErrorCode::unsupported_algorithm, "core-dump exclusion is not supported on this platform path");
#endif
}

SecureBytes& SecureBytes::operator=(SecureBytes&& other) noexcept {
  if (this != &other) {
    secure_zero(data_.data(), data_.size());
    data_ = std::move(other.data_);
  }
  return *this;
}

SecureBytes::~SecureBytes() {
  secure_zero(data_.data(), data_.size());
}

Result<LockedBytes> LockedBytes::allocate(std::size_t size) noexcept {
  LockedBytes out(size);
  if (size == 0) return out;
  const auto lock = lock_memory(out.data(), out.size());
  out.locked_ = lock.ok();
  const auto dump = exclude_from_core_dump(out.data(), out.size());
  out.dump_excluded_ = dump.ok();
  return out;
}

LockedBytes::LockedBytes(LockedBytes&& other) noexcept
    : data_(std::move(other.data_)), locked_(other.locked_), dump_excluded_(other.dump_excluded_) {
  other.locked_ = false;
  other.dump_excluded_ = false;
}

LockedBytes& LockedBytes::operator=(LockedBytes&& other) noexcept {
  if (this != &other) {
    release();
    data_ = std::move(other.data_);
    locked_ = other.locked_;
    dump_excluded_ = other.dump_excluded_;
    other.locked_ = false;
    other.dump_excluded_ = false;
  }
  return *this;
}

LockedBytes::~LockedBytes() { release(); }

void LockedBytes::release() noexcept {
  if (!data_.empty()) {
    secure_zero(data_.data(), data_.size());
    if (locked_) (void)unlock_memory(data_.data(), data_.size());
  }
  locked_ = false;
  dump_excluded_ = false;
}

}  // namespace quantlib

#pragma once
#include "quantlib/bytes.hpp"
#include "quantlib/result.hpp"
#include <cstddef>

namespace quantlib::kdf {

inline constexpr std::size_t kSha256DigestBytes = 32;

[[nodiscard]] Bytes hmac_sha256(ByteView key, ByteView message);
[[nodiscard]] Result<Bytes> hkdf_sha256(ByteView ikm, ByteView salt, ByteView info, std::size_t output_len);

}  // namespace quantlib::kdf

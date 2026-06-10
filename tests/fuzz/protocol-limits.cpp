#include "quantlib/quantlib.hpp"
#include <cstdint>
#include <cstddef>
#ifndef QUANTLIB_LIBFUZZER
#include <iostream>
#include <iterator>
#include <vector>
#endif
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  quantlib::protocol::HandshakeLimits limits;
  limits.max_frame_bytes = 4096;
  limits.max_record_plaintext = 2048;
  const quantlib::ByteView input(data, size);
  (void)quantlib::protocol::validate_frame_limits(input, limits);
  (void)quantlib::protocol::validate_plaintext_limits(input, limits);
  return 0;
}

#ifndef QUANTLIB_LIBFUZZER
int main() {
  std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(std::cin), {});
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}
#endif

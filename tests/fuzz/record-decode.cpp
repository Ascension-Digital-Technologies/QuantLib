#include "quantlib/quantlib.hpp"
#include <cstdint>
#include <cstddef>
#ifndef QUANTLIB_LIBFUZZER
#include <iostream>
#include <iterator>
#include <vector>
#endif
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const quantlib::ByteView input(data, size);
  (void)quantlib::record::decode_frame(input);
  return 0;
}

#ifndef QUANTLIB_LIBFUZZER
int main() {
  std::vector<std::uint8_t> data(std::istreambuf_iterator<char>(std::cin), {});
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}
#endif

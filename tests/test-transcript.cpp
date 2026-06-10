#include "quantlib/quantlib.hpp"
#include <cassert>

int run_transcript_tests() {
  quantlib::transcript::Transcript a("QuantLib Test Transcript v1");
  assert(a.append("client", quantlib::Bytes{1,2,3}).ok());
  assert(a.append_u64("counter", 7).ok());
  const auto da = a.digest();
  assert(da.size() == 32);

  quantlib::transcript::Transcript b("QuantLib Test Transcript v1");
  assert(b.append("client", quantlib::Bytes{1,2,3}).ok());
  assert(b.append_u64("counter", 7).ok());
  assert(da == b.digest());

  quantlib::transcript::Transcript c("QuantLib Test Transcript v1");
  assert(c.append("client", quantlib::Bytes{1,2,4}).ok());
  assert(c.append_u64("counter", 7).ok());
  assert(da != c.digest());

  assert(!a.append("", quantlib::Bytes{1}).ok());
  assert(quantlib::transcript::digest("domain", quantlib::Bytes{9}).size() == 32);
  return 0;
}

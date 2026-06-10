#include "quantlib/replay.hpp"
#include <cassert>

int run_replay_tests() {
  quantlib::replay::ReplayWindow w;
  assert(quantlib::replay::accept(w, 10).ok());
  assert(quantlib::replay::seen(w, 10));
  assert(!quantlib::replay::accept(w, 10).ok());
  assert(quantlib::replay::accept(w, 12).ok());
  assert(quantlib::replay::accept(w, 11).ok());
  assert(!quantlib::replay::accept(w, 12).ok());
  assert(quantlib::replay::accept(w, 80).ok());
  assert(!quantlib::replay::accept(w, 10).ok());
  quantlib::replay::reset(w);
  assert(quantlib::replay::accept(w, 1).ok());
  return 0;
}

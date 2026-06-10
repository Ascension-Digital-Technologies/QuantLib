#include "quantlib/quantlib.hpp"
#include <cassert>

namespace {
void test_audit_chain_roundtrip() {
  quantlib::audit::AuditLog log;
  auto a = quantlib::audit::append(log, quantlib::audit::EventType::vault_created, "vault-1", "created");
  auto b = quantlib::audit::append(log, quantlib::audit::EventType::key_generated, "handle-1", "ed25519");
  assert(a && b);
  assert(log.events.size() == 2);
  assert(log.events[0].sequence == 0);
  assert(log.events[1].sequence == 1);
  assert(log.events[1].previous_hash == log.events[0].event_hash);
  assert(quantlib::audit::verify(log));
  auto encoded = quantlib::audit::encode_log(log);
  assert(encoded);
  auto decoded = quantlib::audit::decode_log(encoded.value());
  assert(decoded);
  assert(decoded.value().events.size() == 2);
  assert(quantlib::audit::head_hash(decoded.value()) == quantlib::audit::head_hash(log));
}

void test_audit_tamper_rejected() {
  quantlib::audit::AuditLog log;
  assert(quantlib::audit::append(log, quantlib::audit::EventType::vault_created, "vault", "created"));
  assert(quantlib::audit::append(log, quantlib::audit::EventType::key_generated, "key", "ed25519"));
  auto tampered = log;
  tampered.events[0].detail = "changed";
  assert(!quantlib::audit::verify(tampered));
  auto encoded = quantlib::audit::encode_log(log);
  assert(encoded);
  auto raw = encoded.value();
  raw[raw.size() / 2] ^= 0x01;
  assert(!quantlib::audit::decode_log(raw));
}

void test_vault_audit_persistence() {
  auto vault = quantlib::vault::create_vault("pw", {.label = "audit", .kdf_iterations = 10000});
  assert(vault);
  assert(vault.value().audit_log.events.size() == 1);
  assert(quantlib::vault::append_audit(vault.value(), quantlib::audit::EventType::key_generated, "handle", "ed25519"));
  auto encoded = quantlib::vault::encode_vault(vault.value(), "pw");
  assert(encoded);
  auto decoded = quantlib::vault::decode_vault(encoded.value(), "pw");
  assert(decoded);
  assert(decoded.value().audit_log.events.size() >= 3);
  assert(quantlib::vault::verify_audit(decoded.value()));
}
}

int run_audit_tests() {
  test_audit_chain_roundtrip();
  test_audit_tamper_rejected();
  test_vault_audit_persistence();
  return 0;
}

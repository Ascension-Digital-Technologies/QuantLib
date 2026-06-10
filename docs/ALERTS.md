# Alert Records

QuantLib record v1 supports encrypted alert records.

## Alert Codes

- `close_notify`
- `unexpected_message`
- `bad_record_mac`
- `protocol_error`
- `key_update_required`

Alert payloads are encrypted and authenticated exactly like normal records. The alert payload is currently one byte.

# Changelog

## 0.1.1 — 2026-11-05

- Detect severity from level fields, timestamp-prefixed text, and LDAP result
  codes by default; add `auto_severity` to disable detection.
- Normalize severity aliases, case, and priorities 0–7; unknown values and NONE
  fall back to INFO without failing a chunk.
- Scrub string keys and values recursively to UTF-8 before formatting, including
  headers. Emit exactly one newline per event and escape embedded CR/LF for
  non-JSON formatters.
- Preserve the legacy Devo header and inject UTC event time with milliseconds
  into `@timestamp`; add `inject_timestamp` and `timestamp_key`. Preserve
  existing payload timestamp fields and event-time precision through buffering.
- Add `sanitize_tag`, remove wire delimiters from headers, and warn once for
  changed or out-of-range Devo tags.
- Close partially constructed TCP/TLS connections on setup, connect, or handshake
  failure; try every resolved address in order with per-address readiness waits.
- Move connection creation outside the logger-cache lock, close concurrent
  duplicate loggers, and prevent reconnection after shutdown or transport close.
- Support hashed CA directories without a trailing slash, encrypted client keys
  through secret `client_key_passphrase`, and leaf-first PEM certificate bundles
  with intermediate chains.
- Warn that `token`, `procid_key`, and `msgid_key` are ignored by this syslog
  format while retaining their configuration compatibility.
- Add explicit `tls false` for plain TCP relays with an unencrypted-traffic warning.
- Document unacknowledged writes, partial-chunk duplicates, buffer-capacity drops,
  and Fluentd's rejection of individual records exceeding the chunk limit.
- Add focused record, framing, TLS/mTLS, cache-race, and lifecycle regressions.

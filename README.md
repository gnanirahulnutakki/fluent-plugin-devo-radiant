# fluent-plugin-devo-radiant

A Fluentd output plugin for sending records to Devo over TLS or an explicitly
selected plain TCP relay. This is a derivative of
[DevoInc/fluent-plugin-devo 1.2.0](https://github.com/DevoInc/fluent-plugin-devo)
under the Apache License 2.0. Both `@type devo_radiant` and `@type devo` are supported.

## Installation

```bash
fluent-gem install fluent-plugin-devo-radiant
```

## Configuration

```conf
<match devo.**>
  @type devo_radiant
  host logs.example.invalid
  port 443
  hostname fid-0
  app_name_key devo_tag

  tls true
  ca_cert system
  verify_cert_name true
  tls_min_version TLSv1_2

  # Optional mutual TLS credentials; certificate bundle is leaf first.
  client_cert /path/to/client.crt
  client_key /path/to/client.key
  # Supply client_key_passphrase securely if the key is encrypted.

  auto_severity true
  inject_timestamp true
  timestamp_key @timestamp
  sanitize_tag true

  <format>
    @type json
  </format>

  <buffer tag>
    @type file
    path /var/log/fluent/devo-buffer
    flush_interval 5s
    retry_forever true
  </buffer>
</match>
```

Set the record's `devo_tag` to a tag such as `my.app.fid`. Without `app_name_key`,
the Fluentd tag is used as the Devo tag. The buffer chunk key defaults to `tag`,
so the explicit `<buffer tag>` argument above is optional. A persistent file
buffer and an intentional retry policy are recommended for production.

| Parameter | Default | Behavior |
| --- | --- | --- |
| `host`, `port` | Required | Listener address and port. All resolved addresses are tried in order per connection attempt. |
| `tls` | `true` | TLS transport. `false` selects plain TCP and warns that traffic is unencrypted. |
| `ca_cert` | `system` | System CA store, CA file, or hashed CA directory (with or without a trailing slash). `false` disables peer and hostname verification and warns. |
| `verify_cert_name` | `true` | Check server hostname. `false` disables hostname matching and warns when TLS is enabled. |
| `tls_min_version` | `TLSv1_2` | Minimum TLS version; `TLSv1_3` is accepted when supported by the OpenSSL runtime. No maximum is pinned. |
| `client_cert` | Unset | PEM client certificate or bundle, with the leaf first followed by intermediate certificates. |
| `client_key` | Unset | PEM private key, including RSA and EC. Masked in Fluentd configuration output. |
| `client_key_passphrase` | Unset | Passphrase for an encrypted private key. Masked in configuration output. Missing or incorrect passphrases fail without an interactive prompt. |
| `idle_timeout` | Unset | Seconds of inactivity before reconnecting on the next write; no background idle sweeper. |
| `hostname` | Local short hostname | Default syslog hostname. |
| `facility` | `LOCAL0` | Default syslog facility. |
| `severity_key` | Unset | Record field with an explicit severity; a missing or null value allows automatic detection. |
| `auto_severity` | `true` | Detect severity when no explicit value is present. `false` uses INFO in that case. |
| `inject_timestamp` | `true` | Add the Fluentd event time to the outgoing record as ISO 8601 UTC with milliseconds. Existing keys, including null values, are preserved. |
| `timestamp_key` | `@timestamp` | Field for the injected timestamp. Non-JSON formatters must include this field to transmit it. |
| `sanitize_tag` | `true` | Remove characters outside `[A-Za-z0-9.]` and collapse empty tag levels. |
| `hostname_key`, `facility_key`, `app_name_key` | Unset | Per-record header mappings. |
| `token`, `procid_key`, `msgid_key` | Unset | Accepted for compatibility, but ignored by this wire format; configuring any of them produces one warning. |

`output_type` and the existing Fluentd formatter/inject compatibility settings
remain accepted. `token` is masked but is **never transmitted**. PROCID, MSGID,
and structured data are not serialized. Configure authentication for the selected
listener, such as mutual TLS; setting `token` does not authenticate a connection.

## Severity and record handling

An explicit severity is normalized case-insensitively. Numeric priorities 0–7
and their strings are accepted. FATAL/CRITICAL map to CRIT, SEVERE/ERROR to ERR,
WARNING to WARN, TRACE/FINE/FINER/FINEST/VERBOSE to DEBUG,
INFORMATION/INFORMATIONAL to INFO, and EMERGENCY/PANIC to EMERG. Unknown values,
including NONE, become INFO and do not fail a chunk.

Automatic detection checks these record keys in order, ignoring key case:
`loglevel`, `status`, `severity`, `level`, `syslog.severity`, `log_level`,
`log.level`, `@l`, `severitytext`, `lvl`, `levelname`. If none has a non-null
value, it checks the timestamp-prefixed text level, using the same prefix pattern
as the Dynatrace output. Text fields are checked in priority order: `content`,
`message`, `payload`, `body`, `log`, `_raw`; the first non-null field is used.
Finally, LDAP `RESULTCODE` maps 0/5/6/10/14 to INFO, 1/51/52/53/54/80 to ERR,
and other integer codes to WARN. Unrecognized content defaults to INFO.

String keys and values are normalized recursively to UTF-8 before formatting.
Invalid bytes become U+FFFD; valid UTF-8 binary strings are preserved. The same
normalization applies to the wire header. Formatter terminal CR/LF is removed,
then one newline frames each event. Embedded CRLF, CR, and LF in non-JSON
formatter output become literal `\n`; JSON's own escaping is preserved.

The RFC 3164-style header remains `<PRI>Mon DD HH:MM:SS hostname app_name`.
It does not carry year, timezone, or fractional seconds. The injected payload
timestamp preserves that information from the **Fluentd event time**; it cannot
repair a source parser that assigned read time instead of parsing the log time.

## Devo tags

[Devo's tag rules](https://devodocs.atlassian.net/wiki/spaces/latest/pages/95126204)
require 2–6 nonempty dot-separated levels and a maximum of 50 characters, with
alphanumeric characters and periods. This plugin's sanitizer uses ASCII letters
and digits. For example, `..my..app.vds_server_access/.` becomes
`my.app.vdsserveraccess`. Each distinct original tag that changes produces one
warning showing original and cleaned values. Each distinct tag still outside
the level/length rules produces one warning and is sent anyway.

Even with `sanitize_tag false`, hostname and app_name always have whitespace,
CR/LF, and control characters removed because they delimit the wire header.
Sanitizing can make different original tags identical. Prefer explicit valid
tags and verify that they select the intended Devo parser. Syntax cleanup does
not establish that a matching parser exists.

## Delivery limits

- Syslog over TCP/TLS has no application acknowledgement. A successful socket
  write is not proof that Devo received, stored, or parsed an event.
- After a partial-chunk failure, Fluentd retries the whole chunk. Previously
  sent records can be duplicated. This is not an exactly-once delivery channel.
- A buffer configured with `overflow_action drop_oldest_chunk` discards old
  chunks when capacity is reached. Size persistence and retention deliberately,
  and monitor backlog and drops. This plugin does not change Fluentd's default
  buffer overflow policy.
- A single record larger than `chunk_limit_size` is rejected by Fluentd before
  transmission. The plugin does not split or truncate oversized events or
  impose a separate receiver-specific event limit.
- Connect and TLS readiness waits are 10 seconds per address/wait; write
  readiness waits are 5 seconds. Slow progress, retries, DNS, and waiting for a
  transport's write lock can extend total elapsed time.
- Each worker caches a connection per Fluentd tag. High tag cardinality retains
  more connections and warning-cache entries until shutdown.
- Shutdown prevents new connections and reconnects, and closes cached transports
  and any concurrent logger-creation loser. Delivery errors remain visible to
  Fluentd so buffered failures can follow its retry policy.

## Development

```bash
bundle install
bundle exec rake test
```

The regression receiver uses connected local socket pairs for real TLS/mTLS
handshakes and wire assertions without a network listener. TCP dial failures,
address ordering, and readiness timeouts also use controlled boundary doubles.
Set `DEVO_TEST_TMPDIR` to choose where temporary test credentials and buffers
are created; the tests remove their own files and stop their own threads.

## Attribution and license

Copyright notices from the upstream project are retained in derived source
files. See [NOTICE](NOTICE) for the derivative-work statement and [LICENSE](LICENSE)
for the Apache License 2.0 and bundled-component notices.

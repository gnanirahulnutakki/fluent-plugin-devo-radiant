# fluent-plugin-devo-radiant

A hardened Fluentd output plugin for sending records to Devo over TLS. This is
a derivative of [DevoInc/fluent-plugin-devo 1.2.0](https://github.com/DevoInc/fluent-plugin-devo)
under the Apache License 2.0.

## Changes from upstream

- Fluentd buffering with retryable chunk failures instead of per-record error swallowing
- Secret masking for `token` and `client_key`
- Multi-worker support and synchronized, worker-aware logger caching
- Peer verification with the system CA store by default
- Explicit warnings if peer or hostname verification is disabled
- Configurable minimum TLS version (`TLSv1_2` by default; `TLSv1_3` is supported)
- Fork-specific namespace for the bundled syslog TLS implementation
- Both `@type devo_radiant` and `@type devo` registrations

Buffered delivery is at least once. If a chunk fails after some records were
accepted by the remote endpoint, Fluentd retries the chunk and those earlier
records can be delivered again.

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

  token YOUR_DEVO_TOKEN
  ca_cert system
  verify_cert_name true
  tls_min_version TLSv1_2

  # Optional mutual TLS credentials
  client_cert /path/to/client.crt
  client_key /path/to/client.key

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

The buffer chunk key defaults to `tag`, so the explicit `<buffer tag>` argument
above is optional. A persistent file buffer and an intentional retry policy are
recommended for production durability.

Setting `ca_cert false` disables both certificate-chain and hostname
verification and produces a warning. Setting `verify_cert_name false` disables
hostname matching only and also produces a warning. Both weaken TLS security.

## Development

```bash
bundle install
bundle exec rake test
```

## Attribution and license

Copyright notices from the upstream project are retained in derived source
files. See [NOTICE](NOTICE) for the derivative-work statement and [LICENSE](LICENSE)
for the Apache License 2.0 and bundled-component notices.

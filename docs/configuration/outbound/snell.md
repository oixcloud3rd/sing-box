---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "identity": 0,
  "reuse": false,
  "preconnect": 0,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  "tls": {},

  ... // Dial Fields
}
```

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "mode": "",

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

==Required==

The Snell protocol version, one of `4` `6`.

Version `4` supports HTTP obfuscation (`obfs_mode` / `obfs_host`); version `6`
replaces it with traffic shaping (`mode`) and requires a `psk` of 12 to 255
bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### userkey

The user key, used to authenticate against a multi-user server.

#### identity

==Version 4 only==

Snell identity version. When omitted, identity is disabled. `1` sends the `DLSNID01` identity,
and `2` sends the `DLSNID02` identity authenticated with the TLS exporter and the Snell salt.

Identity v1 is the first 16 bytes of `BLAKE3-512(psk)`. Identity v2 requires ECH-TLS and an
accepted ECH handshake. It is not bound to a specific ALPN. With the default TCP transport it can
be used with `tls.insecure: true`; HTTP/3 requires certificate verification.

#### reuse

Enable connection reuse (the Snell v2 `CONNECT` command).

#### preconnect

Number of reusable connections to establish in the background, from `0` to `4`. Disabled by default.

A positive value requires Snell v4, ECH-TLS, and `reuse: true`. Preconnect failures are logged as
warnings and do not prevent the outbound from starting.

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### obfs_mode

==Version 4 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### obfs_host

==Version 4 only==

The HTTP `Host` header sent when `obfs_mode` is `http`.

`bing.com` is used by default.

#### tls

==Version 4 only==

TLS configuration, see [TLS](/configuration/shared/tls/).

For Snell ECH-TLS, TLS must be enabled and `ech.enabled` must be `true`. Without `transport`, the
TLS connection carries raw Snell v4. It cannot be combined with simple-obfs.
ECH must be accepted by the server.

`alpn` is empty by default. If configured, the negotiated ALPN must be one of the configured values.
`snell-ech/1` is available as an explicit protocol value, but custom values are also supported.

Example:

```json
{
  "type": "snell",
  "tag": "snell-ech",
  "server": "server.example.com",
  "server_port": 443,
  "version": 4,
  "psk": "password",
  "identity": 2,
  "reuse": true,
  "preconnect": 2,
  "tls": {
    "enabled": true,
    "server_name": "public.example.com",
    "alpn": ["snell-ech/1"],
    "ech": {
      "enabled": true,
      "config": [
        "-----BEGIN ECH CONFIGS-----",
        "...",
        "-----END ECH CONFIGS-----"
      ]
    },
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

#### transport

==Version 4 only==

Optional Snell-specific transport. Omit it to retain the existing TCP behavior.
The only supported `type` is `http3`.

HTTP/3 carries Snell v4 inside an Extended CONNECT tunnel over QUIC. It is not the
official Snell v5 QUIC mode or the V2Ray QUIC transport. The server must implement
the matching tunnel protocol: `:protocol = websocket`, with the path
`/ws-tunnel-` followed by the lowercase hexadecimal first 12 bytes of SHA-256 of the PSK.
The tunnel carries raw Snell bytes, not WebSocket frames.

Requires explicit `identity: 2`, TLS and ECH enabled, and certificate verification
(`tls.insecure` must be `false`). Simple-obfs, Reality, non-Go TLS engines, and
explicit TLS versions other than `1.3` are not supported.
The binary must be built with `with_quic`, even when fallback is enabled.

```json
{
  "type": "snell",
  "server": "server.example.com",
  "server_port": 443,
  "version": 4,
  "psk": "password",
  "identity": 2,
  "transport": {
    "type": "http3",
    "fallback": false,
    "quic_congestion_control": "reno"
  },
  "tls": {
    "enabled": true,
    "server_name": "inner.example.com",
    "ech": {
      "enabled": true
    }
  }
}
```

ECH supports inline configs, a config file, or DNS lookup as in the existing TLS
configuration. HTTP/3 uses Go TLS 1.3 with ALPN `h3`; `tls.utls`, TLS fragmentation,
spoofing and kTLS only apply to TCP fallback. HTTP/3 does not overwrite the TCP ALPN:
fallback uses `tls.alpn`, or `snell-ech/1` when omitted.

Both TCP and UDP proxy traffic use the tunnel. QUIC sessions are shared across
independent tunnels; existing `reuse` and `preconnect` options still apply.

##### transport.fallback

Default: `false`. HTTP/3 tunnel establishment has a 10-second budget and failures
are returned directly.

When `true`, the HTTP/3 budget is 2 seconds. Establishment failure falls back to
ECH-TLS TCP at the same server address and port. New connections use TCP for
30 seconds before trying HTTP/3 again. A shorter caller deadline takes precedence.
Fallback still requires certificate verification and accepted ECH; it never
uses plaintext Snell or Identity v1, or retries after Snell data has been sent.

##### transport.quic_congestion_control

One of `reno`, `cubic`, `bbr`. Defaults to the QUIC library's native Reno controller.
Applies to client-side QUIC sending only, not the server's sending algorithm or TCP fallback.

##### transport.bbr_profile

One of `standard`, `conservative`, `aggressive`. Defaults to `standard` when using BBR.
Only valid with explicit `quic_congestion_control: "bbr"`; setting it with any other
algorithm is an error and does not automatically select BBR.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

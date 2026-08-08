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
  ... // Destination Strategy Fields
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
accepted ECH handshake. It is not bound to a specific ALPN and can be used with `tls.insecure: true`.

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

For Snell ECH-TLS, TLS must be enabled and `ech.enabled` must be `true`. The TLS connection carries
raw Snell v4 and cannot be combined with `obfs_mode`. ECH must be accepted by the server.

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

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.

### Destination Strategy Fields

See [Destination Strategy Fields](/configuration/shared/destination-strategy/) for details.
